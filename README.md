# redline-suite

Offensive lab tools that show how C2 channels actually work.

This is the red-team counterpart to [plaintext-suite](../plaintext-suite): that
repo watches and explains; this one demonstrates the attacker side in a way you
can read, run in a lab, and break on purpose. Both are teaching projects, not
products.

## Still a work in progress

Small tools for authorised labs and coursework. Each one does a specific job,
runs without a service behind it, and has its own README with the limitations
written down. Nothing here is meant for use against systems you do not own or
have written permission to test. See [DISCLAIMER.md](DISCLAIMER.md).

## The tools

| Tool | Language | What it does |
|------|----------|--------------|
| [aether-dns](tools/aether-dns) | Python | DNS tunnelling C2: AES-256-GCM payloads in base32 labels, selective-repeat retries, beacon jitter. Controller and agent. |
| [icmp-c2](tools/icmp-c2) | Python | ICMP echo C2: zlib-chunked streams over type-8 packets, RETRY/ACK, source-IP filter. Controller and agent. |
| [spoof-proof](tools/spoof-proof) | Python | Email-auth spoof demo: for a domain missing DMARC/DKIM, sends one clearly `[DEMO]`-marked message with a forged `From` to an address you control, proving impersonation. Reuses the blue-team [domain-checker](https://github.com/DhWonder/plaintext-suite/tree/main/tools/domain-checker) verdict. Authorised demos only. |

Start with **aether-dns** if you want encrypted DNS labels and a menu that
survives longer commands. Use **icmp-c2** when you want a thinner channel that
looks like ping traffic on a host-only or AWS lab link.

## Two rules these tools follow

**Config is explicit.** No silent shared keys, no baked-in lab IPs that only
work on one VirtualBox host. Flags and environment variables set the peer,
interface, domain, and crypto key. Demo modes exist and warn loudly.

**Lab-shaped, not product-shaped.** Docstrings and menus say teaching PoC.
Shutdown restores systemd-resolved / kernel ICMP echo behaviour. Loot files
land next to the controller as `loot_*` so you can see what came back.

## Running them

```bash
pip3 install -r requirements.txt
```

Each tool's README has the exact commands. Both need root on the controller
side (bind :53 or sniff/send raw ICMP).

## How this was built

Written with help from Grok. It drafted code and first drafts of the docs.
Every design decision, test run, and lab check was mine, and nothing went in
unread. These tools are for authorised labs only.

## License

MIT, all of it. Use it, change it, ship it — within the limits in
[DISCLAIMER.md](DISCLAIMER.md).
