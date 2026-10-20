# ICMP C2 — Lab Implementation Notes

Authorised cybersecurity coursework. Documents how we built
`tools/icmp-c2` (controller + agent) function by function: what each piece
does, why it exists, and where AI-assisted iteration changed it. Original
base was a **pull-only Scapy ICMP PoC**; AI did not one-shot the final
design — humans provisioned AWS, ran live debug, and fed screenshots;
AI evolved beacon, quiet UX, off-thread send, and NAT echo-reply.

**Repo:** `tools/icmp-c2` in this repository  
**Commit:** `9caf8dd` on `main`  
(*quiet beacons, off-thread jobs, NAT-friendly echo replies*)

---

## 1. Goal and topology (brief)

**Goal:** ICMP C2 on AWS EC2; local Ubuntu agent. DNS/Aether deferred (already
had beacons). Dedicated EC2 controller (not the honeypot) in a lab region; controller
NIC typically `ens5`; agent on a Wi-Fi NIC (e.g. `wlp8s0`) behind residential
NAT; security group: All ICMP + SSH from the lab operator `/32`. EC2 and home
public IPs change across sessions — use placeholders like `<ec2-public-ip>`
and `<home-public-ip>`. Consumer VPNs often block or mangle ICMP — disconnect
for the lab.

**Why pull-only failed:** new type-8 to residential public IP never arrived.
Fix: agent beacons first; controller type-0 reply with matching id/seq.

---

## 2. Shared constants / wire format

Both sides agree on:

| Item | Meaning |
|------|---------|
| `TRIGGER_MARKER = b"CMD!"` | Magic prefix in ICMP Raw; everything after is protocol |
| `CMD!BEACON\|<id>` | Agent → controller (type 8) |
| `CMD!LS\|path` / `RUN\|cmd` / `SEND\|path` | Controller → agent (type 0 reply) |
| `CMD![START]<n>\|<name>` | Start of zlib stream; `n` = chunk count |
| `CMD![CHUNK]<bytes>` | One frame; seq carried in ICMP `seq` field |
| `CMD![END]<name>` | End of stream |
| `CMD!RETRY\|1,4,7` | Retransmit missing seqs |
| `CMD!ACK\|DONE` | Stream accepted; agent clears busy |
| `CMD!SIZE\|…` | Optional chunk-size tweak (legacy from early PoC) |
| Agent uplink id | `0xC200` on type-8 sends |
| Chunk size (agent) | `CHUNK_SIZE = 36` compressed bytes per frame |

Uplink = agent type **8**. Downlink = controller type **0**. VirtualBox/same-L2
can still use leftover `send_trigger` (type 8); AWS+home-NAT needs type 0.

---

## 3. Controller — build order (function by function)

File: `controller.py`. We describe dependency order: kernel isolation →
send helpers → packet branches → sniffer → CLI/menu.

### 3.1 Module state

`TARGET_IP`, `IFACE`, `LOCK_TARGET`, `received_chunks`, `current_filename`,
`expected_max_seq`, `stream_lock`, `stream_busy`, `pending_cmd`,
`last_agent_id`. Early PoC had a fixed target IP. AI+human iteration made
`TARGET_IP` optional and **filled from BEACON** unless `--lock-target`.
`pending_cmd` is the queue of one task waiting for the next beacon.

### 3.2 `toggle_kernel_icmp(state)` / `restore_kernel_icmp()` / `shutdown_sequence()`

**Purpose:** While we sniff, stop the Linux kernel from auto-answering ICMP
echo (`sysctl net.ipv4.icmp_echo_ignore_all=1`). Otherwise the OS steals
legitimate replies and confuses the lab.

**Side effects:** `"1"` isolates; `"0"` restores (`atexit`). `shutdown_sequence`
restores then `os._exit(0)`. From original PoC; `kill -9` can leave ignore_all
stuck (see README).

### 3.3 `send_icmp_reply(dst, icmp_id, icmp_seq, cmd_string)` — NAT path

**Purpose:** Build `IP(dst) / ICMP(type=0, id=…, seq=…) / Raw(CMD! + cmd)`
and `send(..., iface=IFACE)`. This is the **primary downlink**.

**Why it exists:** Screenshots/`tcpdump` showed beacons arriving on EC2 but
commands never on `wlp8s0` when we used fresh type-8. AI diagnosis: reply
to the agent’s request with matching id/seq so home NAT forwards.

**Critical behaviour:** Caller must pass the **beacon or END packet’s**
id/seq, not a random id. Used for dispatch, RETRY, and ACK.

### 3.4 `send_trigger(cmd_string)` — legacy type-8 push

**Purpose:** New type-8 `CMD!` to `TARGET_IP` (id `0xC200`). Kept as fallback
when there is no live request to reply to (e.g. same-L2 VirtualBox demos).

**Why still here:** Documents the old pull-only model. On AWS+NAT it fails;
menu path no longer calls it — `packet_handler` uses `send_icmp_reply`.

### 3.5 `packet_handler(packet)` — BEACON branch

**Purpose:** Sniff callback entry. Ignore non-IP/Raw or payloads without
`CMD!`. Strip marker; read `icmp_id` / `icmp_seq` / `src`.

On `BEACON|<id>`:

1. Record `last_agent_id`.
2. Honour `--lock-target` (drop wrong src).
3. If dynamic: update `TARGET_IP` and **print only on IP change** (quiet
   beacon — AI patch; old code spammed `*` every few seconds).
4. If `pending_cmd` and not `stream_busy`: clear queue, start a **daemon
   thread** that calls `send_icmp_reply(src, id, seq, cmd)`.

**Iteration:** Quiet print + off-thread `_dispatch` + type-0 reply were the
three AI-assisted NAT/UX fixes on this branch. `send()` inside sniff `prn`
was unreliable (reentrancy / stalls).

### 3.6 `packet_handler` — START / CHUNK / END

**`[START]<n>|<name>`:** Under `stream_lock`, set `expected_max_seq`,
`current_filename`, empty `received_chunks`, `stream_busy=True`. From
original PoC framing.

**`[CHUNK]`:** Key by `packet[ICMP].seq`; store payload after `[CHUNK]`;
print `.` progress. Ignore if not busy.

**`[END]`:** Snapshot chunks; compute missing seqs.

- If missing → off-thread `send_icmp_reply(..., f"RETRY|{…}")` using **END’s**
  id/seq (same NAT trick).
- If complete → zlib decompress; print `ls_output.txt` / `command_log.txt` or
  write `loot_<name>`; off-thread `ACK|DONE`; clear busy state in `finally`.

**Iteration:** RETRY/ACK switched from type-8 `send_trigger` to type-0
`send_icmp_reply` + off-thread, same as BEACON dispatch.

### 3.7 `background_sniffer()`

Thin wrapper: `sniff(iface=IFACE, filter="icmp", prn=packet_handler, store=0)`.
Runs on a daemon thread so the menu can block on `input()`.

### 3.8 `parse_args()` / `main()`

**`parse_args`:** `--target` (optional), `--iface` (required), `--lock-target`.
Env fallbacks `ICMP_C2_*`. Flags parsed before root check so `--help` works
without sudo (earlier suite commit).

**`main`:** Require root + iface; set globals; `toggle_kernel_icmp("1")`;
start sniffer thread; loop menu.

Menu choices build `LS|…` / `RUN|…` / `SEND|…` strings into **`pending_cmd`
only** — they do not send immediately. That queue-on-beacon behaviour is the
teaching upgrade over pull-only push. Rejects queue while stream busy or
another cmd already pending. Choice `4` → `shutdown_sequence`.

---

## 4. Agent — build order (function by function)

File: `agent.py`. Original PoC: sniff for type-8 triggers, stream results.
Added: outbound beacon loop, accept type-0 triggers, ACK timeout, off-thread
jobs.

### 4.1 Module state

`INTERFACE`, `C2_SERVER_IP`, `BEACON_INTERVAL`, `BEACON_JITTER`, `AGENT_ID`,
`active_stream_name`, `cached_chunks_matrix`, `busy`, `_busy_lock`, `_stop`,
`_ack_timer`. `busy` pauses beacons during an uplink so frames do not
interleave with BEACONs.

### 4.2 `transmit_chunk(data_bytes, sequence_number)`

**Purpose:** One uplink frame: type-8, id `0xC200`, `seq=sequence_number`,
Raw = `CMD!` + caller-supplied bytes (usually `[CHUNK]` + payload). Tiny
`sleep(0.01)` to pace sends.

**Why:** Shared by initial stream and RETRY retransmit so seq numbering stays
consistent. From original PoC; largely unchanged.

### 4.3 `_cancel_ack_timer()` / `_schedule_ack_timeout()`

**Purpose:** After `[END]`, wait up to `ACK_TIMEOUT_S` (3s) for `ACK|DONE`.
On expiry: clear `busy`, wipe chunk cache, print notice so **beacons resume**.

**Why it exists:** AI+human NAT debug — ACKs sometimes dropped; agent stuck
busy forever. Teaching-friendly recovery, not production reliability.

### 4.4 `optimize_and_stream(stream_name, raw_data_bytes)`

**Purpose:** Set `busy`; zlib-compress; split into `CHUNK_SIZE` pieces into
`cached_chunks_matrix`; send `[START]<count>|<name>`, each `transmit_chunk`,
then `[END]<name>`; schedule ACK timeout.

**Why:** Single uplink path for LS / RUN / SEND results. Matrix kept so
RETRY can resend without re-running the command. Core of original PoC;
ACK-timeout hook added later.

### 4.5 `send_beacon()` / `_next_beacon_sleep()` / `beacon_loop()`

**`send_beacon`:** Type-8 `CMD!BEACON|<AGENT_ID>` to `C2_SERVER_IP`, seq 0.

**`_next_beacon_sleep`:** `interval ± jitter*interval`, floor 1s — avoids
metronomic timing for teaching realism.

**`beacon_loop`:** While not `_stop`: if not busy, `send_beacon()`; wait
jittered sleep. Daemon thread from `main`.

**Iteration:** Entire beacon subsystem is the first major AI-assisted
evolution away from pull-only (inspired by Aether DNS “agent speaks first”).

### 4.6 `parse_trigger(packet)` — downlink handler

**Purpose:** Sniff callback. Require IP src == `C2_SERVER_IP` and `CMD!` in
Raw. Split `action|argument`.

| Action | Behaviour |
|--------|-----------|
| `SIZE` | Adjust `CHUNK_SIZE` (legacy) |
| `RETRY` | Cancel ACK timer; `transmit_chunk` missing seqs; resend `[END]`; reschedule ACK timer |
| `ACK` | Cancel timer; clear cache; `busy=False` |
| `LS` / `RUN` / `SEND` | If not already busy, start `_run_job` on a **daemon thread** |

**`_run_job` (nested):** `LS` → `os.listdir` → stream as `ls_output.txt`;
`RUN` → `subprocess.run(..., shell=True)` → `command_log.txt`; `SEND` → read
file → stream basename (or error text). All end in `optimize_and_stream`.

**Critical AI-assisted changes:**

1. Accept **any ICMP type** from C2 (docstring + no type filter) so type-0
   replies work.
2. Off-thread `_run_job` — Scapy `send()` / long shell work inside `prn` was
   unreliable.
3. Busy guard so overlapping LS/RUN/SEND are dropped.

### 4.7 `parse_args()` / `main()`

**Args:** `--server`, `--iface` (required; no baked-in IPs), `--beacon-interval`,
`--jitter`, `--agent-id` (default hostname). Env equivalents.

**`main`:** Root check; set globals; start `beacon_loop` thread; blocking
`sniff(..., prn=parse_trigger)`; on exit cancel ACK timer and set `_stop`.

---

## 5. End-to-end: one `whoami`

Numbered call flow across both processes (AWS controller, home agent):

1. **Human / AWS:** `main` → `toggle_kernel_icmp("1")` → `background_sniffer`
   → menu shows; operator chooses **2: Run Command**, enters `whoami` →
   `pending_cmd = "RUN|whoami"`.
2. **Agent:** `beacon_loop` → `send_beacon()` → type-8 `CMD!BEACON|<id>`
   leaves `wlp8s0` toward EC2.
3. **Controller:** `packet_handler` BEACON branch learns/confirms `TARGET_IP`
   (e.g. `<home-public-ip>`); sees pending cmd → thread →
   `send_icmp_reply(..., "RUN|whoami")` type-0, same id/seq as beacon.
4. **NAT:** Home router delivers echo **reply** to LAN agent.
5. **Agent:** `parse_trigger` sees `RUN|whoami` → thread `_run_job` →
   `subprocess.run("whoami")` → stdout `root\n` →
   `optimize_and_stream("command_log.txt", …)`.
6. **Agent uplink:** `[START]` / `[CHUNK]`… / `[END]` as type-8; then
   `_schedule_ack_timeout`.
7. **Controller:** START → CHUNK dots → END complete → zlib decompress →
   print `[Agent output]: root` → thread `send_icmp_reply(..., "ACK|DONE")`.
8. **Agent:** `parse_trigger` ACK → clear busy → `beacon_loop` resumes.
9. **Verify aid:** `tcpdump -ni wlp8s0 icmp` on agent shows inbound type-0
   with `CMD!` at step 3/7.

If step 3 used `send_trigger` (type 8) instead, step 4 never happens on
typical home NAT — that was the live failure mode before the echo-reply patch.

---

## 6. Lessons, repo, safety

### Lessons

1. Send helpers first; NAT picks type-0 vs type-8.
2. Sniff `prn` ≈ interrupt: no long work; send off-thread.
3. Queue on beacon beats blind push behind NAT.
4. Quiet BEACON logging is UX, not cosmetics.
5. ACK timeout needed when replies vanish.
6. AI helped fastest function-by-function after packet evidence — not one-shot codegen.

### Repo

```text
tools/icmp-c2/agent.py
tools/icmp-c2/controller.py
tools/icmp-c2/README.md          # how to run
tools/icmp-c2/IMPLEMENTATION.md  # how we built it (this file)
```

`9caf8dd` — quiet beacons, off-thread jobs, NAT-friendly echo replies  
Prior: `927ff5c` — outbound beacon, jitter, queue, dynamic target  
Earlier: pull-only Scapy PoC (suite initial + local `icmp-aws` scratch)

### Authorised lab only

Dedicated EC2 separate from honeypot. Scrub secrets before any public share.
Example IPs/instance ids here are lab chronology, not credentials — tighten
SG when the lab ends. Root/raw sockets required; do not aim at networks
without written authorisation.

---

*Function-level lab notes for redline-suite ICMP C2. Prefer README for flags
and usage.*
