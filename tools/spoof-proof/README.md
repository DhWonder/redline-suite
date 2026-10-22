# spoof-proof

**Prove, safely, that a domain with missing DMARC/DKIM can be impersonated.**

Its blue-team sibling, [`domain-checker`](https://github.com/DhWonder/plaintext-suite/tree/main/tools/domain-checker), *tells* you a
domain is spoofable. `spoof-proof` lets you *demonstrate* it — by sending one
clearly `[DEMO]`-marked message, with a forged `From`, to an address you choose
— so the owner sees the fake "new bank details" invoice land in their own inbox
instead of taking the risk on faith.

> ## ⚠ Authorised use only
> - Use this **only** on a domain you own or are **explicitly authorised** to test.
> - Send **only** to a recipient you control or who has agreed to receive it.
> - **Do not** use it to phish, defraud, or impersonate third parties. Spoofing a
>   domain you have no permission to test may be illegal where you live.
> - The **domain** and the **recipient** are always CLI arguments — nothing is
>   hardcoded — and **nothing is sent without `--confirm`**.

## How it works

1. It runs the same read-only SPF/DKIM/DMARC check as `domain-checker` (it
   imports that module when the tools ship together, and falls back to a small
   built-in DNS-over-HTTPS probe when published on its own).
2. It builds a demonstration email whose `From` is forged to
   `<from-local>@<domain>`. The forgery is the point — but the subject starts
   with `[DEMO - AUTHORISED EMAIL-AUTH TEST]`, the body opens with a banner
   explaining it is an authorised demonstration, and honest `X-Demo-*` headers
   are attached, so it can never be mistaken for, or quietly reused as, real phish.
3. With `--confirm` it transmits that message through **your** SMTP server to
   **your** `--to`. Whether it lands in the inbox, in spam, or is rejected *is*
   the finding.

It never uses an open relay and never guesses a mail server.

## Usage

```bash
# Read-only verdict (reuses domain-checker)
python3 spoof_proof.py check --domain example.com

# Dry run: build and print the demo message, send nothing (no --confirm)
python3 spoof_proof.py send --domain example.com --to you@example.com \
        --from-local ceo --save-eml demo.eml

# Actually send it through your SMTP server (authorised demos only)
python3 spoof_proof.py send --domain example.com --to you@example.com \
        --from-local ceo \
        --smtp-host smtp.example.net --smtp-port 587 \
        --smtp-user you@example.net --smtp-pass 'app-password' \
        --smtp-security starttls --confirm
```

## SMTP configuration

Point it at a server you are allowed to use, via flags or environment variables
(flags win). **No secrets live in this repo** — pass them at runtime:

```bash
export SMTP_HOST=smtp.example.net
export SMTP_PORT=587            # 465 for ssl, 25 for a plain relay
export SMTP_USER=you@example.net
export SMTP_PASS='an app password, not your real one'
export SMTP_SECURITY=starttls   # starttls | ssl | none
```

If no SMTP host is set, `send` stops and prints these exact steps rather than
doing anything surprising.

## Options

| Flag | Meaning |
|------|---------|
| `--domain` | Domain to spoof (required). You must be authorised to test it. |
| `--to` | The single recipient — an address you control (required for `send`). |
| `--from-local` | Local part of the forged `From` (default `demo`). |
| `--subject` | Override the demo subject (the `[DEMO …]` prefix is always kept). |
| `--dkim-selector` | Extra DKIM selector for the check (repeatable). |
| `--smtp-host/-port/-user/-pass/-security` | Your SMTP server. |
| `--save-eml FILE` | Write the built message to a `.eml` for inspection. |
| `--confirm` | Actually transmit. Without it, `send` is a dry run. |

## See also

- **[`domain-checker`](https://github.com/DhWonder/plaintext-suite/tree/main/tools/domain-checker)** — the read-only blue-team checker.
  Run it first; it explains in plain English exactly what is missing and how to
  fix it (publish DMARC, start `p=none` → move to `p=reject`, add DKIM).

---

Written by DhWonder. MIT license. Use responsibly.
