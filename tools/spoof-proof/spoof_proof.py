#!/usr/bin/env python3
"""
spoof-proof - prove, safely, that a domain with missing DMARC/DKIM can be
impersonated.

WHAT THIS IS FOR
    A domain with no DMARC policy and no DKIM signature can be forged: a
    stranger can send mail that says it comes from it. domain-checker (the
    companion blue-team tool in this repo) tells you a domain is exposed.
    spoof-proof lets you DEMONSTRATE it - by sending one clearly marked demo
    message, with a forged From, to an address you choose - so the owner sees
    the fake invoice land in their own inbox instead of taking it on faith.

AUTHORISED USE ONLY
    * Use this only on a domain you own or are explicitly authorised to test,
      and send only to a recipient you control or who has agreed to receive it.
    * Do NOT use it to phish, defraud, or impersonate third parties. Spoofing a
      domain you have no permission to test may be illegal where you live.
    * The domain and the recipient are always command-line arguments. Nothing
      is hardcoded, and nothing is sent without the --confirm flag.

TWO MODES
    check   reuse domain-checker's read-only DNS verdict for a domain.
    send    build a DEMO-labelled message with a forged From and - only with
            --confirm - transmit it through YOUR SMTP server to YOUR --to.
            Without --confirm it is a dry run: it prints the message and stops.

    SMTP is YOUR server, given by env (SMTP_HOST, SMTP_PORT, SMTP_USER,
    SMTP_PASS, SMTP_SECURITY) or by --smtp-* flags. Open relays are never used.

Usage:
    python3 spoof_proof.py check --domain example.com
    python3 spoof_proof.py send  --domain example.com --to you@example.com \\
            --from-local ceo --smtp-host smtp.example.net --smtp-user me \\
            --smtp-pass '...' --confirm

Standard library only, Python 3.7+. MIT license. See README.md.
"""

import argparse
import os
import smtplib
import ssl
import sys
from email.message import EmailMessage
from email.utils import formatdate, make_msgid


# ---------------------------------------------------------------------------
# Reuse the blue-team check when it is sitting next to us; fall back to a
# small built-in probe so spoof-proof also works published on its own.
# ---------------------------------------------------------------------------
def load_domain_checker():
    """Return the domain_checker module if it is reachable, else None.

    We look in a sibling ../domain-checker folder (how this repo ships) and on
    the normal import path. Reusing it means the demo's verdict is exactly the
    one the blue tool gives, with no second copy of the logic to drift."""
    here = os.path.dirname(os.path.abspath(__file__))
    candidate = os.path.join(here, "..", "domain-checker")
    for path in (candidate, here):
        full = os.path.abspath(path)
        if full not in sys.path and os.path.isdir(full):
            sys.path.insert(0, full)
    try:
        import domain_checker  # type: ignore
        return domain_checker
    except Exception:
        return None


def doh_txt(name, timeout=15):
    """Minimal DNS-over-HTTPS TXT lookup, used only when domain-checker is
    not available. Same public resolver, same read-only behaviour."""
    import json
    import urllib.parse
    import urllib.request
    query = urllib.parse.urlencode({"name": name, "type": "TXT"})
    url = "https://dns.google/resolve?%s" % query
    req = urllib.request.Request(url, headers={"User-Agent": "spoof-proof/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    out = []
    for answer in data.get("Answer", []):
        text = answer.get("data", "").strip()
        if text.startswith('"') and text.endswith('"'):
            text = text[1:-1]
        out.append(text.replace('" "', ""))
    return out


def quick_verdict(domain):
    """A built-in, standalone SPF/DMARC read when domain-checker is absent.

    Deliberately terse - the full plain-English report lives in the blue tool.
    Returns (exposed: bool, lines: list[str])."""
    lines = []
    exposed = False
    try:
        spf = [r for r in doh_txt(domain) if r.lower().startswith("v=spf1")]
    except Exception:
        return (False, ["  could not read DNS for %s" % domain])
    if not spf:
        lines.append("  SPF   : missing")
        exposed = True
    elif "-all" in spf[0]:
        lines.append("  SPF   : present and strict (-all)")
    else:
        lines.append("  SPF   : present but not strict")
    try:
        dmarc = [r for r in doh_txt("_dmarc." + domain)
                 if r.lower().startswith("v=dmarc1")]
    except Exception:
        dmarc = []
    if not dmarc:
        lines.append("  DMARC : missing - receivers are told nothing about fakes")
        exposed = True
    elif "p=reject" in dmarc[0].lower():
        lines.append("  DMARC : p=reject - fakes are thrown away")
    elif "p=quarantine" in dmarc[0].lower():
        lines.append("  DMARC : p=quarantine - fakes go to spam")
    else:
        lines.append("  DMARC : p=none - watches only, does not block")
        exposed = True
    return (exposed, lines)


def run_check(args):
    """check mode: print the domain's email-auth posture. Reads DNS only."""
    domain = normalise_domain(args.domain)
    checker = load_domain_checker()
    if checker is not None:
        print("Using domain-checker for the full read-only verdict:\n")
        options = {}
        if args.dkim_selector:
            options["dkim-selector"] = ",".join(args.dkim_selector)
        spf_status, spf_msg = checker.check_spf(domain)
        dmarc_status, dmarc_msg = checker.check_dmarc(domain)
        dkim_status, dkim_msg, _found = checker.check_dkim(domain, options)
        checker.line(spf_status, "SPF  ", spf_msg)
        checker.line(dmarc_status, "DMARC", dmarc_msg)
        checker.line(dkim_status, "DKIM ", dkim_msg)
        exposed = (dmarc_status in ("missing", "weak")
                   or spf_status in ("missing", "bad"))
    else:
        print("(domain-checker not found next to spoof-proof; built-in quick "
              "check)\n")
        exposed, lines = quick_verdict(domain)
        for text in lines:
            print(text)
    print()
    if exposed:
        print("Verdict: this domain looks SPOOFABLE. A demo send (below) will "
              "likely be accepted by the recipient's mail server.")
    else:
        print("Verdict: this domain is reasonably protected; a forged demo is "
              "likely to be rejected or quarantined (which itself proves the "
              "control works).")
    return 0 if not exposed else 1


# ---------------------------------------------------------------------------
# Building the demonstration message
# ---------------------------------------------------------------------------
def normalise_domain(value):
    """Strip scheme, path and a leading @ from whatever the operator typed."""
    domain = (value or "").strip().lower()
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    return domain.split("/")[0].lstrip("@")


def build_demo_message(domain, from_local, to_addr, subject=None):
    """Create the forged-From demonstration email.

    The From header is forged to <from_local>@<domain> on purpose - that is the
    thing being demonstrated - but the message says so in its subject and body,
    in both a visible marker and the headers, so it can never be mistaken for a
    real phishing email or quietly reused as one."""
    forged_from = "%s@%s" % (from_local, domain)
    subject = subject or ("Urgent: updated bank details for the next invoice")
    subject = "[DEMO - AUTHORISED EMAIL-AUTH TEST] " + subject

    body = (
        "*** THIS IS AN AUTHORISED EMAIL-AUTHENTICATION DEMONSTRATION ***\n"
        "\n"
        "You are reading this because someone ran an authorised security\n"
        "demonstration against the domain:  %s\n"
        "\n"
        "The 'From' address on this message was forged. It was NOT sent by\n"
        "the real owner of %s. It was sent by a demonstration tool to show\n"
        "that, because this domain is missing a DMARC policy and/or a DKIM\n"
        "signature, anyone on the internet can send mail that appears to come\n"
        "from it - for example a fake 'new bank details' invoice like this.\n"
        "\n"
        "If this had been a real attacker, this message would have no banner,\n"
        "and the bank details below would be theirs:\n"
        "\n"
        "    Please pay the attached invoice to:\n"
        "    Account name : (an attacker's account would go here)\n"
        "    Sort code    : 00-00-00      Account : 00000000\n"
        "\n"
        "THE FIX: publish a DMARC record (start p=none, move to p=reject) and\n"
        "a DKIM signature for the domain's mail. domain-checker (the companion\n"
        "tool) explains exactly what is missing and what to add.\n"
        "\n"
        "No action is required from you. This message was sent only to the\n"
        "address the operator supplied for the demonstration.\n"
        % (domain, domain)
    )

    message = EmailMessage()
    message["From"] = forged_from
    message["To"] = to_addr
    message["Subject"] = subject
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid()
    # Honest machine-readable markers so this is never mistaken for live phish.
    message["X-Demo-Tool"] = "spoof-proof (authorised email-auth demonstration)"
    message["X-Demo-Forged-From"] = forged_from
    message["Auto-Submitted"] = "auto-generated"
    message.set_content(body)
    return message


# ---------------------------------------------------------------------------
# SMTP configuration: the operator's own server, from env or flags
# ---------------------------------------------------------------------------
def smtp_config(args):
    """Collect SMTP settings from --smtp-* flags, then the environment.

    Returns (config dict, list of missing-field messages). A flag beats the
    matching env var. We never fall back to an open relay or to localhost by
    guess: no host means we stop and say how to set one."""
    cfg = {
        "host": args.smtp_host or os.environ.get("SMTP_HOST", ""),
        "port": args.smtp_port or os.environ.get("SMTP_PORT", ""),
        "user": args.smtp_user or os.environ.get("SMTP_USER", ""),
        "password": args.smtp_pass or os.environ.get("SMTP_PASS", ""),
        "security": (args.smtp_security or os.environ.get("SMTP_SECURITY", "")
                     ).strip().lower(),
    }
    missing = []
    if not cfg["host"]:
        missing.append("no SMTP host (set --smtp-host or SMTP_HOST)")
    if not cfg["port"]:
        cfg["port"] = "465" if cfg["security"] == "ssl" else "587"
    if not cfg["security"]:
        cfg["security"] = ("ssl" if str(cfg["port"]) == "465"
                           else ("none" if str(cfg["port"]) == "25"
                                 else "starttls"))
    try:
        cfg["port"] = int(cfg["port"])
    except (TypeError, ValueError):
        missing.append("SMTP port is not a number: %r" % cfg["port"])
    return cfg, missing


def smtp_help():
    """The exact steps to configure sending, printed when we cannot send."""
    return (
        "To actually send the demo you must point spoof-proof at an SMTP server\n"
        "you are allowed to use (your own, or your test account's). Set either\n"
        "environment variables:\n"
        "\n"
        "    export SMTP_HOST=smtp.example.net\n"
        "    export SMTP_PORT=587            # 465 for ssl, 25 for a plain relay\n"
        "    export SMTP_USER=you@example.net\n"
        "    export SMTP_PASS='an app password, not your real one'\n"
        "    export SMTP_SECURITY=starttls   # starttls | ssl | none\n"
        "\n"
        "or pass the matching flags: --smtp-host --smtp-port --smtp-user\n"
        "--smtp-pass --smtp-security. spoof-proof never uses an open relay or\n"
        "guesses a server for you."
    )


def send_over_smtp(message, cfg, timeout=20):
    """Hand the built message to the operator's SMTP server. Raises on failure.

    Note the envelope sender is the forged From: that is the point of the demo,
    and whether the operator's server allows it is itself part of the result."""
    host, port, security = cfg["host"], cfg["port"], cfg["security"]
    if security == "ssl":
        server = smtplib.SMTP_SSL(host, port, timeout=timeout,
                                  context=ssl.create_default_context())
    else:
        server = smtplib.SMTP(host, port, timeout=timeout)
    try:
        server.ehlo()
        if security == "starttls":
            server.starttls(context=ssl.create_default_context())
            server.ehlo()
        if cfg["user"]:
            server.login(cfg["user"], cfg["password"])
        server.send_message(message)
    finally:
        try:
            server.quit()
        except Exception:
            pass


def run_send(args):
    """send mode: build the demo, show it, and transmit only with --confirm."""
    domain = normalise_domain(args.domain)
    if not args.to:
        print("send needs a recipient: --to you@example.com", file=sys.stderr)
        return 2

    # Always run the read-only check first, so the demo is informed by the
    # same verdict the owner can reproduce with domain-checker.
    print("Step 1 - read-only auth check for %s" % domain)
    print("-" * 60)
    run_check(args)
    print()

    message = build_demo_message(domain, args.from_local, args.to, args.subject)
    print("Step 2 - the demonstration message")
    print("-" * 60)
    print("  Forged From : %s" % message["From"])
    print("  To          : %s" % message["To"])
    print("  Subject     : %s" % message["Subject"])
    if args.save_eml:
        with open(args.save_eml, "wb") as handle:
            handle.write(message.as_bytes())
        print("  Saved full message to %s for inspection." % args.save_eml)
    print()

    cfg, missing = smtp_config(args)
    if missing:
        print("Step 3 - cannot send yet:")
        for item in missing:
            print("  - %s" % item)
        print()
        print(smtp_help())
        return 2

    print("Step 3 - SMTP target: %s:%s (%s)%s"
          % (cfg["host"], cfg["port"], cfg["security"],
             " as %s" % cfg["user"] if cfg["user"] else ""))

    if not args.confirm:
        print()
        print("DRY RUN. Nothing was sent. Re-run with --confirm to transmit the")
        print("message above to %s. Only do this for an authorised demo." % args.to)
        return 0

    try:
        send_over_smtp(message, cfg)
    except Exception as exc:
        print()
        print("Send FAILED: %s: %s" % (type(exc).__name__, exc))
        print("(A rejection here can itself be the finding: the server or the")
        print(" recipient's provider refused the forged mail.)")
        return 1

    print()
    print("Sent. One DEMO message with a forged From %s was delivered to the"
          % message["From"])
    print("operator-supplied recipient %s via your SMTP server." % args.to)
    print("Check whether it landed in the inbox, in spam, or was rejected -")
    print("that outcome is the demonstration.")
    return 0


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------
def build_parser():
    parser = argparse.ArgumentParser(
        prog="spoof_proof.py",
        description="Authorised demonstration of missing DMARC/DKIM. "
                    "Use only on domains you are permitted to test.")
    sub = parser.add_subparsers(dest="command")

    common_dkim = dict(action="append", metavar="NAME",
                       help="extra DKIM selector to probe (repeatable)")

    p_check = sub.add_parser("check", help="read-only SPF/DKIM/DMARC verdict")
    p_check.add_argument("--domain", required=True)
    p_check.add_argument("--dkim-selector", dest="dkim_selector", **common_dkim)

    p_send = sub.add_parser("send", help="build a DEMO forged message; "
                                         "transmit only with --confirm")
    p_send.add_argument("--domain", required=True)
    p_send.add_argument("--to", required=True,
                        help="the single recipient (an address you control)")
    p_send.add_argument("--from-local", dest="from_local", default="demo",
                        help="local part of the forged From (default: demo)")
    p_send.add_argument("--subject", default=None)
    p_send.add_argument("--dkim-selector", dest="dkim_selector", **common_dkim)
    p_send.add_argument("--smtp-host", dest="smtp_host", default="")
    p_send.add_argument("--smtp-port", dest="smtp_port", default="")
    p_send.add_argument("--smtp-user", dest="smtp_user", default="")
    p_send.add_argument("--smtp-pass", dest="smtp_pass", default="")
    p_send.add_argument("--smtp-security", dest="smtp_security", default="",
                        help="starttls | ssl | none")
    p_send.add_argument("--save-eml", dest="save_eml", default="",
                        help="write the message to a .eml file for inspection")
    p_send.add_argument("--confirm", action="store_true",
                        help="actually send (without this it is a dry run)")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 2
    if args.command == "check":
        return run_check(args)
    if args.command == "send":
        return run_send(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
