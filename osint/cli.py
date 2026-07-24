"""
OSINT Toolkit command line.

    python -m osint dns      example.com
    python -m osint whois    example.com
    python -m osint whois    8.8.8.8
    python -m osint username someuser

Passive OSINT -- investigate footprints you're authorized to assess.
"""

from __future__ import annotations

import argparse
import sys

from . import dns_recon, whois_intel, username_check


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="osint", description="OSINT: DNS recon, WHOIS/IP intel, username search.")
    sub = p.add_subparsers(dest="command", required=True)

    d = sub.add_parser("dns", help="DNS records (A/AAAA/MX/NS/TXT/CNAME/SOA).")
    d.add_argument("domain")
    d.add_argument("--server", default="8.8.8.8")

    w = sub.add_parser("whois", help="WHOIS for a domain or IP.")
    w.add_argument("target")
    w.add_argument("--raw", action="store_true", help="Print full raw WHOIS text.")

    u = sub.add_parser("username", help="Check a username across many sites.")
    u.add_argument("name")
    return p


def main(argv: list | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "dns":
            print(dns_recon.recon(args.domain, server=args.server).as_text())
        elif args.command == "whois":
            res = whois_intel.lookup(args.target)
            print(res.raw if args.raw else res.as_text())
        elif args.command == "username":
            print(username_check.check(args.name).as_text())
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
