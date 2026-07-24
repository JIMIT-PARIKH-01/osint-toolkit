# OSINT Toolkit

Passive open-source-intelligence toolkit — **dependency-free**, GUI + CLI.

1. **DNS recon** — A/AAAA/MX/NS/TXT/CNAME/SOA via a minimal built-in DNS-over-UDP resolver
2. **WHOIS / IP intel** — domain WHOIS (IANA referral chain) and IP WHOIS + reverse DNS
3. **Username checker** — checks a username across ~14 sites (Sherlock-style), concurrently

Standard library only (`socket`, `struct`, `urllib`, `concurrent.futures`). Python 3.8+.

## ⚠️ Authorized/ethical use only
Investigate footprints you own or are permitted to assess.

## Run
```powershell
python osint/gui.py            # GUI (tabs: DNS / WHOIS / Username), or run.bat

python -m osint dns      example.com
python -m osint whois    example.com
python -m osint whois    8.8.8.8
python -m osint username someuser
```

## Layout
```
osint-toolkit/
└── osint/
    ├── dns_recon.py       # minimal DNS-over-UDP resolver
    ├── whois_intel.py     # domain/IP WHOIS + reverse DNS
    ├── username_check.py  # multi-site username search
    ├── cli.py  gui.py  run.bat
```

MIT — see [LICENSE](./LICENSE).
