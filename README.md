# OSINT Toolkit

[![CI](https://github.com/JIMIT-PARIKH-01/osint-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/JIMIT-PARIKH-01/osint-toolkit/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.8%2B-blue) ![License](https://img.shields.io/badge/license-MIT-green)

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

## ⬇️ Download & Install

**This is a public tool — download and use it on your device for free.**

```bash
# 1) Clone it
git clone https://github.com/JIMIT-PARIKH-01/osint-toolkit.git
cd osint-toolkit

# 2) ...or download a ZIP (no git needed)
#    https://github.com/JIMIT-PARIKH-01/osint-toolkit/archive/refs/heads/main.zip

# 3) ...or install the command straight from GitHub
pip install git+https://github.com/JIMIT-PARIKH-01/osint-toolkit.git
```

Then run it as shown in the usage section above (CLI `python -m ...`, or launch
the GUI via `run.bat`).

<details>
<summary><b>🔒 Requesting access to a private tool</b></summary>

Public tools install with the commands above. If a tool is **private**, access
is granted by the owner through GitHub — a static link cannot unlock private
code, only GitHub can:

1. **Request access** — open an [access request](https://github.com/JIMIT-PARIKH-01/JIMIT-PARIKH-01/issues/new?template=tool-access-request.md&title=Access+request:+osint-toolkit) or message on
   [LinkedIn](https://www.linkedin.com/in/jimit-devangkumar-parikh/).
2. The owner reviews it and, if approved, **adds you as a collaborator** on the
   private repository.
3. GitHub then lets you clone / download it with your own account. Access is
   revoked the moment the owner removes you as a collaborator.

</details>

