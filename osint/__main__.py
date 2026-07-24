"""Entry point:  python -m osint <dns|whois|username> ..."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
