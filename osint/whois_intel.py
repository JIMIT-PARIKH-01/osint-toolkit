"""
WHOIS / IP intel (standard library only).

Queries WHOIS servers over port 43 (following the IANA referral for domains) and
reverse-resolves IPs, then extracts a short summary. Passive OSINT.
"""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field

_SUMMARY_FIELDS = [
    ("registrar", r"(?im)^\s*registrar:\s*(.+)$"),
    ("created", r"(?im)^\s*(?:creation date|created|registered on):\s*(.+)$"),
    ("expires", r"(?im)^\s*(?:registry expiry date|expiry date|expires):\s*(.+)$"),
    ("org", r"(?im)^\s*(?:org(?:anization)?|orgname):\s*(.+)$"),
    ("country", r"(?im)^\s*country:\s*(.+)$"),
    ("name servers", r"(?im)^\s*name server:\s*(.+)$"),
]


@dataclass
class WhoisResult:
    target: str
    summary: dict = field(default_factory=dict)
    reverse_dns: str = ""
    raw: str = ""

    def as_text(self) -> str:
        lines = [f"WHOIS: {self.target}"]
        if self.reverse_dns:
            lines.append(f"  reverse DNS : {self.reverse_dns}")
        for k, v in self.summary.items():
            lines.append(f"  {k:<12}: {v}")
        if not self.summary:
            lines.append("  (no summary fields parsed; see raw output)")
        return "\n".join(lines)


def _whois_query(server: str, query: str, timeout: float = 12.0) -> str:
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.sendall((query + "\r\n").encode())
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", "replace")


def _summarize(raw: str) -> dict:
    summary = {}
    for name, pattern in _SUMMARY_FIELDS:
        matches = re.findall(pattern, raw)
        if matches:
            summary[name] = matches[0].strip() if name != "name servers" \
                else ", ".join(sorted(set(m.strip() for m in matches))[:4])
    return summary


def whois_domain(domain: str, timeout: float = 12.0) -> WhoisResult:
    domain = domain.strip().lower()
    iana = _whois_query("whois.iana.org", domain, timeout)
    refer = None
    for line in iana.splitlines():
        if line.lower().startswith("refer:"):
            refer = line.split(":", 1)[1].strip()
    raw = _whois_query(refer, domain, timeout) if refer else iana
    return WhoisResult(target=domain, summary=_summarize(raw), raw=raw)


def whois_ip(ip: str, timeout: float = 12.0) -> WhoisResult:
    ip = ip.strip()
    try:
        rev = socket.gethostbyaddr(ip)[0]
    except (socket.herror, OSError):
        rev = ""
    raw = _whois_query("whois.arin.org", f"n + {ip}", timeout)
    return WhoisResult(target=ip, summary=_summarize(raw), reverse_dns=rev, raw=raw)


def lookup(target: str) -> WhoisResult:
    """Auto-route: IPv4 -> IP whois, otherwise domain whois."""
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target.strip()):
        return whois_ip(target)
    return whois_domain(target)
