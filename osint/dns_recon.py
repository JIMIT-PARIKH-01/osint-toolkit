"""
DNS recon (standard library only) -- a minimal DNS-over-UDP resolver.

Queries A / AAAA / MX / NS / TXT / CNAME / SOA records by building and parsing
DNS packets directly (no dnspython). Passive lookups against a public resolver.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field

RTYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15,
          "TXT": 16, "AAAA": 28}
_RTYPE_NAME = {v: k for k, v in RTYPES.items()}
DEFAULT_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")


@dataclass
class DNSResult:
    domain: str
    records: dict = field(default_factory=dict)     # type -> [values]
    errors: list = field(default_factory=list)

    def as_text(self) -> str:
        lines = [f"DNS records for {self.domain}:"]
        for rtype in DEFAULT_TYPES:
            vals = self.records.get(rtype)
            if vals:
                for v in vals:
                    lines.append(f"  {rtype:<6} {v}")
        if not any(self.records.values()):
            lines.append("  (no records found)")
        for e in self.errors:
            lines.append(f"  ! {e}")
        return "\n".join(lines)


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


def _read_name(data: bytes, offset: int):
    labels = []
    jumped = False
    end = offset
    while True:
        length = data[offset]
        if length & 0xC0 == 0xC0:                       # compression pointer
            pointer = struct.unpack(">H", data[offset:offset + 2])[0] & 0x3FFF
            if not jumped:
                end = offset + 2
            offset = pointer
            jumped = True
            continue
        offset += 1
        if length == 0:
            break
        labels.append(data[offset:offset + length].decode("ascii", "replace"))
        offset += length
    if not jumped:
        end = offset
    return ".".join(labels), end


def _parse_rdata(rtype: int, data: bytes, offset: int, rdlength: int) -> str:
    if rtype == 1:      # A
        return ".".join(str(b) for b in data[offset:offset + 4])
    if rtype == 28:     # AAAA
        return socket.inet_ntop(socket.AF_INET6, data[offset:offset + 16])
    if rtype in (2, 5, 12):     # NS, CNAME, PTR
        return _read_name(data, offset)[0]
    if rtype == 15:     # MX
        pref = struct.unpack(">H", data[offset:offset + 2])[0]
        return f"{pref} {_read_name(data, offset + 2)[0]}"
    if rtype == 16:     # TXT
        out, i = [], offset
        while i < offset + rdlength:
            slen = data[i]
            out.append(data[i + 1:i + 1 + slen].decode("ascii", "replace"))
            i += 1 + slen
        return " ".join(out)
    if rtype == 6:      # SOA
        mname, i = _read_name(data, offset)
        rname, _ = _read_name(data, i)
        return f"{mname} {rname}"
    return data[offset:offset + rdlength].hex()


def query(domain: str, rtype: str, server: str = "8.8.8.8",
          timeout: float = 4.0) -> list:
    qtype = RTYPES[rtype]
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    packet = header + _encode_name(domain) + struct.pack(">HH", qtype, 1)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, (server, 53))
        data, _ = sock.recvfrom(4096)

    ancount = struct.unpack(">H", data[6:8])[0]
    # skip header + question
    offset = 12
    _qname, offset = _read_name(data, offset)
    offset += 4
    results = []
    for _ in range(ancount):
        _name, offset = _read_name(data, offset)
        rt, _cls, _ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        if rt == qtype or _RTYPE_NAME.get(rt) == rtype:
            results.append(_parse_rdata(rt, data, offset, rdlength))
        offset += rdlength
    return results


def recon(domain: str, types=DEFAULT_TYPES, server: str = "8.8.8.8") -> DNSResult:
    domain = domain.strip().lower().lstrip("*.")
    result = DNSResult(domain=domain)
    for rtype in types:
        try:
            vals = query(domain, rtype, server=server)
            if vals:
                result.records[rtype] = vals
        except (OSError, struct.error, IndexError) as exc:
            result.errors.append(f"{rtype}: {exc}")
    return result
