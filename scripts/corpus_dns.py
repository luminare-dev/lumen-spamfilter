#!/usr/bin/env python3
"""A tiny authoritative DNS server for the corpus test (Python standard library only).

It answers A, MX, TXT and PTR questions from a JSON zone file and NXDOMAIN for every other name,
so the Rspamd container in CI resolves SPF, DKIM and DMARC records of the synthetic senders and
never asks the internet (no blocklist or URL lookups leave the runner).

Zone file: {"name": {"A": ["198.51.100.10"], "MX": ["mail.example.net"], "TXT": ["v=spf1 ..."],
"PTR": ["mail.example.net"]}}

Usage: python3 scripts/corpus_dns.py ZONE.json [--port 5353]
"""

from __future__ import annotations

import argparse
import json
import socket
import struct
import sys

TYPES = {1: "A", 12: "PTR", 15: "MX", 16: "TXT"}


def parse_name(data: bytes, off: int) -> tuple[str, int]:
    labels = []
    while True:
        n = data[off]
        if n == 0:
            return ".".join(labels), off + 1
        if n & 0xC0:
            raise ValueError("compressed question names are not expected")
        labels.append(data[off + 1: off + 1 + n].decode("ascii", "replace"))
        off += 1 + n


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii")
        out += bytes([len(raw)]) + raw
    return out + b"\0"


def rdata(rtype: str, value: str) -> bytes:
    if rtype == "A":
        return socket.inet_aton(value)
    if rtype == "MX":
        return struct.pack("!H", 10) + encode_name(value)
    if rtype == "PTR":
        return encode_name(value)
    raw = value.encode("utf-8")
    return b"".join(bytes([len(raw[i:i + 255])]) + raw[i:i + 255] for i in range(0, max(len(raw), 1), 255))


def answer(query: bytes, zone: dict) -> bytes:
    qid, flags, qd = struct.unpack("!HHH", query[:6])
    name, off = parse_name(query, 12)
    qtype, _qclass = struct.unpack("!HH", query[off: off + 4])
    question = query[12: off + 4]
    entry = zone.get(name.lower().rstrip("."))
    rtype = TYPES.get(qtype)
    records = (entry or {}).get(rtype, []) if rtype else []
    rcode = 0 if entry is not None else 3
    out_flags = 0x8000 | 0x0400 | (flags & 0x0100) | 0x0080 | rcode  # QR, AA, RD copied, RA
    body = b""
    for value in records:
        rd = rdata(rtype, value)
        body += struct.pack("!HHHIH", 0xC00C, qtype, 1, 300, len(rd)) + rd
    return struct.pack("!HHHHHH", qid, out_flags, 1, len(records), 0, 0) + question + body


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("zone")
    ap.add_argument("--port", type=int, default=5353)
    args = ap.parse_args(argv)
    with open(args.zone, encoding="utf-8") as fh:
        zone = {k.lower(): v for k, v in json.load(fh).items()}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", args.port))
    print(f"corpus DNS on 127.0.0.1:{args.port}, {len(zone)} names", flush=True)
    while True:
        data, addr = sock.recvfrom(4096)
        try:
            sock.sendto(answer(data, zone), addr)
        except (ValueError, IndexError, struct.error) as exc:
            print(f"bad query from {addr}: {exc}", file=sys.stderr, flush=True)


if __name__ == "__main__":
    sys.exit(main())
