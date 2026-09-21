#!/usr/bin/env python3
"""Probe the local DNS and NTP fixtures from an isolated Rocky node."""

from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import struct
import time


def dns_query(server: str, port: int, name: str, timeout: float = 3.0) -> str:
    ident = 0x4841
    labels = name.rstrip(".").split(".")
    question = b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\x00"
    payload = struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + question + struct.pack("!HH", 1, 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(payload, (server, port))
        response, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    if len(response) < 12:
        raise ValueError("short DNS response")
    r_ident, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", response[:12])
    if r_ident != ident or flags & 0x000F or qdcount != 1 or ancount < 1:
        raise ValueError("DNS response did not contain the expected A answer")
    offset = 12
    while response[offset] != 0:
        offset += response[offset] + 1
    offset += 1 + 4
    if response[offset : offset + 2] != b"\xc0\x0c":
        raise ValueError("unexpected DNS answer name encoding")
    rtype, rclass, _, rdlength = struct.unpack("!HHIH", response[offset + 2 : offset + 12])
    if rtype != 1 or rclass != 1 or rdlength != 4:
        raise ValueError("unexpected DNS answer type")
    return str(ipaddress.IPv4Address(response[offset + 12 : offset + 16]))


def ntp_query(server: str, port: int, timeout: float = 3.0) -> float:
    request = bytearray(48)
    request[0] = 0x23
    now = time.time()
    seconds = int(now) + 2_208_988_800
    fraction = int((now - int(now)) * (1 << 32))
    request[40:48] = struct.pack("!II", seconds, fraction)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(request, (server, port))
        response, _ = sock.recvfrom(1024)
    finally:
        sock.close()
    if len(response) < 48 or response[0] & 0x07 != 4:
        raise ValueError("invalid NTP server response")
    tx_seconds, tx_fraction = struct.unpack("!II", response[40:48])
    server_time = (tx_seconds - 2_208_988_800) + tx_fraction / float(1 << 32)
    return server_time - time.time()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dns-server", required=True)
    parser.add_argument("--dns-port", type=int, required=True)
    parser.add_argument("--dns-name", required=True)
    parser.add_argument("--dns-address", required=True)
    parser.add_argument("--ntp-server", required=True)
    parser.add_argument("--ntp-port", type=int, required=True)
    parser.add_argument("--max-ntp-offset", type=float, default=5.0)
    args = parser.parse_args()

    expected = str(ipaddress.IPv4Address(args.dns_address))
    actual = dns_query(
        str(ipaddress.IPv4Address(args.dns_server)),
        args.dns_port,
        args.dns_name,
    )
    if actual != expected:
        raise SystemExit(f"DNS answer mismatch: expected {expected}, got {actual}")
    offset = ntp_query(str(ipaddress.IPv4Address(args.ntp_server)), args.ntp_port)
    if abs(offset) > args.max_ntp_offset:
        raise SystemExit(f"NTP offset exceeds bound: {offset:.3f}s")
    print(json.dumps({
        "dns": {
            "name": args.dns_name,
            "address": actual,
            "server": args.dns_server,
            "port": args.dns_port,
        },
        "ntp": {
            "server": args.ntp_server,
            "port": args.ntp_port,
            "offset_seconds": round(offset, 6),
            "maximum_offset_seconds": args.max_ntp_offset,
        },
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
