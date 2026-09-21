#!/usr/bin/env python3
"""Minimal offline DNS/NTP fixtures for the local RKE2 HA qualification."""

from __future__ import annotations

import argparse
import ipaddress
import socket
import struct
import time


def _dns_name(payload: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    while True:
        if offset >= len(payload):
            raise ValueError("truncated DNS question")
        length = payload[offset]
        offset += 1
        if length == 0:
            break
        if length > 63 or offset + length > len(payload):
            raise ValueError("invalid DNS label")
        labels.append(payload[offset : offset + length].decode("ascii"))
        offset += length
    return ".".join(labels).lower() + ".", offset


def _dns_server(bind: str, port: int, record_name: str, record_address: str) -> None:
    expected = record_name.rstrip(".").lower() + "."
    address = ipaddress.IPv4Address(record_address).packed
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind, port))
    while True:
        payload, peer = sock.recvfrom(4096)
        if len(payload) < 12:
            continue
        ident, flags, qdcount, _, _, _ = struct.unpack("!HHHHHH", payload[:12])
        if qdcount != 1:
            continue
        try:
            name, offset = _dns_name(payload, 12)
        except (UnicodeDecodeError, ValueError):
            continue
        if offset + 4 > len(payload):
            continue
        qtype, qclass = struct.unpack("!HH", payload[offset : offset + 4])
        question = payload[12 : offset + 4]
        recursion_desired = flags & 0x0100
        if name == expected and qtype == 1 and qclass == 1:
            response_flags = 0x8000 | 0x0400 | recursion_desired | 0x0080
            header = struct.pack("!HHHHHH", ident, response_flags, 1, 1, 0, 0)
            answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + address
            response = header + question + answer
        else:
            response_flags = 0x8000 | 0x0400 | recursion_desired | 0x0080 | 0x0003
            response = struct.pack("!HHHHHH", ident, response_flags, 1, 0, 0, 0) + question
        sock.sendto(response, peer)


def _ntp_timestamp(now: float) -> bytes:
    seconds = int(now) + 2_208_988_800
    fraction = int((now - int(now)) * (1 << 32))
    return struct.pack("!II", seconds, fraction)


def _ntp_server(bind: str, port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind, port))
    while True:
        payload, peer = sock.recvfrom(1024)
        if len(payload) < 48:
            continue
        now = time.time()
        response = bytearray(48)
        response[0] = 0x24
        response[1] = 2
        response[2] = payload[2]
        response[3] = 0xEC
        response[12:16] = b"LOCL"
        response[16:24] = _ntp_timestamp(now - 1)
        response[24:32] = payload[40:48]
        response[32:40] = _ntp_timestamp(now)
        response[40:48] = _ntp_timestamp(time.time())
        sock.sendto(response, peer)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    dns = sub.add_parser("dns")
    dns.add_argument("--bind", required=True)
    dns.add_argument("--port", type=int, required=True)
    dns.add_argument("--record-name", required=True)
    dns.add_argument("--record-address", required=True)
    ntp = sub.add_parser("ntp")
    ntp.add_argument("--bind", required=True)
    ntp.add_argument("--port", type=int, required=True)
    args = parser.parse_args()

    bind = str(ipaddress.IPv4Address(args.bind))
    if args.mode == "dns":
        record_address = str(ipaddress.IPv4Address(args.record_address))
        _dns_server(bind, args.port, args.record_name, record_address)
    else:
        _ntp_server(bind, args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
