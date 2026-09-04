#!/usr/bin/env python3
"""Validate the canonical, non-secret Terraform pg connection URL."""

from __future__ import annotations

import os
import sys
from urllib.parse import parse_qsl, urlsplit


def fail(message: str) -> None:
    raise SystemExit(f"Terraform pg connection invalid: {message}")


conn_str = os.environ.get("PG_CONN_STR", "")
expected_host = os.environ.get("TERRAFORM_PG_TUNNEL_HOST", "")
expected_port_text = os.environ.get("TERRAFORM_PG_TUNNEL_PORT", "")

if not conn_str:
    fail("PG_CONN_STR is required")
if any(character in conn_str for character in ("\x00", "\r", "\n")):
    fail("PG_CONN_STR contains a forbidden control character")
if expected_host != "127.0.0.1":
    fail("TERRAFORM_PG_TUNNEL_HOST must equal 127.0.0.1")
try:
    expected_port = int(expected_port_text)
except ValueError:
    fail("TERRAFORM_PG_TUNNEL_PORT must be numeric")
if not 1 <= expected_port <= 65535 or str(expected_port) != expected_port_text:
    fail("TERRAFORM_PG_TUNNEL_PORT must be canonical and between 1 and 65535")

try:
    parsed = urlsplit(conn_str)
    parsed_port = parsed.port
except ValueError as exc:
    fail(f"PG_CONN_STR is not a valid URL: {exc}")

if parsed.scheme != "postgres":
    fail("scheme must equal postgres")
if parsed.fragment:
    fail("fragments are forbidden")
if parsed.username != "terraform_backend":
    fail("user must equal terraform_backend")
if parsed.password is not None:
    fail("password must be supplied only through PGPASSWORD")
if parsed.hostname != expected_host:
    fail("host must equal the approved SSH tunnel address")
if parsed_port != expected_port:
    fail("port must equal TERRAFORM_PG_TUNNEL_PORT")
if parsed.path != "/terraform_backend":
    fail("database path must equal /terraform_backend")

# Requiring the canonical authority also rejects percent-encoded user/host
# aliases, empty passwords, extra userinfo delimiters and IPv6/multihost forms.
expected_authority = f"terraform_backend@{expected_host}:{expected_port}"
if parsed.netloc != expected_authority:
    fail("authority is not in the canonical user@host:port form")

try:
    query = parse_qsl(
        parsed.query,
        keep_blank_values=True,
        strict_parsing=True,
        max_num_fields=2,
        separator="&",
    )
except ValueError as exc:
    fail(f"query string is invalid: {exc}")
if query != [("sslmode", "verify-full")] or parsed.query != "sslmode=verify-full":
    fail("the only allowed query parameter is exactly sslmode=verify-full")

sys.exit(0)
