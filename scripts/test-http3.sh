#!/bin/sh
set -eu

usage() {
  printf 'usage: %s <https-url>\n' "$0" >&2
  exit 2
}

[ "$#" -eq 1 ] || usage
target_url=$1
case "$target_url" in
  https://*) ;;
  *) printf 'FAIL: an explicit https:// URL is required\n' >&2; exit 1 ;;
esac
authority=${target_url#https://}
authority=${authority%%/*}
case "$authority" in
  *@*) printf 'FAIL: credentials in the target URL are forbidden\n' >&2; exit 1 ;;
  '') printf 'FAIL: target URL has no authority\n' >&2; exit 1 ;;
esac

if ! command -v curl >/dev/null 2>&1; then
  printf 'SKIP: curl is required\n'
  exit 77
fi
if ! curl --version | awk 'NR == 1 || /^Features:/' | grep -q 'HTTP3'; then
  printf 'SKIP: local curl has no HTTP/3 capability; install a verified HTTP/3-capable client\n'
  exit 77
fi

run_probe() {
  expected=$1
  shift
  observed=$(curl --proto '=https' \
    --connect-timeout "${HTTP3_CONNECT_TIMEOUT_SECONDS:-10}" \
    --max-time "${HTTP3_MAX_TIME_SECONDS:-30}" \
    --fail --silent --show-error --output /dev/null \
    --write-out '%{http_version}' \
    "$@" "$target_url") || return 1
  [ "$observed" = "$expected" ] || {
    printf 'FAIL: expected HTTP/%s, observed HTTP/%s\n' "$expected" "$observed" >&2
    return 1
  }
}

run_probe 3 --http3-only --tlsv1.3 || {
  printf 'FAIL: HTTP/3-only negotiation or TLS validation failed\n' >&2
  exit 1
}
run_probe 2 --http2 --tlsv1.2 || {
  printf 'FAIL: HTTP/2 fallback or TLS validation failed\n' >&2
  exit 1
}

if [ "${HTTP3_EXPECT_HTTP1:-1}" = 1 ]; then
  run_probe 1.1 --http1.1 --tlsv1.2 || {
    printf 'FAIL: HTTP/1.1 compatibility fallback failed\n' >&2
    exit 1
  }
fi

printf 'PASS: h3-only, h2 fallback, expected h1 fallback and certificate validation succeeded\n'
printf 'NOTE: UDP/443 policy parity, Alt-Svc, observability, rate limiting and WAF require separate reviewed evidence\n'
