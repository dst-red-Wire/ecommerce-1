#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(git rev-parse --show-toplevel)"
# shellcheck disable=SC1091
. "$ROOT/config/toolchain/versions.env"

: "${SQLC_VERSION:?SQLC_VERSION must be pinned in config/toolchain/versions.env}"
: "${SQLC_SHA256_LINUX_AMD64:?SQLC_SHA256_LINUX_AMD64 must be pinned in config/toolchain/versions.env}"

export PATH="$HOME/.local/bin:$PATH"
expected="v${SQLC_VERSION}"
if command -v sqlc >/dev/null 2>&1; then
  current="$(sqlc version 2>/dev/null | awk '{print $NF}')"
  if [[ "$current" == "$expected" || "$current" == "$SQLC_VERSION" ]]; then
    printf 'PASS sqlc %s already available\n' "$expected"
    exit 0
  fi
fi

machine="$(uname -m)"
[[ "$machine" == x86_64 || "$machine" == amd64 ]] || {
  printf 'FAIL sqlc: only linux/amd64 is pinned, got %s\n' "$machine" >&2
  exit 2
}

target_dir="$HOME/.local/share/ecommerce-1/tools/sqlc/$SQLC_VERSION"
bin_dir="$HOME/.local/bin"
archive="$(mktemp)"
extract_dir="$(mktemp -d)"
cleanup() {
  rm -f "$archive"
  rm -rf "$extract_dir"
}
trap cleanup EXIT

url="https://github.com/sqlc-dev/sqlc/releases/download/v${SQLC_VERSION}/sqlc_${SQLC_VERSION}_linux_amd64.tar.gz"
if ! curl -fL --retry 3 --retry-delay 2 -o "$archive" "$url"; then
  if command -v curl.exe >/dev/null 2>&1 && command -v wslpath >/dev/null 2>&1; then
    curl.exe -fL --retry 3 --retry-delay 2 -o "$(wslpath -w "$archive")" "$url" >/dev/null
  else
    printf 'FAIL sqlc: download failed and Windows curl fallback is unavailable\n' >&2
    exit 3
  fi
fi

printf '%s  %s\n' "$SQLC_SHA256_LINUX_AMD64" "$archive" | sha256sum -c - >/dev/null || {
  printf 'FAIL sqlc: SHA256 verification failed for %s\n' "$url" >&2
  exit 4
}

mkdir -p "$target_dir" "$bin_dir"
tar -C "$extract_dir" -xzf "$archive"
[[ -x "$extract_dir/sqlc" ]] || {
  printf 'FAIL sqlc: release archive does not contain executable sqlc\n' >&2
  exit 5
}
install -m 0755 "$extract_dir/sqlc" "$target_dir/sqlc"

link="$bin_dir/sqlc"
if [[ -e "$link" && ! -L "$link" ]]; then
  printf 'FAIL sqlc: refusing to replace unmanaged file %s\n' "$link" >&2
  exit 6
fi
ln -sfn "$target_dir/sqlc" "$link"
hash -r
current="$("$link" version 2>/dev/null | awk '{print $NF}')"
[[ "$current" == "$expected" || "$current" == "$SQLC_VERSION" ]] || {
  printf 'FAIL sqlc: expected %s, got %s\n' "$expected" "$current" >&2
  exit 7
}
printf 'PASS sqlc %s installed with verified SHA256\n' "$expected"
