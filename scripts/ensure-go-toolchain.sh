#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(git rev-parse --show-toplevel)"
# shellcheck disable=SC1091
. "$ROOT/config/toolchain/versions.env"

: "${GO_VERSION:?GO_VERSION must be pinned in config/toolchain/versions.env}"
: "${GO_SHA256_LINUX_AMD64:?GO_SHA256_LINUX_AMD64 must be pinned in config/toolchain/versions.env}"

export PATH="$HOME/.local/bin:$PATH"
expected="go${GO_VERSION}"
if command -v go >/dev/null 2>&1 && command -v gofmt >/dev/null 2>&1; then
  current="$(go version | awk '{print $3}')"
  if [[ "$current" == "$expected" ]]; then
    printf 'PASS go-toolchain %s already available\n' "$expected"
    exit 0
  fi
fi

machine="$(uname -m)"
[[ "$machine" == x86_64 || "$machine" == amd64 ]] || {
  printf 'FAIL go-toolchain: only linux/amd64 is pinned, got %s\n' "$machine" >&2
  exit 2
}

target="$HOME/.local/share/ecommerce-1/toolchains/go/$GO_VERSION"
bin_dir="$HOME/.local/bin"
archive="$(mktemp)"
staging="${target}.staging.$$"
extract_dir="$(mktemp -d)"
cleanup() {
  rm -f "$archive"
  rm -rf "$staging" "$extract_dir"
}
trap cleanup EXIT

url="https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
if ! curl -fL --retry 3 --retry-delay 2 -o "$archive" "$url"; then
  if command -v curl.exe >/dev/null 2>&1 && command -v wslpath >/dev/null 2>&1; then
    curl.exe -fL --retry 3 --retry-delay 2 -o "$(wslpath -w "$archive")" "$url" >/dev/null
  else
    printf 'FAIL go-toolchain: download failed and Windows curl fallback is unavailable\n' >&2
    exit 3
  fi
fi

printf '%s  %s\n' "$GO_SHA256_LINUX_AMD64" "$archive" | sha256sum -c - >/dev/null || {
  printf 'FAIL go-toolchain: SHA256 verification failed for %s\n' "$url" >&2
  exit 4
}

mkdir -p "$(dirname "$target")" "$bin_dir"
tar -C "$extract_dir" -xzf "$archive"
# The official archive extracts as a top-level go/ directory.
mv "$extract_dir/go" "$staging"
rm -rf "$target"
mv "$staging" "$target"

for tool in go gofmt; do
  link="$bin_dir/$tool"
  if [[ -e "$link" && ! -L "$link" ]]; then
    printf 'FAIL go-toolchain: refusing to replace unmanaged file %s\n' "$link" >&2
    exit 5
  fi
  ln -sfn "$target/bin/$tool" "$link"
done

hash -r
current="$("$bin_dir/go" version | awk '{print $3}')"
[[ "$current" == "$expected" ]] || {
  printf 'FAIL go-toolchain: expected %s, got %s\n' "$expected" "$current" >&2
  exit 6
}
printf 'PASS go-toolchain %s installed with verified SHA256\n' "$expected"
