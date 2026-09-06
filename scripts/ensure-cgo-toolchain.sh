#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"
export PATH="$HOME/.local/bin:$PATH"

"$ROOT/scripts/ensure-go-toolchain.sh"

if ! command -v cc >/dev/null 2>&1; then
  [[ -r /etc/os-release ]] || { echo 'FAIL cgo-toolchain: /etc/os-release missing' >&2; exit 2; }
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ "${ID:-}" == ubuntu ]] || {
    echo "FAIL cgo-toolchain: automatic compiler install is supported only on Ubuntu, got ${ID:-unknown}" >&2
    exit 2
  }
  grep -qi microsoft /proc/version 2>/dev/null || {
    echo 'FAIL cgo-toolchain: expected WSL2 Microsoft kernel for workstation reconciliation' >&2
    exit 2
  }

  sudo apt-get update
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends build-essential
fi

command -v cc >/dev/null 2>&1 || {
  echo 'FAIL cgo-toolchain: native C compiler is unavailable after reconciliation' >&2
  exit 3
}

cgo="$(CGO_ENABLED=1 go env CGO_ENABLED)"
[[ "$cgo" == 1 ]] || {
  echo "FAIL cgo-toolchain: expected explicit CGO_ENABLED=1, got $cgo" >&2
  exit 4
}

printf 'PASS cgo-toolchain compiler=%s CGO_ENABLED=1\n' "$(command -v cc)"
