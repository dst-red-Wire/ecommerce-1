#!/bin/sh

set -eu

info() { printf '[ci] %s\n' "$*"; }
warn() { printf '[ci] warning: %s\n' "$*" >&2; }
fail() { printf '[ci] error: %s\n' "$*" >&2; exit 1; }

repo_root() {
  git rev-parse --show-toplevel 2>/dev/null || {
    script_directory=$(
      unset CDPATH
      cd -- "$(dirname -- "$0")" && pwd
    )
    cd -- "$script_directory/.."
    pwd
  }
}

have() { command -v "$1" >/dev/null 2>&1; }

require() {
  have "$1" || fail "required command not found: $1"
}
