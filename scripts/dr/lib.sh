#!/bin/sh

set -eu

# DR scripts extend the repository-wide CI helpers instead of duplicating them.
# This file is intended to be sourced by scripts located in scripts/dr/.
DR_SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$DR_SCRIPT_DIR/../lib.sh"

DR_OUTPUT_FORMAT=${DR_OUTPUT_FORMAT:-text}

_dr_emit() {
  status=$1
  shift
  message=$*

  case "$DR_OUTPUT_FORMAT" in
    text)
      printf '[dr] %s: %s\n' "$status" "$message"
      ;;
    kv)
      safe_message=$(printf '%s' "$message" | tr '\n' ' ')
      printf 'status=%s message=%s\n' "$status" "$safe_message"
      ;;
    *)
      fail "unsupported DR_OUTPUT_FORMAT: $DR_OUTPUT_FORMAT"
      ;;
  esac
}

dr_info() { _dr_emit INFO "$*"; }
pass() { _dr_emit PASS "$*"; }
skip() { _dr_emit SKIP "$*"; }
dr_warn() { _dr_emit WARN "$*" >&2; }
dr_fail() { _dr_emit FAIL "$*" >&2; exit 1; }

require_dr_command() {
  have "$1" || dr_fail "required command not found: $1"
}

skip_if_missing_command() {
  if have "$1"; then
    return 1
  fi

  skip "optional command unavailable: $1"
  return 0
}

require_nonempty() {
  name=$1
  value=$2
  [ -n "$value" ] || dr_fail "required value is empty: $name"
}

require_positive_integer() {
  name=$1
  value=$2

  case "$value" in
    ''|*[!0-9]*|0)
      dr_fail "$name must be a positive integer"
      ;;
  esac
}

require_destructive_guard() {
  [ "${DR_ALLOW_DESTRUCTIVE:-}" = "1" ] || \
    dr_fail "destructive DR action refused: set DR_ALLOW_DESTRUCTIVE=1 explicitly"

  case "${DR_ENVIRONMENT:-}" in
    lab|staging)
      pass "destructive guard accepted for environment: $DR_ENVIRONMENT"
      ;;
    ''|prod|production)
      dr_fail "destructive DR action refused for production or undefined environment"
      ;;
    *)
      dr_fail "destructive DR action refused for unsupported environment: $DR_ENVIRONMENT"
      ;;
  esac
}

run_with_timeout() {
  seconds=$1
  shift

  require_positive_integer timeout_seconds "$seconds"
  [ "$#" -gt 0 ] || dr_fail "run_with_timeout requires a command"

  if have timeout; then
    timeout "$seconds" "$@"
    return $?
  fi

  dr_fail "timeout command is required for bounded external checks"
}
