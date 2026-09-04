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

read_pinned_version() {
  variable_name=$1
  versions_file=${2:-versions.mk}

  awk -v variable_name="$variable_name" '
    $1 == variable_name && $2 == ":=" {
      count++
      value = $3
      if (NF != 3) invalid = 1
    }
    END {
      if (count != 1 || invalid || value == "") exit 1
      print value
    }
  ' "$versions_file"
}

require_management_s3_identity() {
  management_principal_arn=${HETZNER_MANAGEMENT_PRINCIPAL_ARN:-}
  active_access_key=${MINIO_USER:-}

  case "$management_principal_arn" in
    arn:aws:iam:::user/p*:*) ;;
    *) fail "HETZNER_MANAGEMENT_PRINCIPAL_ARN is not a Hetzner S3 principal ARN" ;;
  esac

  principal_identity=${management_principal_arn#arn:aws:iam:::user/p}
  principal_project=${principal_identity%%:*}
  principal_access_key=${principal_identity#*:}
  case "$principal_project" in
    '' | *[!0-9]*) fail "management S3 principal project identifier is invalid" ;;
  esac
  case "$principal_access_key" in
    '' | *[!A-Za-z0-9]*) fail "management S3 principal access key identifier is invalid" ;;
  esac

  [ "$active_access_key" = "$principal_access_key" ] ||
    fail "active MINIO_USER does not match the dedicated management principal"
}
