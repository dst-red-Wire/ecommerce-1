#!/bin/sh
set -eu
# shellcheck source=scripts/lib.sh
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

require curl
require install
require sha256sum
require uname

version=$(read_pinned_version OPA_VERSION) ||
  fail "versions.mk must define OPA_VERSION exactly once"
expected_sha256=$(read_pinned_version OPA_LINUX_AMD64_SHA256) ||
  fail "versions.mk must define OPA_LINUX_AMD64_SHA256 exactly once"

case "$expected_sha256" in
  '' | *[!0-9a-f]*) fail "OPA_LINUX_AMD64_SHA256 must be a lowercase SHA-256 digest" ;;
esac
[ "${#expected_sha256}" -eq 64 ] || fail "OPA_LINUX_AMD64_SHA256 must contain 64 characters"
[ "$(uname -s)" = Linux ] || fail "OPA installer supports Linux only"
[ "$(uname -m)" = x86_64 ] || fail "OPA installer requires Linux x86_64"

: "${HOME:?HOME must be set}"
install_directory=${OPA_INSTALL_DIR:-$HOME/.local/bin}
case "$install_directory" in
  /*) ;;
  *) fail "OPA_INSTALL_DIR must be an absolute path" ;;
esac
target=$install_directory/opa

if [ -x "$target" ]; then
  installed_version=$("$target" version 2>/dev/null | awk '$1 == "Version:" {print $2}')
  installed_sha256=$(sha256sum "$target" | awk '{print $1}')
  if [ "$installed_version" = "$version" ] && [ "$installed_sha256" = "$expected_sha256" ]; then
    info "OPA $version is already installed and verified at $target"
    exit 0
  fi
  warn "replacing unverified OPA installation at $target"
fi

temporary_file=$(mktemp)
cleanup() { rm -f -- "$temporary_file"; }
trap cleanup EXIT HUP INT TERM
curl --fail --location --silent --show-error \
  --retry 3 --retry-delay 1 --retry-connrefused \
  --output "$temporary_file" \
  "https://openpolicyagent.org/downloads/v$version/opa_linux_amd64"
[ -s "$temporary_file" ] || fail "downloaded OPA binary is empty"
actual_sha256=$(sha256sum "$temporary_file" | awk '{print $1}')
[ "$actual_sha256" = "$expected_sha256" ] || fail "OPA binary SHA-256 mismatch"
chmod 0755 "$temporary_file"
downloaded_version=$("$temporary_file" version 2>/dev/null | awk '$1 == "Version:" {print $2}')
[ "$downloaded_version" = "$version" ] ||
  fail "expected downloaded OPA $version, found $downloaded_version"

install -d -m 0755 "$install_directory"
install -m 0755 "$temporary_file" "$target"
info "installed and verified OPA $version at $target"
