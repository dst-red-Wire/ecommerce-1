#!/bin/sh
set -eu
# shellcheck source=scripts/lib.sh
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

require curl
require install
require mktemp
require sha256sum
require tar
require uname

version=$(read_pinned_version TRIVY_VERSION) ||
  fail "versions.mk must define TRIVY_VERSION exactly once"
expected_sha256=$(read_pinned_version TRIVY_LINUX_X64_SHA256) ||
  fail "versions.mk must define TRIVY_LINUX_X64_SHA256 exactly once"
case "$expected_sha256" in
  '' | *[!0-9a-f]*) fail "TRIVY_LINUX_X64_SHA256 must be a lowercase SHA-256 digest" ;;
esac
[ "${#expected_sha256}" -eq 64 ] || fail "TRIVY_LINUX_X64_SHA256 must contain 64 characters"
[ "$(uname -s)" = Linux ] || fail "Trivy installer supports Linux only"
[ "$(uname -m)" = x86_64 ] || fail "Trivy installer requires Linux x86_64"

: "${HOME:?HOME must be set}"
install_directory=${TRIVY_INSTALL_DIR:-$HOME/.local/bin}
case "$install_directory" in
  /*) ;;
  *) fail "TRIVY_INSTALL_DIR must be an absolute path" ;;
esac
target=$install_directory/trivy

if [ -x "$target" ]; then
  installed_version=$("$target" --version 2>/dev/null | awk 'NR == 1 {print $2}')
  if [ "$installed_version" = "$version" ]; then
    info "Trivy $version is already installed at $target"
    exit 0
  fi
  warn "replacing Trivy installation at $target"
fi

work_directory=$(mktemp -d)
cleanup() {
  [ -n "${work_directory:-}" ] && [ -d "$work_directory" ] &&
    rm -rf -- "$work_directory"
}
trap cleanup EXIT HUP INT TERM
archive=trivy_${version}_Linux-64bit.tar.gz
curl --fail --location --silent --show-error \
  --retry 3 --retry-delay 1 --retry-connrefused \
  --output "$work_directory/$archive" \
  "https://github.com/aquasecurity/trivy/releases/download/v$version/$archive"
actual_sha256=$(sha256sum "$work_directory/$archive" | awk '{print $1}')
[ "$actual_sha256" = "$expected_sha256" ] || fail "Trivy archive SHA-256 mismatch"
tar -xzf "$work_directory/$archive" -C "$work_directory" trivy
[ -f "$work_directory/trivy" ] || fail "Trivy binary is missing from archive"
chmod 0755 "$work_directory/trivy"
downloaded_version=$("$work_directory/trivy" --version 2>/dev/null | awk 'NR == 1 {print $2}')
[ "$downloaded_version" = "$version" ] ||
  fail "expected downloaded Trivy $version, found $downloaded_version"

install -d -m 0755 "$install_directory"
install -m 0755 "$work_directory/trivy" "$target"
info "installed Trivy $version from verified archive at $target"
