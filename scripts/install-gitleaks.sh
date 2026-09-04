#!/bin/sh
set -eu
# shellcheck source=scripts/lib.sh
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

require awk
require sha256sum
require uname

version=$(read_pinned_version GITLEAKS_VERSION) ||
  fail "versions.mk must define GITLEAKS_VERSION exactly once"
checksums_sha256=$(read_pinned_version GITLEAKS_CHECKSUMS_SHA256) ||
  fail "versions.mk must define GITLEAKS_CHECKSUMS_SHA256 exactly once"
archive_sha256=$(read_pinned_version GITLEAKS_LINUX_X64_SHA256) ||
  fail "versions.mk must define GITLEAKS_LINUX_X64_SHA256 exactly once"
binary_sha256=$(read_pinned_version GITLEAKS_LINUX_X64_BINARY_SHA256) ||
  fail "versions.mk must define GITLEAKS_LINUX_X64_BINARY_SHA256 exactly once"

validate_sha256() {
  checksum_name=$1
  checksum_value=$2
  case "$checksum_value" in
    '' | *[!0-9a-f]*) fail "$checksum_name must be a lowercase SHA-256 digest" ;;
  esac
  [ "${#checksum_value}" -eq 64 ] ||
    fail "$checksum_name must contain exactly 64 hexadecimal characters"
}

validate_sha256 GITLEAKS_CHECKSUMS_SHA256 "$checksums_sha256"
validate_sha256 GITLEAKS_LINUX_X64_SHA256 "$archive_sha256"
validate_sha256 GITLEAKS_LINUX_X64_BINARY_SHA256 "$binary_sha256"

[ "$(uname -s)" = Linux ] || fail "Gitleaks installer supports Linux only"
[ "$(uname -m)" = x86_64 ] || fail "Gitleaks installer requires Linux x86_64"

: "${HOME:?HOME must be set}"
install_directory=${GITLEAKS_INSTALL_DIR:-$HOME/.local/bin}
case "$install_directory" in
  /*) ;;
  *) fail "GITLEAKS_INSTALL_DIR must be an absolute path" ;;
esac
target=$install_directory/gitleaks

if [ -x "$target" ]; then
  installed_version=$("$target" version 2>/dev/null || true)
  installed_sha256=$(sha256sum "$target" | awk '{print $1}')
  if [ "$installed_version" = "$version" ] && [ "$installed_sha256" = "$binary_sha256" ]; then
    info "Gitleaks $version is already installed and verified at $target"
    exit 0
  fi
  warn "replacing unverified Gitleaks installation at $target"
fi

require curl
require tar
require install
require mktemp

archive_name=gitleaks_${version}_linux_x64.tar.gz
checksums_name=gitleaks_${version}_checksums.txt
release_base=https://github.com/gitleaks/gitleaks/releases/download/v$version
work_directory=$(mktemp -d)
cleanup() {
  [ -n "${work_directory:-}" ] && [ -d "$work_directory" ] &&
    rm -rf -- "$work_directory"
}
trap cleanup EXIT HUP INT TERM

download() {
  source_url=$1
  destination=$2
  curl --fail --location --silent --show-error \
    --retry 3 --retry-delay 1 --retry-connrefused \
    --output "$destination" "$source_url"
  [ -s "$destination" ] || fail "download is empty: $source_url"
}

download "$release_base/$archive_name" "$work_directory/$archive_name"
download "$release_base/$checksums_name" "$work_directory/$checksums_name"

actual_checksums_sha256=$(sha256sum "$work_directory/$checksums_name" | awk '{print $1}')
[ "$actual_checksums_sha256" = "$checksums_sha256" ] ||
  fail "official Gitleaks checksum manifest SHA-256 mismatch"

manifest_archive_sha256=$(awk -v archive_name="$archive_name" '
  $2 == archive_name { count++; value = $1 }
  END {
    if (count != 1) exit 1
    print value
  }
' "$work_directory/$checksums_name") ||
  fail "official Gitleaks checksum manifest has no unique entry for $archive_name"
[ "$manifest_archive_sha256" = "$archive_sha256" ] ||
  fail "pinned Gitleaks archive SHA-256 differs from the official manifest"

actual_archive_sha256=$(sha256sum "$work_directory/$archive_name" | awk '{print $1}')
[ "$actual_archive_sha256" = "$manifest_archive_sha256" ] ||
  fail "Gitleaks archive SHA-256 mismatch"

archive_entries=$(tar -tzf "$work_directory/$archive_name") ||
  fail "Gitleaks archive is unreadable"
expected_archive_entries='LICENSE
README.md
gitleaks'
[ "$archive_entries" = "$expected_archive_entries" ] ||
  fail "Gitleaks archive contains unexpected entries"

tar -xzf "$work_directory/$archive_name" -C "$work_directory" gitleaks ||
  fail "unable to extract Gitleaks binary"
[ -f "$work_directory/gitleaks" ] || fail "Gitleaks binary is missing from archive"

actual_binary_sha256=$(sha256sum "$work_directory/gitleaks" | awk '{print $1}')
[ "$actual_binary_sha256" = "$binary_sha256" ] ||
  fail "extracted Gitleaks binary SHA-256 mismatch"
chmod 0755 "$work_directory/gitleaks"
downloaded_version=$("$work_directory/gitleaks" version 2>/dev/null) ||
  fail "downloaded Gitleaks binary cannot report its version"
[ "$downloaded_version" = "$version" ] ||
  fail "expected downloaded Gitleaks $version, found $downloaded_version"

install -d -m 0755 "$install_directory"
temporary_target=$install_directory/.gitleaks.$$
install -m 0755 "$work_directory/gitleaks" "$temporary_target"
mv -f -- "$temporary_target" "$target"

installed_sha256=$(sha256sum "$target" | awk '{print $1}')
[ "$installed_sha256" = "$binary_sha256" ] || fail "installed Gitleaks SHA-256 mismatch"
installed_version=$("$target" version 2>/dev/null) ||
  fail "installed Gitleaks cannot report its version"
[ "$installed_version" = "$version" ] ||
  fail "expected installed Gitleaks $version, found $installed_version"

info "installed Gitleaks $version at $target"
info "verified Linux x86_64 archive SHA-256: $archive_sha256"
case ":$PATH:" in
  *":$install_directory:"*) ;;
  *) info "add Gitleaks for this shell with: PATH=$install_directory:\$PATH" ;;
esac
