#!/bin/sh
set -eu
# shellcheck source=scripts/lib.sh
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

expected_version=$(read_pinned_version GITLEAKS_VERSION) ||
  fail "versions.mk must define GITLEAKS_VERSION exactly once"

require gitleaks
if ! found_version=$(gitleaks version 2>/dev/null); then
  fail "unable to determine Gitleaks version"
fi

[ "$found_version" = "$expected_version" ] ||
  fail "expected Gitleaks $expected_version, found $found_version"

info "Gitleaks $found_version matches the project pin"
