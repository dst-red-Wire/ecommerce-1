#!/bin/sh
set -eu
# shellcheck source=scripts/lib.sh
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

expected_version=$(read_pinned_version TRIVY_VERSION) ||
  fail "versions.mk must define TRIVY_VERSION exactly once"
require trivy
found_version=$(trivy --version 2>/dev/null | awk 'NR == 1 {print $2}')
[ "$found_version" = "$expected_version" ] ||
  fail "expected Trivy $expected_version, found $found_version"
info "Trivy $found_version matches the project pin"
