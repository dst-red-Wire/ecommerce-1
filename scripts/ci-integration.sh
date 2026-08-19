#!/bin/sh
set -eu
# shellcheck source=scripts/lib.sh
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

integration_files=$(find . -type f \( -path '*/integration/*' -o -name '*integration_test.go' -o -name '*.integration.test.*' \) -not -path './vendor/*' -not -path '*/node_modules/*' -print 2>/dev/null || true)
if [ -z "$integration_files" ]; then
  info "no integration test area found; integration tests skipped"
  exit 0
fi

info "integration tests are present; service-specific runners must publish JUnit artifacts"
