#!/bin/sh
set -eu
# shellcheck source=./scripts/lib.sh
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

require shellcheck
shell_files=$(find scripts -type f -name '*.sh' -print 2>/dev/null || true)
if [ -n "$shell_files" ]; then
  # Word splitting is intentional: find emits repository-controlled paths only.
  # shellcheck disable=SC2086
  shellcheck $shell_files
fi
info "shell checks completed"
