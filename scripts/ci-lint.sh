#!/bin/sh
set -eu
# shellcheck source=./scripts/lib.sh
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

if have shellcheck; then
  shell_files=$(find scripts -type f -name '*.sh' -print 2>/dev/null || true)
  if [ -n "$shell_files" ]; then
    # Word splitting is intentional: find emits repository-controlled paths.
    # shellcheck disable=SC2086
    shellcheck $shell_files
  fi
else
  warn "shellcheck is unavailable; shell lint skipped"
fi

if have go && find . -name go.mod -not -path './vendor/*' -print -quit | grep -q .; then
  unformatted=$(find . -type f -name '*.go' -not -path './vendor/*' -exec gofmt -l {} +)
  [ -z "$unformatted" ] || fail "gofmt required for:\n$unformatted"
else
  info "no Go modules found; Go lint skipped"
fi

if have npm; then
  find . -name package.json -not -path '*/node_modules/*' -print | while IFS= read -r manifest; do
    directory=${manifest%/*}
    [ -f "$directory/package-lock.json" ] || { warn "$directory has no package-lock.json; npm lint skipped"; continue; }
    (cd "$directory" && npm ci && npm run lint --if-present)
  done
else
  info "npm unavailable; frontend lint skipped"
fi

info "lint checks completed"
