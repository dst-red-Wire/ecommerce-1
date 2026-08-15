#!/bin/sh
set -eu
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

modules=$(find . -name go.mod -not -path './vendor/*' -print 2>/dev/null || true)
if [ -n "$modules" ]; then
  require go
  printf '%s\n' "$modules" | while IFS= read -r module; do
    directory=${module%/*}
    info "testing Go module $directory"
    (cd "$directory" && go test ./...)
  done
else
  info "no Go modules found; Go tests skipped"
fi

if have npm; then
  find . -name package.json -not -path '*/node_modules/*' -print | while IFS= read -r manifest; do
    directory=${manifest%/*}
    [ -f "$directory/package-lock.json" ] || { warn "$directory has no package-lock.json; npm tests skipped"; continue; }
    (cd "$directory" && npm ci && npm test --if-present)
  done
else
  info "npm unavailable; frontend tests skipped"
fi

info "test checks completed"
