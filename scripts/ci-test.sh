#!/bin/sh
set -eu
# shellcheck source=./scripts/lib.sh
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

require ruby
for test_file in tests/*_test.rb; do
  [ -f "$test_file" ] || continue
  ruby -Itest "$test_file"
done

if [ -d tests/delivery ]; then
  require python3
  python3 -m unittest discover -s tests/delivery -p 'test_*.py'
fi

modules=$(find services -name go.mod -not -path '*/vendor/*' -print 2>/dev/null || true)
if [ -n "$modules" ]; then
  ./scripts/ensure-go-toolchain.sh
  export PATH="$HOME/.local/bin:$PATH"
  require go
  printf '%s
' "$modules" | while IFS= read -r module; do
    directory=${module%/*}
    info "testing Go module $directory"
    (cd "$directory" && go test ./... && go vet ./...)
  done
else
  info "no Go service modules found; Go tests not applicable"
fi

if [ -f frontend/package.json ]; then
  ./scripts/ci-frontend.sh test all
else
  info "frontend package is absent; frontend tests not applicable"
fi

info "test checks completed"
