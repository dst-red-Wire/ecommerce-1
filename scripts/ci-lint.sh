#!/bin/sh
set -eu
# shellcheck source=./scripts/lib.sh
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

if find services -name go.mod -not -path '*/vendor/*' -print -quit 2>/dev/null | grep -q .; then
  ./scripts/ensure-go-toolchain.sh
  export PATH="$HOME/.local/bin:$PATH"
  require gofmt
  unformatted=$(find services -type f -name '*.go' -not -path '*/vendor/*' -exec gofmt -l {} +)
  [ -z "$unformatted" ] || fail "gofmt required for:
$unformatted"
else
  info "no Go service modules found; Go lint not applicable"
fi

if [ -f frontend/package.json ]; then
  ./scripts/ci-frontend.sh lint all
else
  info "frontend package is absent; frontend lint not applicable"
fi

info "lint checks completed"
