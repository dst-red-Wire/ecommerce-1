#!/bin/sh
set -eu
# shellcheck source=./scripts/lib.sh
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

./scripts/ensure-go-toolchain.sh
export PATH="$HOME/.local/bin:$PATH"
require go
require gofmt

unformatted=$(find services/product -type f -name '*.go' -exec gofmt -l {} +)
[ -z "$unformatted" ] || fail "gofmt required for:\n$unformatted"

(
  cd services/product
  go test ./...
  go vet ./...
)
info "product golden runtime checks completed"
