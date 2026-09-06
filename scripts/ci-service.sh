#!/bin/sh
set -eu
# shellcheck source=./scripts/lib.sh
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

service=${SERVICE:-${1:-}}
case "$service" in
  ''|*[!a-z0-9-]*) fail "SERVICE must be a canonical lowercase service name" ;;
esac

module="services/$service"
[ -d "$module" ] || fail "service directory does not exist: $module"
[ -f "$module/go.mod" ] || fail "service Go module does not exist: $module/go.mod"

require ruby
ruby -ryaml -e '
  lock = YAML.safe_load(File.read(ARGV[1]))
  services = lock.dig("business", "services") || []
  exit(services.include?(ARGV[0]) ? 0 : 1)
' "$service" architecture.lock.yaml || fail "service is not declared in architecture.lock.yaml: $service"

./scripts/ensure-go-toolchain.sh
export PATH="$HOME/.local/bin:$PATH"
require go
require gofmt

# The Go race detector requires a working C compiler. Keep this in the generic
# service gate so Product and future Go services do not grow parallel CI logic.
[ -x ./scripts/ensure-cgo-toolchain.sh ] || fail "CGO toolchain reconciler is missing: scripts/ensure-cgo-toolchain.sh"
./scripts/ensure-cgo-toolchain.sh

unformatted=$(find "$module" -type f -name '*.go' -exec gofmt -l {} +)
[ -z "$unformatted" ] || fail "gofmt required for:
$unformatted"

(
  cd "$module"
  CGO_ENABLED=1 go test -race ./...
  if [ -d ./internal/infrastructure/postgres ]; then
  CGO_ENABLED=1 go test -race -tags=integration ./internal/infrastructure/postgres -count=1
  fi
  go vet ./...
  go build ./...
)
info "$service service checks completed"
