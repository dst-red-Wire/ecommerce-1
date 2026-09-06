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

unformatted=$(find "$module" -type f -name '*.go' -exec gofmt -l {} +)
[ -z "$unformatted" ] || fail "gofmt required for:
$unformatted"

(
  cd "$module"
  go test ./...
  go vet ./...
  go build ./...
)
info "$service service checks completed"
