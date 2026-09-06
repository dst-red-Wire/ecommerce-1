#!/usr/bin/env bash
set -Eeuo pipefail

# Reconcile Product persistence code generation and pinned Go dependencies.
# This script owns only local developer bootstrap state and Go module metadata.
# It does not start a persistent database, apply infrastructure, or publish code.

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

./scripts/ensure-docker-daemon.sh
./scripts/ensure-go-toolchain.sh
./scripts/ensure-sqlc.sh
export PATH="$HOME/.local/bin:$PATH"

cd services/product

# Dependency ownership belongs to services/product/go.mod. Keep module
# reconciliation isolated from the root workspace so go get/go mod tidy cannot
# rewrite go.work as an incidental side effect.
export GOWORK=off

# Critical ordering contract: store.go imports sqlcgen. Generate that local
# package before `go get` asks the Go resolver to inspect all module imports.
sqlc generate
sqlc vet
[[ -d internal/infrastructure/postgres/sqlcgen ]] || {
  echo 'FAIL product persistence bootstrap: sqlcgen package was not generated' >&2
  exit 2
}

# Exact versions are intentional and reviewed as part of the M2B tranche.
go get github.com/jackc/pgx/v5@v5.10.0
go get github.com/jackc/tern/v2@v2.4.3
go get github.com/testcontainers/testcontainers-go@v0.44.0
go get github.com/testcontainers/testcontainers-go/modules/postgres@v0.44.0
go mod tidy

# Regenerate after dependency reconciliation and verify SQL statically.
sqlc generate
sqlc vet

echo 'PASS Product persistence bootstrap reconciled sqlc output and pinned Go dependencies.'
