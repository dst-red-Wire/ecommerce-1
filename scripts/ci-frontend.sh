#!/bin/sh
set -eu
# shellcheck source=./scripts/lib.sh
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

action=${1:-check}
scope=${2:-all}

case "$action" in
  check|lint|test|build) ;;
  *) fail "frontend action must be one of: check, lint, test, build" ;;
esac
case "$scope" in
  all|storefront|admin) ;;
  *) fail "frontend scope must be one of: all, storefront, admin" ;;
esac

[ -f frontend/package.json ] || fail "frontend/package.json is required"
[ -f frontend/pnpm-workspace.yaml ] || fail "frontend/pnpm-workspace.yaml is required"
[ -f frontend/pnpm-lock.yaml ] || fail "frontend/pnpm-lock.yaml is required"
require node
require corepack

package_manager=$(node -p "require('./frontend/package.json').packageManager || ''")
case "$package_manager" in
  pnpm@*) ;;
  *) fail "frontend packageManager must declare an exact pnpm version; got: $package_manager" ;;
esac
expected_pnpm=${package_manager#pnpm@}
actual_pnpm=$(cd frontend && corepack pnpm --version)
[ "$actual_pnpm" = "$expected_pnpm" ] || fail "pnpm version mismatch: expected $expected_pnpm, got $actual_pnpm"

run_pnpm() (
  cd frontend
  corepack pnpm "$@"
)

run_pnpm install --frozen-lockfile

run_lint() {
  if [ "$scope" = all ]; then
    run_pnpm run lint
  else
    run_pnpm exec eslint "apps/$scope" packages
  fi
}

run_typecheck() {
  if [ "$scope" = all ]; then
    run_pnpm run typecheck
  else
    run_pnpm --filter @noma/ui typecheck
    run_pnpm --filter "@noma/$scope" typecheck
  fi
}

run_tests() {
  if [ "$scope" = all ]; then
    run_pnpm run test
  else
    run_pnpm --filter "@noma/$scope" test
  fi
}

run_build() {
  if [ "$scope" = all ]; then
    run_pnpm run build
  else
    run_pnpm --filter "@noma/$scope" build
  fi
}

case "$action" in
  lint) run_lint ;;
  test)
    run_typecheck
    run_tests
    ;;
  build) run_build ;;
  check)
    run_lint
    run_typecheck
    run_tests
    run_build
    ;;
esac

info "frontend $scope $action checks completed"
