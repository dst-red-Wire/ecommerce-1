#!/bin/sh
set -eu
# shellcheck source=./scripts/lib.sh
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

require git
require pre-commit
[ -f .pre-commit-config.yaml ] || fail ".pre-commit-config.yaml is missing"
pre-commit install --hook-type pre-commit
info "pre-commit hook installed for this worktree"
