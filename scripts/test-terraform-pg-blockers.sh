#!/bin/sh
set -eu

# Offline only: synthetic URLs, metadata fixtures and isolated temporary state.
# shellcheck disable=SC1091
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

require python3
PYTHONDONTWRITEBYTECODE=1
export PYTHONDONTWRITEBYTECODE
python3 -m unittest -v \
  tests/terraform-pg/test_blockers.py \
  tests/terraform-pg/test_project_env.py
info "Terraform PostgreSQL blocker regression suites passed offline"
