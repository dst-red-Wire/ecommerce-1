#!/bin/sh
set -eu
# shellcheck source=scripts/lib.sh
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

require python3
require jq

export PYTHONDONTWRITEBYTECODE=1
python3 scripts/validate-governance.py
python3 -m unittest discover -s tests/governance -p 'test_*.py'
./scripts/check-security-tool-versions.sh

if have opa; then
  OPA_BIN=$(command -v opa)
else
  ./scripts/install-opa.sh
  OPA_BIN=${OPA_INSTALL_DIR:-$HOME/.local/bin}/opa
fi
export OPA_BIN
./scripts/test-governance-policy.sh

info "governance schema, references, unit tests and Policy as Code passed"
