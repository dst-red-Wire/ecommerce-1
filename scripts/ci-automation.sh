#!/bin/sh
set -eu
# shellcheck source=./scripts/lib.sh
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

require python3
python3 -m unittest tests.toolchain_automation_test
info "engineering automation contracts validated"
