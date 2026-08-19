#!/bin/sh
set -eu
# shellcheck source=scripts/lib.sh
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

scenario=performance/k6/scenarios/ecommerce.js
[ -f "$scenario" ] || { info "no k6 scenario found; performance validation skipped"; exit 0; }
require k6
k6 inspect "$scenario" >/dev/null
info "k6 scenario syntax and options validated; no HTTP traffic was generated"
