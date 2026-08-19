#!/bin/sh
set -eu
# shellcheck source=scripts/lib.sh
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

[ "${RUN_LOAD_TESTS:-0}" = "1" ] || fail "load tests are disabled; set RUN_LOAD_TESTS=1 only in an authorized staging environment"
[ -n "${TARGET_URL:-}" ] || fail "TARGET_URL is required"
require k6

TEST_PROFILE="${TEST_PROFILE:-load}" k6 run performance/k6/scenarios/ecommerce.js
