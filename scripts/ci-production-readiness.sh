#!/bin/sh
set -eu
# shellcheck source=scripts/lib.sh
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

require jq
catalog=tests/production-readiness/gates.json
[ -f "$catalog" ] || fail "missing production gate catalog: $catalog"

jq --exit-status '
  .version == 1 and
  (.gates | length == 11) and
  all(.gates[];
    (.id | length > 0) and
    (.command | length > 0) and
    (.pass | length > 0) and
    (.fail | length > 0) and
    (.artifact | length > 0) and
    (.requiredFor | index("production") != null))
' "$catalog" >/dev/null

if [ "${PRODUCTION_GATE_MODE:-validate}" != "enforce" ]; then
  info "production gate catalog validated"
  exit 0
fi

results_directory=${GATE_RESULTS_DIR:-artifacts/gates}
failed=0
for gate_id in $(jq -r '.gates[] | select(.requiredFor | index("production")) | .id' "$catalog"); do
  result_file="$results_directory/$gate_id.json"
  if [ ! -f "$result_file" ] || ! jq --exit-status '.status == "pass"' "$result_file" >/dev/null 2>&1; then
    warn "production blocked: missing or failed gate $gate_id"
    failed=1
  fi
done

[ "$failed" -eq 0 ] || fail "production readiness gates did not pass"
info "all production readiness gates passed"
