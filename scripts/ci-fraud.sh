#!/bin/sh
set -eu
# shellcheck source=scripts/lib.sh
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

require jq
catalog=tests/security/fraud-abuse-scenarios.json
[ -f "$catalog" ] || fail "missing fraud/abuse scenario catalog: $catalog"

jq --exit-status '
  .version == 1 and
  (.scenarios | length > 0) and
  all(.scenarios[];
    (.id | length > 0) and
    (.objective | length > 0) and
    (.environment == "staging") and
    (.syntheticData == true) and
    (.expected | length > 0) and
    (.pass | length > 0) and
    (.fail | length > 0) and
    (.severity | IN("critical", "high")) and
    (.gate == "identity-fraud-abuse") and
    (.artifact | length > 0) and
    (.frequency | length > 0))
' "$catalog" >/dev/null

info "fraud and abuse scenario definitions validated; no attack traffic was generated"
