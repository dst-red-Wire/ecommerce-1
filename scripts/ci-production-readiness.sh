#!/bin/sh
set -eu
# shellcheck disable=SC1091
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

require jq
require python3
catalog=tests/production-readiness/gates.json
schema=contracts/supply-chain/gate-evidence.schema.json
trust_policy=contracts/supply-chain/gate-trust-policy.json
[ -f "$catalog" ] || fail "missing production gate catalog: $catalog"
[ -f "$schema" ] || fail "missing gate evidence schema: $schema"
[ -f "$trust_policy" ] || fail "missing gate trust policy: $trust_policy"

jq --exit-status '
  .version == 2 and
  .evidenceContract == "contracts/supply-chain/gate-evidence.schema.json" and
  (.gates | length == 11) and
  all(.gates[];
    (.id | length > 0) and
    (.command | length > 0) and
    (.pass | length > 0) and
    (.fail | length > 0) and
    (.artifact | length > 0) and
    (.requiredFor | index("production") != null))
' "$catalog" >/dev/null || fail "invalid production gate catalog"

jq --slurpfile catalog "$catalog" --exit-status '
  . as $policy |
  .version == 1 and
  .activationStatus == "NOT_PROVEN" and
  .maximumValiditySeconds > 0 and
  .maximumFutureSkewSeconds >= 0 and
  ((.gateAuthorities | keys | sort) == ($catalog[0].gates | map(.id) | sort)) and
  all(.gateAuthorities[]; . as $authority | $policy.authorities[$authority] != null) and
  ([.authorities[].keyFile] | unique | length) == (.authorities | length)
' "$trust_policy" >/dev/null || fail "invalid or incomplete closed gate trust mapping"

python3 - "$schema" <<'PY'
import json
import sys
from jsonschema import Draft202012Validator

with open(sys.argv[1], encoding="utf-8") as stream:
    Draft202012Validator.check_schema(json.load(stream))
PY

mode=${PRODUCTION_GATE_MODE:-validate}
artifact_root=${GATE_ARTIFACT_ROOT:-.}
if [ "$mode" = validate-file ]; then
  if [ -z "${GATE_RESULT_FILE:-}" ] || [ -z "${GATE_ID:-}" ]; then
    fail "GATE_RESULT_FILE and GATE_ID are required for validate-file"
  fi
  python3 scripts/validate-gate-evidence.py \
    --evidence "$GATE_RESULT_FILE" \
    --expected-gate "$GATE_ID" \
    --artifact-root "$artifact_root" >/dev/null || \
    fail "gate evidence structure or artifact binding is NOT PROVEN"
  info "gate evidence schema, authority, artifact hash, time, and replay binding validated; signature remains NOT PROVEN"
  exit 0
fi

if [ "$mode" != enforce ]; then
  info "production gate catalog, JSON Schema, and closed trust mapping validated; runtime evidence is NOT PROVEN"
  exit 0
fi

have cosign || fail "production gate signatures are NOT PROVEN: cosign is unavailable"
trust_dir=${GATE_TRUST_DIR:-}
if [ -z "$trust_dir" ] || [ ! -d "$trust_dir" ]; then
  fail "production gate signatures are NOT PROVEN: authority trust directory is unavailable"
fi

frozen_root=$(mktemp -d)
trap 'rm -rf "$frozen_root"' EXIT HUP INT TERM
mkdir "$frozen_root/trust" "$frozen_root/gates"
key_hashes=
for authority in $(jq -r '.authorities | keys[]' "$trust_policy"); do
  key_file=$(jq -r --arg authority "$authority" '.authorities[$authority].keyFile' "$trust_policy")
  case "$key_file" in
    ""|*/*|*..*) fail "unsafe authority key mapping" ;;
  esac
  key_path="$trust_dir/$key_file"
  if [ ! -f "$key_path" ] || [ -L "$key_path" ]; then
    fail "authority key is unavailable or unsafe: $authority"
  fi
  frozen_key="$frozen_root/trust/$key_file"
  cp "$key_path" "$frozen_key"
  chmod 0444 "$frozen_key"
  key_hash=$(sha256sum "$frozen_key" | awk '{print $1}')
  case "
$key_hashes
" in
    *"
$key_hash
"*) fail "distinct gate authorities must not share one logical trust key" ;;
  esac
  key_hashes="$key_hashes
$key_hash"
done

results_directory=${GATE_RESULTS_DIR:-artifacts/gates}
failed=0
bound_subject=
seen_idempotence=
for gate_id in $(jq -r '.gates[] | select(.requiredFor | index("production")) | .id' "$catalog"); do
  result_file="$results_directory/$gate_id.json"
  bundle_file="$results_directory/$gate_id.sigstore.json"
  if [ ! -f "$result_file" ] || [ -L "$result_file" ] || \
     [ ! -f "$bundle_file" ] || [ -L "$bundle_file" ]; then
    warn "production blocked: gate $gate_id is missing or unsafe"
    failed=1
    continue
  fi
  frozen_result="$frozen_root/gates/$gate_id.json"
  frozen_bundle="$frozen_root/gates/$gate_id.sigstore.json"
  cp "$result_file" "$frozen_result"
  cp "$bundle_file" "$frozen_bundle"
  chmod 0444 "$frozen_result" "$frozen_bundle"
  idempotence=$(python3 scripts/validate-gate-evidence.py \
    --evidence "$frozen_result" \
    --expected-gate "$gate_id" \
    --artifact-root "$artifact_root" \
    --trust-dir "$frozen_root/trust" 2>/dev/null) || {
      warn "production blocked: gate $gate_id schema, artifact, authority, time, or replay binding failed"
      failed=1
      continue
    }
  case "
$seen_idempotence
" in
    *"
$idempotence
"*) warn "production blocked: replayed GateEvidence idempotence key for $gate_id"; failed=1; continue ;;
  esac
  seen_idempotence="$seen_idempotence
$idempotence"
  authority=$(jq -r --arg gate "$gate_id" '.gateAuthorities[$gate]' "$trust_policy")
  key_file=$(jq -r --arg authority "$authority" '.authorities[$authority].keyFile' "$trust_policy")
  key_path="$frozen_root/trust/$key_file"
  if ! cosign verify-blob --offline --key "$key_path" \
    --bundle "$frozen_bundle" "$frozen_result" >/dev/null 2>&1; then
    warn "production blocked: cryptographic verification failed for gate $gate_id"
    failed=1
    continue
  fi
  subject=$(jq -r '[.repository, .sourceCommit, .imageDigest, .environment] | join("|")' "$frozen_result")
  if [ -z "$bound_subject" ]; then
    bound_subject=$subject
  elif [ "$subject" != "$bound_subject" ]; then
    warn "production blocked: gate $gate_id is bound to a different subject"
    failed=1
  fi
done

[ "$failed" -eq 0 ] || fail "production readiness is NOT PROVEN"
info "all production gates are artifact-bound, authority-mapped, replay-safe, and cryptographically verified"
