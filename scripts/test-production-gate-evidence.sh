#!/bin/sh
set -eu

# shellcheck disable=SC1091
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT HUP INT TERM
mkdir -p "$fixture/trust"
printf '%s\n' 'synthetic public key bytes for contract tests only' >"$fixture/trust/ci-gates.pub"

python3 - "$fixture" <<'PY'
import datetime as dt
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
artifact = root / "lint-report.json"
artifact.write_text('{"result":"synthetic-pass"}\n', encoding="utf-8")
artifact_sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
key_sha = hashlib.sha256((root / "trust/ci-gates.pub").read_bytes()).hexdigest()
now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
expires = now + dt.timedelta(hours=1)
repository = "https://github.com/dst-red-Wire/ecommerce-1.git"
commit = "a" * 40
digest = "sha256:" + "b" * 64
parts = ["lint", repository, commit, digest, "production", artifact_sha]
evidence = {
    "schemaVersion": "ecommerce.dev/gate-evidence/v1",
    "gateId": "lint",
    "status": "PASS",
    "repository": repository,
    "sourceCommit": commit,
    "imageDigest": digest,
    "environment": "production",
    "issuedAt": now.isoformat().replace("+00:00", "Z"),
    "expiresAt": expires.isoformat().replace("+00:00", "Z"),
    "expiresAtEpoch": int(expires.timestamp()),
    "idempotenceKey": "sha256:" + hashlib.sha256("|".join(parts).encode()).hexdigest(),
    "issuer": {"id": "tekton-ci-attestor", "type": "tekton"},
    "evidence": {"artifact": "lint-report.json", "sha256": artifact_sha},
    "verification": {"mechanism": "cosign-key", "keyId": "sha256:" + key_sha},
}
(root / "lint.json").write_text(json.dumps(evidence), encoding="utf-8")
PY

PRODUCTION_GATE_MODE=validate-file \
  GATE_RESULT_FILE="$fixture/lint.json" \
  GATE_ID=lint \
  GATE_ARTIFACT_ROOT="$fixture" \
  ./scripts/ci-production-readiness.sh >/dev/null

python3 scripts/validate-gate-evidence.py \
  --evidence "$fixture/lint.json" \
  --expected-gate lint \
  --artifact-root "$fixture" \
  --trust-dir "$fixture/trust" >/dev/null

cp "$fixture/lint.json" "$fixture/original.json"
printf '%s\n' 'artifact replaced after evidence issuance' >"$fixture/lint-report.json"
if PRODUCTION_GATE_MODE=validate-file GATE_RESULT_FILE="$fixture/lint.json" GATE_ID=lint \
  GATE_ARTIFACT_ROOT="$fixture" ./scripts/ci-production-readiness.sh >/dev/null 2>&1; then
  fail "GateEvidence with a false artifact hash was accepted"
fi

printf '%s\n' '{"result":"synthetic-pass"}' >"$fixture/lint-report.json"
jq '.issuer.id = "self-declared"' "$fixture/original.json" >"$fixture/lint.json"
if PRODUCTION_GATE_MODE=validate-file GATE_RESULT_FILE="$fixture/lint.json" GATE_ID=lint \
  GATE_ARTIFACT_ROOT="$fixture" ./scripts/ci-production-readiness.sh >/dev/null 2>&1; then
  fail "self-declared GateEvidence issuer was accepted"
fi

jq '.verification.keyId = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"' \
  "$fixture/original.json" >"$fixture/lint.json"
if python3 scripts/validate-gate-evidence.py --evidence "$fixture/lint.json" --expected-gate lint \
  --artifact-root "$fixture" --trust-dir "$fixture/trust" >/dev/null 2>&1; then
  fail "GateEvidence keyId not matching the mapped public key was accepted"
fi

printf '%s\n' '{"status":"pass"}' >"$fixture/forged.json"
if PRODUCTION_GATE_MODE=validate-file GATE_RESULT_FILE="$fixture/forged.json" GATE_ID=lint \
  GATE_ARTIFACT_ROOT="$fixture" ./scripts/ci-production-readiness.sh >/dev/null 2>&1; then
  fail "forgeable status-only production gate was incorrectly accepted"
fi

info "GateEvidence schema, artifact, authority, key identity, and forgery tests passed"
