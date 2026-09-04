#!/bin/sh
set -eu
# shellcheck source=scripts/lib.sh
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

require jq
: "${OPA_BIN:=opa}"
command -v "$OPA_BIN" >/dev/null 2>&1 || fail "OPA executable not found: $OPA_BIN"

policy_data=governance/exceptions.yaml
"$OPA_BIN" check --strict security/opa
"$OPA_BIN" test security/opa "$policy_data"

evaluate_count() {
  package=$1
  fixture=$2
  "$OPA_BIN" eval --format json \
    --data security/opa \
    --data "$policy_data" \
    --input "$fixture" \
    "data.ecommerce.$package.deny" |
    jq -er '.result[0].expressions[0].value | length'
}

expect_pass() {
  package=$1
  fixture=$2
  count=$(evaluate_count "$package" "$fixture")
  [ "$count" -eq 0 ] || fail "policy PASS fixture was denied: $fixture ($count violations)"
}

expect_fail() {
  package=$1
  fixture=$2
  count=$(evaluate_count "$package" "$fixture")
  [ "$count" -gt 0 ] || fail "policy FAIL fixture was accepted: $fixture"
}

expect_pass terraform tests/governance/fixtures/terraform-pass.json
expect_fail terraform tests/governance/fixtures/terraform-fail-public-db.json
expect_fail terraform tests/governance/fixtures/terraform-fail-public-ssh.json
expect_fail terraform tests/governance/fixtures/terraform-fail-protected-delete.json
expect_pass kubernetes tests/governance/fixtures/kubernetes-pass.json
expect_fail kubernetes tests/governance/fixtures/kubernetes-fail-latest.json
expect_fail kubernetes tests/governance/fixtures/kubernetes-fail-tagged.json
expect_fail kubernetes tests/governance/fixtures/kubernetes-fail-privileged.json

info "OPA/Rego unit tests and PASS/FAIL fixtures passed"
