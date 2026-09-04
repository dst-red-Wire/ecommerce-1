#!/bin/sh
set -eu
# shellcheck disable=SC1091
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

require yq
require jq
require kubectl
require python3

mutable_images=$(grep -RInE 'image:[[:space:]]*[^#[:space:]]+:latest([[:space:]]|$)' \
  gitops platform security tekton .woodpecker 2>/dev/null || true)
[ -z "$mutable_images" ] || {
  printf '%s\n' "$mutable_images" >&2
  fail "mutable :latest image references are forbidden"
}

unpinned_direct_images=$(grep -RInE \
  '^[[:space:]]*image:[[:space:]]*[a-z0-9./_-]+:[^[:space:]#]+([[:space:]]|$)' \
  gitops/infrastructure/tekton-ci .woodpecker 2>/dev/null || true)
unpinned_tool_defaults=$(grep -RInE \
  '^[[:space:]]*default:[[:space:]]*[a-z0-9./_-]+:[^[:space:]#]+([[:space:]]|$)' \
  gitops/infrastructure/tekton-ci 2>/dev/null | grep -v 'https://' || true)
[ -z "$unpinned_direct_images$unpinned_tool_defaults" ] || {
  printf '%s\n%s\n' "$unpinned_direct_images" "$unpinned_tool_defaults" >&2
  fail "Tekton tooling images must use image@sha256 references"
}
# shellcheck disable=SC2016
replaceable_tooling=$(grep -RInF 'image: $(params.' \
  gitops/infrastructure/tekton-ci/tasks 2>/dev/null || true)
[ -z "$replaceable_tooling" ] || {
  printf '%s\n' "$replaceable_tooling" >&2
  fail "security tooling images must not be caller-replaceable Task parameters"
}

uppercase_ghcr=$(grep -RInE 'ghcr\.io/[^#[:space:]]*[A-Z]' \
  gitops platform security tekton 2>/dev/null | grep -v '\$' || true)
[ -z "$uppercase_ghcr" ] || {
  printf '%s\n' "$uppercase_ghcr" >&2
  fail "GHCR image paths must be lowercase"
}

for required_path in \
  contracts/supply-chain/delivery-evidence.schema.json \
  contracts/supply-chain/promotion-proof.schema.json \
  contracts/supply-chain/gate-evidence.schema.json \
  contracts/supply-chain/gate-trust-policy.json \
  contracts/supply-chain/tekton-admission-policy.json \
  contracts/supply-chain/promotion-policy.json \
  gitops/infrastructure/tekton-ci/contracts/build-and-publish.run-contract.yaml \
  gitops/infrastructure/tekton-ci/contracts/promote-image.run-contract.yaml \
  gitops/infrastructure/tekton-ci/contracts/promotion-trust-root.configmap-contract.yaml \
  gitops/infrastructure/tekton-ci/tasks/create-delivery-evidence.yaml \
  gitops/infrastructure/tekton-ci/tasks/verify-promotion-proof.yaml \
  gitops/infrastructure/tekton-ci/tasks/gitops-propose-promotion.yaml \
  platform/tekton/chains/chains-config.yaml \
  platform/tekton/chains/signing-secret.contract.yaml \
  platform/tekton/chains/registry-secret.contract.yaml; do
  [ -f "$required_path" ] || fail "missing supply-chain contract: $required_path"
done

for schema in contracts/supply-chain/*.json tests/production-readiness/gates.json; do
  jq empty "$schema" || fail "invalid JSON: $schema"
done
python3 - <<'PY'
import json
from pathlib import Path
from jsonschema import Draft202012Validator

for path in list(Path("contracts/supply-chain").glob("*.schema.json")) + [
    Path("infrastructure/hetzner/preproduction/lifecycle.schema.json")
]:
    with path.open(encoding="utf-8") as stream:
        Draft202012Validator.check_schema(json.load(stream))
PY
promotion_schema_sha=$(sha256sum contracts/supply-chain/promotion-proof.schema.json | awk '{print $1}')
delivery_schema_sha=$(sha256sum contracts/supply-chain/delivery-evidence.schema.json | awk '{print $1}')
grep -q "$promotion_schema_sha" \
  gitops/infrastructure/tekton-ci/contracts/promotion-trust-root.configmap-contract.yaml || \
  fail "promotion trust contract is not pinned to the current PromotionProof schema"
grep -q "$delivery_schema_sha" \
  gitops/infrastructure/tekton-ci/contracts/promotion-trust-root.configmap-contract.yaml || \
  fail "promotion trust contract is not pinned to the current DeliveryEvidence schema"
jq --exit-status '
  .authoritativeBranch == "main" and
  .changeMode == "pull-request-proposal" and
  .forcePushAllowed == false and
  .directTargetPushAllowed == false and
  .transitions.integration.source == "build" and
  .transitions.preproduction.source == "integration" and
  .transitions.production.source == "preproduction" and
  .idempotenceFields == ["environment", "imageRepository", "imageDigest"] and
  .optimisticLock == "expected-remote-main-sha"
' contracts/supply-chain/promotion-policy.json >/dev/null || \
  fail "invalid authoritative promotion policy"

yaml_files=$(find gitops platform/tekton/chains infrastructure/ansible \
  -type f \( -name '*.yaml' -o -name '*.yml' \) -print 2>/dev/null || true)
yaml_files="$yaml_files
.woodpecker/ci.yaml"
printf '%s\n' "$yaml_files" | while IFS= read -r manifest; do
  [ -n "$manifest" ] || continue
  yq eval-all '.' "$manifest" >/dev/null || fail "invalid YAML: $manifest"
done

promotion_pipeline=gitops/infrastructure/tekton-ci/pipelines/promote-image.yaml
proposal_task=gitops/infrastructure/tekton-ci/tasks/gitops-propose-promotion.yaml
proof_task=gitops/infrastructure/tekton-ci/tasks/verify-promotion-proof.yaml
build_pipeline=gitops/infrastructure/tekton-ci/pipelines/build-and-publish.yaml

for forbidden_param in image-digest target-branch source-revision source-environment; do
  if grep -q "\$(params\.$forbidden_param)" "$promotion_pipeline"; then
    fail "promotion pipeline still accepts free parameter $forbidden_param"
  fi
done
grep -q 'name:[[:space:]]*verify-promotion-proof' "$proof_task" || \
  fail "promotion proof verifier Task is missing"
grep -q 'command:[[:space:]]*\[/ko-app/cosign\]' "$proof_task" || \
  fail "PromotionProof verifier must execute cosign"
grep -q '^[[:space:]]*- verify-blob' "$proof_task" || \
  fail "PromotionProof must be cryptographically verified"
grep -q 'promotion-proof.json' "$proof_task" || \
  fail "fixed promotion proof path is missing"
grep -q 'promotion-proof.sigstore.json' "$proof_task" || \
  fail "fixed Sigstore bundle path is missing"
grep -q '/var/run/frozen/payload/promotion-proof.json' "$proof_task" || \
  fail "Cosign and semantic parsing must consume a frozen PromotionProof snapshot"
grep -q 'validate-promotion-proof-schema' "$proof_task" || \
  fail "PromotionProof JSON Schema is not applied by the verifier Task"
grep -q 'delivery-evidence.json' "$proof_task" || \
  fail "PromotionProof is not bound to consumed DeliveryEvidence"
grep -q "$promotion_schema_sha" "$proof_task" || \
  fail "verifier Task does not pin the current PromotionProof schema"
grep -q "$delivery_schema_sha" "$proof_task" || \
  fail "verifier Task does not pin the current DeliveryEvidence schema"
grep -q 'integration:build|preproduction:integration|production:preproduction' "$proof_task" || \
  fail "environment transitions are not closed over the allowed graph"
grep -q "printf '%s|%s|%s'" "$proof_task" || \
  fail "idempotence key is not bound to environment, repository and digest"

grep -q 'refs/heads/main' "$proposal_task" || fail "promotion does not fetch authoritative main"
grep -q 'stale main HEAD' "$proposal_task" || fail "promotion lacks optimistic locking"
grep -q 'git diff --name-only' "$proposal_task" || fail "promotion path scope is not checked"
# shellcheck disable=SC2016
grep -q 'refs/heads/$proposal_branch' "$proposal_task" || fail "promotion proposal branch is missing"
# shellcheck disable=SC2016
if grep -Eq 'HEAD:\$TARGET_BRANCH|git push[^\n]*(--force|--force-with-lease)' "$proposal_task"; then
  fail "promotion may transport arbitrary history or force push"
fi
if grep -Eq 'while .*attempt|sleep [0-9]' "$proposal_task"; then
  fail "promotion repeats a stale Git push"
fi

grep -q 'BUILT_IMAGE_DIGEST' gitops/infrastructure/tekton-ci/tasks/build-push.yaml || \
  fail "raw build digest must not use a Chains approval type hint"
# shellcheck disable=SC2016
taskrun_type_hints=$(yq eval-all -r '
  select(.kind == "Task") as $task |
  $task.spec.results[]? |
  select(.name == "IMAGE_URL" or .name == "IMAGE_DIGEST") |
  $task.metadata.name + "/" + .name
' gitops/infrastructure/tekton-ci/tasks/*.yaml)
if [ -n "$taskrun_type_hints" ]; then
  fail "TaskRun results must not trigger generic Chains OCI signing"
fi
grep -q 'value:.*create-evidence.results.APPROVED_IMAGE_DIGEST' "$build_pipeline" || \
  fail "Pipeline image digest is not gated by final evidence binding"
grep -q 'artifacts.taskrun.storage:[[:space:]]*""' platform/tekton/chains/chains-config.yaml || \
  fail "TaskRun provenance storage must be disabled to avoid premature approval"
grep -q 'artifacts.pipelinerun.enable-deep-inspection:[[:space:]]*"true"' \
  platform/tekton/chains/chains-config.yaml || fail "Chains PipelineRun deep inspection is required"
grep -q 'artifacts.oci.storage:[[:space:]]*""' platform/tekton/chains/chains-config.yaml || \
  fail "generic TaskRun OCI result signing must remain disabled"

push_service_accounts=$(yq eval-all -r '
  select(.kind == "ServiceAccount") |
  select(.secrets[]?.name == "ghcr-push") |
  .metadata.name
' gitops/infrastructure/tekton-ci/serviceaccounts.yaml)
[ "$push_service_accounts" = tekton-image-push ] || \
  fail "ghcr-push must be attached only to tekton-image-push"
token_enabled_service_accounts=$(yq eval-all -r '
  select(.kind == "ServiceAccount") |
  select(.automountServiceAccountToken != false) |
  .metadata.name
' gitops/infrastructure/tekton-ci/serviceaccounts.yaml)
[ -z "$token_enabled_service_accounts" ] || \
  fail "CI ServiceAccounts must disable Kubernetes token automount"
grep -q 'tekton-source-read' gitops/infrastructure/tekton-ci/contracts/build-and-publish.run-contract.yaml
grep -q 'tekton-image-push' gitops/infrastructure/tekton-ci/contracts/build-and-publish.run-contract.yaml
grep -q 'tekton-git-promotion' gitops/infrastructure/tekton-ci/contracts/promote-image.run-contract.yaml
build_identity_count=$(grep -c 'serviceAccountName:' \
  gitops/infrastructure/tekton-ci/contracts/build-and-publish.run-contract.yaml)
[ "$build_identity_count" -eq 7 ] || fail "build Run contract must assign all seven task identities"
promotion_identity_count=$(grep -c 'serviceAccountName:' \
  gitops/infrastructure/tekton-ci/contracts/promote-image.run-contract.yaml)
[ "$promotion_identity_count" -eq 2 ] || fail "promotion Run contract must assign both task identities"
grep -q 'name:[[:space:]]*promotion-trust-root' \
  gitops/infrastructure/tekton-ci/contracts/promote-image.run-contract.yaml || \
  fail "promotion trust root binding is not fixed"
grep -q 'secretName:[[:space:]]*github-git-write' \
  gitops/infrastructure/policies/kyverno/tekton-run-contracts.yaml || \
  fail "promotion Git credential binding is not fixed"
grep -q '../../infrastructure/policies/kyverno' gitops/clusters/integration/kustomization.yaml || \
  fail "integration overlay does not include the Tekton admission policy"

grep -q 'ecommerce.dev/workload:[[:space:]]*ci-build' \
  gitops/infrastructure/tekton-ci/contracts/build-and-publish.run-contract.yaml || \
  fail "BuildKit lacks a dedicated CI node selector"
grep -q 'key:[[:space:]]*ecommerce.dev/ci-build' \
  gitops/infrastructure/tekton-ci/contracts/build-and-publish.run-contract.yaml || \
  fail "BuildKit lacks a dedicated CI taint toleration"
grep -q 'computeResources:' gitops/infrastructure/tekton-ci/tasks/build-push.yaml || \
  fail "BuildKit resources are unbounded"
[ -f gitops/infrastructure/tekton-ci/networkpolicies.yaml ] || fail "CI NetworkPolicy is missing"
[ -f gitops/infrastructure/tekton-ci/rbac.yaml ] || fail "CI RBAC is missing"
[ -f gitops/infrastructure/policies/kyverno/tekton-run-contracts.yaml ] || \
  fail "future Kyverno run enforcement policy is missing"

for environment in integration preproduction production; do
  sync=gitops/clusters/$environment/flux-system/gotk-sync.yaml
  [ "$(yq -r 'select(.kind == "GitRepository") | .spec.ref.branch' "$sync")" = main ] || \
    fail "$environment Flux source must track authoritative main"
  kubectl kustomize "gitops/clusters/$environment" >/dev/null || \
    fail "$environment Kustomize render failed"
done

detached_images=$(grep -RInE '^[[:space:]]*images:[[:space:]]*\[\]' gitops 2>/dev/null || true)
[ -z "$detached_images" ] || fail "detached images: [] placeholders are forbidden"
mutable_kustomize=$(grep -RInE '^[[:space:]]*newTag:' gitops 2>/dev/null || true)
[ -z "$mutable_kustomize" ] || fail "Kustomize overlays must promote digests, not tags"

./scripts/validate-gitops-images.sh
./scripts/test-gitops-image-binding.sh
./scripts/test-production-gate-evidence.sh
python3 scripts/validate-tekton-contracts.py --self-test
./scripts/test-source-immutability.sh
python3 scripts/validate-tekton-admission.py \
  --fixture-suite tests/supply-chain/admission-cases.json
./scripts/test-promotion-proof.sh
./scripts/test-git-promotion.sh

info "supply-chain contracts and static adversarial tests passed; runtime cryptographic evidence remains NOT PROVEN"
