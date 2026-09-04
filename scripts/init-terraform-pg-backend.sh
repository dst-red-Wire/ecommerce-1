#!/bin/sh
set -eu

# This gate initializes only an approved empty management pg backend. It never
# performs state migration; migration requires a separate, explicit procedure.
# shellcheck disable=SC1091
. "$(dirname "$0")/lib.sh"
# shellcheck disable=SC1091
. "$(dirname "$0")/lib-terraform-pg.sh"
cd "$(repo_root)"

require jq
require psql
require realpath
require sha256sum
require terraform

: "${TERRAFORM_PG_LOCKING_EVIDENCE:?TERRAFORM_PG_LOCKING_EVIDENCE is required}"
: "${MANAGEMENT_STATE_INSPECTION_EVIDENCE:?MANAGEMENT_STATE_INSPECTION_EVIDENCE is required}"
: "${MANAGEMENT_STATE_ACTIVATION_DECISION:?MANAGEMENT_STATE_ACTIVATION_DECISION is required}"
repository=$(pwd -P)
terraform_pg_require_runtime

locking_evidence=$(terraform_pg_external_path "$TERRAFORM_PG_LOCKING_EVIDENCE" "locking evidence")
inspection_evidence=$(terraform_pg_external_path "$MANAGEMENT_STATE_INSPECTION_EVIDENCE" "state inspection evidence")
activation_decision=$(terraform_pg_external_path "$MANAGEMENT_STATE_ACTIVATION_DECISION" "state activation decision")
for gate_file in "$locking_evidence" "$inspection_evidence" "$activation_decision"; do
  [ -f "$gate_file" ] || fail "required activation gate file is unavailable"
  [ ! -L "$gate_file" ] || fail "activation gate files must not be symbolic links"
done

terraform_version=$(terraform version -json | jq -r '.terraform_version')
[ "$terraform_version" = "1.15.5" ] || fail "management activation requires Terraform 1.15.5"
backend_hash=$(sha256sum infrastructure/hetzner/management/backend.tf | awk '{print $1}')
contract_hash=$(sha256sum infrastructure/hetzner/management/backend.contract.json | awk '{print $1}')

jq --exit-status \
  --arg backend_hash "$backend_hash" \
  --arg contract_hash "$contract_hash" '
    .version == 1 and
    .status == "PROVEN" and
    .terraformVersion == "1.15.5" and
    .backendType == "pg" and
    .database == "terraform_backend" and
    .schema == "terraform_lock_probe" and
    .workspace == "default" and
    .managementBackendSha256 == $backend_hash and
    .managementContractSha256 == $contract_hash and
    .tlsVerifyFullProven == true and
    .tlsWrongCaRejected == true and
    .tlsWrongHostnameRejected == true and
    .authenticationProven == true and
    .schemaPermissionsProven == true and
    .advisoryLockObservedDirectly == true and
    .distinctClientProcesses == true and
    .contendersRejectedForLocking == true and
    .holderCancelledCleanly == true and
    .advisoryLockAbsentAfterRelease == true and
    .postReleaseSucceeded == true and
    ((.observedAt | fromdateiso8601) as $observed |
      $observed <= now and (now - $observed) <= 86400)
  ' "$locking_evidence" >/dev/null ||
  fail "PostgreSQL locking/TLS runtime evidence is missing, stale or incompatible"

jq --exit-status '
    .version == 2 and
    .status == "INSPECTED" and
    .bucket == "ecommerce-management-tfstate-20260820-70b94831" and
    .legacyObjectKey == "ecommerce/management/terraform.tfstate" and
    .legacyVersionHistoryCheckedAuthenticated == true and
    .legacyVersionHistory.verdict == "ZERO_HISTORY" and
    .legacyVersionHistory.apiComplete == true and
    .legacyVersionHistory.totalHistoryEntryCount == 0 and
    .localCandidatesChecked == true and
    (.sources | type == "array" and length == 3) and
    ((.observedAt | fromdateiso8601) as $observed |
      $observed <= now and (now - $observed) <= 86400)
  ' "$inspection_evidence" >/dev/null ||
  fail "management state source inspection is missing, stale or incomplete"
inspection_hash=$(sha256sum "$inspection_evidence" | awk '{print $1}')
inspection_observed_at=$(jq -r '.observedAt' "$inspection_evidence")
all_sources_absent=$(jq -r '.allSourcesAbsent' "$inspection_evidence")

decision=$(jq -er '.decision | select(type == "string")' "$activation_decision") ||
  fail "state activation decision is unavailable"
case "$decision" in
  initialize-empty) ;;
  migrate-after-separate-human-approval)
    fail "state migration is intentionally unsupported by this initializer; stop for a separate human gate"
    ;;
  *) fail "unsupported state activation decision" ;;
esac
[ "$all_sources_absent" = true ] ||
  fail "one or more management state sources exist; empty initialization is forbidden"

jq --exit-status \
  --arg inspection_hash "$inspection_hash" \
  --arg inspection_observed "$inspection_observed_at" '
    .version == 1 and
    .status == "HUMAN_APPROVED" and
    .decision == "initialize-empty" and
    .inspectionEvidenceSha256 == $inspection_hash and
    .inspectionObservedAt == $inspection_observed and
    .allSourcesAbsent == true and
    .migrationApproved == false and
    .postgresqlTargetExpectedEmpty == true and
    .postgresqlWriterFreezeConfirmed == true and
    (.approvedBy | type == "array" and length >= 1 and all(.[]; type == "string" and length > 0)) and
    (.rationale | type == "string" and length > 0) and
    ((.approvedAt | fromdateiso8601) as $approved |
      $approved <= now and (now - $approved) <= 86400)
  ' "$activation_decision" >/dev/null ||
  fail "empty management backend initialization lacks a valid human approval"

management_health=$(terraform_pg_psql --tuples-only --no-align --command="
  SELECT ssl
    AND current_user = 'terraform_backend'
    AND current_database() = 'terraform_backend'
    AND to_regclass('terraform_management.states') IS NOT NULL
    AND has_table_privilege(current_user, 'terraform_management.states', 'SELECT')
    AND has_table_privilege(current_user, 'terraform_management.states', 'INSERT')
    AND has_table_privilege(current_user, 'terraform_management.states', 'UPDATE')
    AND has_table_privilege(current_user, 'terraform_management.states', 'DELETE')
  FROM pg_stat_ssl WHERE pid = pg_backend_pid();
") || fail "management schema TLS/auth preflight failed"
[ "$management_health" = t ] || fail "management schema TLS/auth preflight returned an invalid result"

observe_management_target() {
  observation_phase=$1
  terraform_pg_psql --tuples-only --no-align --command="
    SELECT json_build_object(
      'database', current_database(),
      'user', current_user,
      'schema', 'terraform_management',
      'table', 'states',
      'schemaExists', to_regnamespace('terraform_management') IS NOT NULL,
      'tableExists', to_regclass('terraform_management.states') IS NOT NULL,
      'tableColumnsExact', (
        SELECT count(*) = 3 AND bool_and(
          (column_name = 'id' AND data_type = 'bigint' AND is_nullable = 'NO') OR
          (column_name = 'name' AND data_type = 'text' AND is_nullable = 'YES') OR
          (column_name = 'data' AND data_type = 'text' AND is_nullable = 'YES')
        )
        FROM information_schema.columns
        WHERE table_schema = 'terraform_management' AND table_name = 'states'
      ),
      'uniqueWorkspaceIndex', EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE schemaname = 'terraform_management'
          AND tablename = 'states'
          AND indexname = 'states_by_name'
          AND indexdef LIKE 'CREATE UNIQUE INDEX%ON terraform_management.states USING btree (name)'
      ),
      'rowCount', (SELECT count(*) FROM terraform_management.states),
      'workspaceNames', coalesce(
        (SELECT json_agg(name ORDER BY name) FROM terraform_management.states),
        '[]'::json
      ),
      'emptyStateRowCount', CASE WHEN '$observation_phase' = 'post-init' THEN (
        SELECT count(*) FROM terraform_management.states
        WHERE data IS NOT NULL
          AND jsonb_typeof(data::jsonb) = 'object'
          AND data::jsonb ? 'version'
          AND data::jsonb ? 'serial'
          AND data::jsonb ? 'lineage'
          AND jsonb_typeof(data::jsonb -> 'resources') = 'array'
          AND jsonb_array_length(data::jsonb -> 'resources') = 0
          AND coalesce(data::jsonb -> 'outputs', '{}'::jsonb) = '{}'::jsonb
      ) ELSE 0 END
    )::text;
  "
}

target_observation_file=$(mktemp)
cleanup_target_observation() {
  rm -f "$target_observation_file"
}
trap cleanup_target_observation EXIT HUP INT TERM
observe_management_target preflight >"$target_observation_file" ||
  fail "management PostgreSQL target inspection failed; verdict UNKNOWN"
target_preflight=$(python3 scripts/evaluate-terraform-pg-target.py \
  --input "$target_observation_file" \
  --phase preflight)
target_preflight_verdict=$(printf '%s' "$target_preflight" | jq -r '.verdict')
target_preflight_rows=$(printf '%s' "$target_preflight" | jq -r '.rowCount')
target_preflight_names=$(printf '%s' "$target_preflight" | jq -c '.workspaceNames')
info "management PostgreSQL target preflight: rowCount=$target_preflight_rows workspaceNames=$target_preflight_names verdict=$target_preflight_verdict"
[ "$target_preflight_verdict" = EMPTY ] ||
  fail "management PostgreSQL target is NON_EMPTY or UNKNOWN; initialize-empty is forbidden"

state_base=${XDG_STATE_HOME:-"$HOME/.local/state"}
terraform_data_directory=$state_base/ecommerce-1/terraform/management-pg/terraform-data
terraform_data_directory=$(realpath -m "$terraform_data_directory")
case "$terraform_data_directory" in
  "$repository" | "$repository"/* | /mnt/c/Users/*/OneDrive/*)
    fail "management Terraform data must remain outside the repository and OneDrive"
    ;;
esac
mkdir -p "$terraform_data_directory"
chmod 0700 "$terraform_data_directory"
export TF_DATA_DIR="$terraform_data_directory"

terraform -chdir=infrastructure/hetzner/management init -reconfigure -input=false
workspace=$(terraform -chdir=infrastructure/hetzner/management workspace show)
[ "$workspace" = "default" ] || fail "management must use only the default Terraform workspace"

observe_management_target post-init >"$target_observation_file" ||
  fail "post-init PostgreSQL target validation failed; verdict UNKNOWN"
target_post_init=$(python3 scripts/evaluate-terraform-pg-target.py \
  --input "$target_observation_file" \
  --phase post-init)
target_post_init_verdict=$(printf '%s' "$target_post_init" | jq -r '.verdict')
target_post_init_rows=$(printf '%s' "$target_post_init" | jq -r '.rowCount')
target_post_init_names=$(printf '%s' "$target_post_init" | jq -c '.workspaceNames')
info "management PostgreSQL target post-init: rowCount=$target_post_init_rows workspaceNames=$target_post_init_names verdict=$target_post_init_verdict"
[ "$target_post_init_verdict" = EMPTY ] ||
  fail "post-init PostgreSQL target is not the expected empty default state"

trap - EXIT HUP INT TERM
cleanup_target_observation

info "management pg backend initialized empty after runtime proof and human state-source approval; no migration was performed"
