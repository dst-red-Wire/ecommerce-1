#!/bin/sh
set -eu

# Runtime harness only: it is intentionally not invoked by static CI.
# shellcheck disable=SC1091
. "$(dirname "$0")/lib.sh"
# shellcheck disable=SC1091
. "$(dirname "$0")/lib-terraform-pg.sh"
cd "$(repo_root)"

require grep
require jq
require mkfifo
require openssl
require psql
require realpath
require sha256sum
require terraform

: "${TERRAFORM_PG_LOCKING_EVIDENCE:?TERRAFORM_PG_LOCKING_EVIDENCE is required}"
repository=$(pwd -P)
terraform_pg_require_runtime

terraform_version=$(terraform version -json | jq -r '.terraform_version')
[ "$terraform_version" = "1.15.5" ] || fail "locking proof requires Terraform 1.15.5"

evidence=$(terraform_pg_external_path "$TERRAFORM_PG_LOCKING_EVIDENCE" "locking evidence")
[ ! -e "$evidence" ] || fail "locking evidence already exists; preserve it and choose a new path"
evidence_directory=$(dirname "$evidence")
mkdir -p "$evidence_directory"
chmod 0700 "$evidence_directory"
umask 077

probe=infrastructure/hetzner/bootstrap/terraform-state/lock-runtime-test
state_base=${XDG_STATE_HOME:-"$HOME/.local/state"}
probe_data_directory=$state_base/ecommerce-1/terraform/pg-lock-runtime-test/terraform-data
probe_data_directory=$(realpath -m "$probe_data_directory")
case "$probe_data_directory" in
  "$repository" | "$repository"/* | /mnt/c/Users/*/OneDrive/*)
    fail "probe Terraform data must remain outside the repository and OneDrive"
    ;;
esac
mkdir -p "$probe_data_directory"
chmod 0700 "$probe_data_directory"
export TF_DATA_DIR="$probe_data_directory"

health_result=$(terraform_pg_psql --tuples-only --no-align --command="
  SELECT (
    ssl
    AND current_user = 'terraform_backend'
    AND current_database() = 'terraform_backend'
    AND to_regclass('terraform_lock_probe.states') IS NOT NULL
    AND has_table_privilege(current_user, 'terraform_lock_probe.states', 'SELECT')
    AND has_table_privilege(current_user, 'terraform_lock_probe.states', 'INSERT')
    AND has_table_privilege(current_user, 'terraform_lock_probe.states', 'UPDATE')
    AND has_table_privilege(current_user, 'terraform_lock_probe.states', 'DELETE')
  )::text || '|' || pg_backend_pid()::text
  FROM pg_stat_ssl WHERE pid = pg_backend_pid();
") || fail "PostgreSQL TLS/auth/schema health preflight failed"
case "$health_result" in
  t\|[0-9]*) health_backend_pid=${health_result#*|} ;;
  *) fail "PostgreSQL TLS/auth/schema health preflight returned an invalid result" ;;
esac

# Prove both trust-anchor and hostname verification negatively immediately
# after the positive verified connection. No state query or payload is used.
tls_test_directory=$(mktemp -d)
wrong_ca_key=$tls_test_directory/wrong-ca.key
wrong_ca_certificate=$tls_test_directory/wrong-ca.crt
wrong_ca_error=$tls_test_directory/wrong-ca.error
wrong_hostname_error=$tls_test_directory/wrong-hostname.error
cleanup_tls_test() {
  rm -f "$wrong_ca_key" "$wrong_ca_certificate" "$wrong_ca_error" "$wrong_hostname_error"
  rmdir "$tls_test_directory" 2>/dev/null || true
}
trap cleanup_tls_test EXIT HUP INT TERM
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
  -subj /CN=terraform-state-negative-test \
  -keyout "$wrong_ca_key" \
  -out "$wrong_ca_certificate" >/dev/null 2>&1 ||
  fail "unable to create the ephemeral wrong-CA TLS test fixture"
set +e
PGSSLROOTCERT="$wrong_ca_certificate" terraform_pg_psql \
  --command='SELECT 1;' >/dev/null 2>"$wrong_ca_error"
wrong_ca_status=$?
set -e
[ "$wrong_ca_status" -ne 0 ] || fail "PostgreSQL TLS accepted an unrelated certificate authority"

wrong_hostname_connection="host=terraform-state.invalid hostaddr=$TERRAFORM_PG_TUNNEL_HOST port=$TERRAFORM_PG_TUNNEL_PORT dbname=terraform_backend user=terraform_backend sslmode=verify-full"
set +e
psql "$wrong_hostname_connection" --no-psqlrc --set=ON_ERROR_STOP=1 \
  --command='SELECT 1;' >/dev/null 2>"$wrong_hostname_error"
wrong_hostname_status=$?
set -e
[ "$wrong_hostname_status" -ne 0 ] || fail "PostgreSQL TLS accepted a hostname absent from the certificate SAN"

trap - EXIT HUP INT TERM
cleanup_tls_test

terraform -chdir="$probe" init -reconfigure -input=false >/dev/null
workspace=$(terraform -chdir="$probe" workspace show)
[ "$workspace" = "default" ] || fail "the locking probe must use only the default workspace"

# A successful plan materializes the default probe row if it does not yet
# exist. This is probe-only state and never the management state.
terraform -chdir="$probe" plan -input=false -lock-timeout=0s -no-color >/dev/null
state_row_id=$(terraform_pg_psql --tuples-only --no-align \
  --command="SELECT id FROM terraform_lock_probe.states WHERE name='default';") ||
  fail "cannot read the default probe state row"
case "$state_row_id" in
  '' | *[!0-9]*) fail "the default probe state row has no valid numeric id" ;;
esac

evidence_name=$(basename "$evidence")
evidence_prefix=${evidence_name%.json}
holder_log=$evidence_directory/$evidence_prefix.holder.log
contender_one_log=$evidence_directory/$evidence_prefix.contender-1.log
contender_two_log=$evidence_directory/$evidence_prefix.contender-2.log
post_release_log=$evidence_directory/$evidence_prefix.post-release.log
for artifact in "$holder_log" "$contender_one_log" "$contender_two_log" "$post_release_log"; do
  [ ! -e "$artifact" ] || fail "locking artifact already exists; choose a new evidence path"
done

work_directory=$(mktemp -d)
fifo=$work_directory/holder.stdin
holder_pid=
holder_fd_open=false
holder_status=

cleanup() {
  if [ -n "$holder_pid" ] && kill -0 "$holder_pid" 2>/dev/null; then
    if [ "$holder_fd_open" = true ]; then
      printf 'no\n' >&3 2>/dev/null || true
      exec 3>&- 2>/dev/null || true
      holder_fd_open=false
    fi
    kill "$holder_pid" 2>/dev/null || true
    wait "$holder_pid" 2>/dev/null || true
  elif [ "$holder_fd_open" = true ]; then
    exec 3>&- 2>/dev/null || true
    holder_fd_open=false
  fi
  rm -f "$fifo"
  rmdir "$work_directory" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

observe_lock() {
  terraform_pg_psql --tuples-only --no-align --command="
    SELECT count(*)::text || '|' || coalesce(min(pid), 0)::text
    FROM pg_locks
    WHERE locktype = 'advisory'
      AND granted
      AND classid = 0
      AND objid = $state_row_id::oid
      AND objsubid = 1;
  "
}

run_contender() {
  contender_log=$1
  set +e
  terraform -chdir="$probe" plan \
    -no-color \
    -input=false \
    -lock-timeout=0s >"$contender_log" 2>&1 &
  contender_process_pid=$!
  wait "$contender_process_pid"
  contender_status=$?
  set -e
}

cancel_holder() {
  if [ -n "$holder_pid" ]; then
    if [ "$holder_fd_open" = true ]; then
      printf 'no\n' >&3
      exec 3>&-
      holder_fd_open=false
    fi
    set +e
    wait "$holder_pid"
    holder_status=$?
    set -e
    holder_pid=
  fi
}

initial_lock=$(observe_lock) || fail "cannot inspect PostgreSQL advisory locks"
[ "$initial_lock" = "0|0" ] || fail "the probe advisory lock is already held; investigate before retrying"

mkfifo "$fifo"
terraform -chdir="$probe" apply \
  -no-color \
  -input=true \
  -lock-timeout=0s <"$fifo" >"$holder_log" 2>&1 &
holder_pid=$!
holder_process_pid=$holder_pid
exec 3>"$fifo"
holder_fd_open=true

prompt_seen=false
attempt=0
while [ "$attempt" -lt 60 ]; do
  if grep -q 'Enter a value:' "$holder_log" 2>/dev/null; then
    prompt_seen=true
    break
  fi
  kill -0 "$holder_pid" 2>/dev/null || fail "lock holder exited before the confirmation prompt"
  attempt=$((attempt + 1))
  sleep 1
done
[ "$prompt_seen" = true ] || fail "lock holder did not reach the confirmation prompt within 60 seconds"

holder_postgresql_pid=
attempt=0
while [ "$attempt" -lt 15 ]; do
  kill -0 "$holder_pid" 2>/dev/null || fail "lock holder exited before direct advisory-lock observation"
  lock_observation=$(observe_lock) || fail "direct advisory-lock observation failed"
  case "$lock_observation" in
    1\|[1-9][0-9]*)
      holder_postgresql_pid=${lock_observation#*|}
      break
      ;;
    0\|0) ;;
    *) fail "unexpected advisory-lock observation: lock count is not exactly one" ;;
  esac
  attempt=$((attempt + 1))
  sleep 1
done
[ -n "$holder_postgresql_pid" ] || fail "holder advisory lock was not observed within 15 seconds"
[ "$holder_postgresql_pid" != "$health_backend_pid" ] ||
  fail "health preflight and lock holder unexpectedly reused one PostgreSQL session"

run_contender "$contender_one_log"
first_status=$contender_status
first_process_pid=$contender_process_pid
[ "$first_status" -ne 0 ] || fail "first contender acquired a live PostgreSQL advisory lock"
grep -q 'Error acquiring the state lock' "$contender_one_log" ||
  fail "first contender failed for a reason unrelated to state locking"
grep -q 'Workspace is already locked: default' "$contender_one_log" ||
  fail "first contender did not report the PostgreSQL workspace advisory lock"
[ "$(observe_lock)" = "1|$holder_postgresql_pid" ] ||
  fail "holder advisory lock changed after the first contender"
kill -0 "$holder_pid" 2>/dev/null || fail "holder exited during the first contention test"

run_contender "$contender_two_log"
second_status=$contender_status
second_process_pid=$contender_process_pid
[ "$second_status" -ne 0 ] || fail "second contender acquired a live PostgreSQL advisory lock"
grep -q 'Error acquiring the state lock' "$contender_two_log" ||
  fail "second contender failed for a reason unrelated to state locking"
grep -q 'Workspace is already locked: default' "$contender_two_log" ||
  fail "second contender did not report the PostgreSQL workspace advisory lock"
[ "$(observe_lock)" = "1|$holder_postgresql_pid" ] ||
  fail "holder advisory lock changed after the second contender"
kill -0 "$holder_pid" 2>/dev/null || fail "holder exited during the second contention test"

if [ "$holder_process_pid" = "$first_process_pid" ] || \
  [ "$holder_process_pid" = "$second_process_pid" ] || \
  [ "$first_process_pid" = "$second_process_pid" ]; then
  fail "locking proof did not use three distinct Terraform client processes"
fi

cancel_holder
[ "$holder_status" -eq 1 ] || fail "holder cancellation returned an unexpected exit code"
grep -q 'Apply cancelled' "$holder_log" || fail "holder cancellation was not confirmed"
if grep -q 'Error releasing the state lock' "$holder_log"; then
  fail "holder reported an advisory-lock release error"
fi
[ "$(observe_lock)" = "0|0" ] || fail "advisory lock remained held after clean cancellation"

run_contender "$post_release_log"
post_release_status=$contender_status
[ "$post_release_status" -eq 0 ] || fail "contender did not succeed after holder release"
[ "$(observe_lock)" = "0|0" ] || fail "post-release plan left an advisory lock held"

backend_hash=$(sha256sum infrastructure/hetzner/management/backend.tf | awk '{print $1}')
contract_hash=$(sha256sum infrastructure/hetzner/management/backend.contract.json | awk '{print $1}')
harness_hash=$(sha256sum scripts/test-terraform-pg-locking.sh | awk '{print $1}')
observed_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
jq -n \
  --arg observed "$observed_at" \
  --arg backend_hash "$backend_hash" \
  --arg contract_hash "$contract_hash" \
  --arg harness_hash "$harness_hash" \
  --argjson row_id "$state_row_id" \
  --argjson health_pid "$health_backend_pid" \
  --argjson holder_pg_pid "$holder_postgresql_pid" \
  --argjson holder_process "$holder_process_pid" \
  --argjson first_process "$first_process_pid" \
  --argjson second_process "$second_process_pid" \
  --argjson first_exit "$first_status" \
  --argjson second_exit "$second_status" \
  --argjson holder_exit "$holder_status" \
  --argjson post_exit "$post_release_status" '
    {
      version: 1,
      status: "PROVEN",
      terraformVersion: "1.15.5",
      backendType: "pg",
      database: "terraform_backend",
      schema: "terraform_lock_probe",
      workspace: "default",
      observedAt: $observed,
      managementBackendSha256: $backend_hash,
      managementContractSha256: $contract_hash,
      harnessSha256: $harness_hash,
      tlsVerifyFullProven: true,
      tlsWrongCaRejected: true,
      tlsWrongHostnameRejected: true,
      authenticationProven: true,
      schemaPermissionsProven: true,
      advisoryLockObservedDirectly: true,
      stateRowId: $row_id,
      healthPostgresqlPid: $health_pid,
      holderPostgresqlPid: $holder_pg_pid,
      holderTerraformPid: $holder_process,
      firstContenderTerraformPid: $first_process,
      secondContenderTerraformPid: $second_process,
      distinctClientProcesses: true,
      firstContenderExitCode: $first_exit,
      secondContenderExitCode: $second_exit,
      contendersRejectedForLocking: true,
      holderExitCode: $holder_exit,
      holderCancelledCleanly: true,
      advisoryLockAbsentAfterRelease: true,
      postReleaseExitCode: $post_exit,
      postReleaseSucceeded: true
    }
  ' >"$evidence"
chmod 0600 "$evidence" "$holder_log" "$contender_one_log" "$contender_two_log" "$post_release_log"

trap - EXIT HUP INT TERM
cleanup
info "PostgreSQL advisory locking runtime PROVEN; evidence written outside the repository"
