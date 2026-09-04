#!/bin/sh
set -eu

# shellcheck disable=SC1091
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

require awk
require curl
require grep
require jq
require mkfifo
require realpath
require sha256sum
require terraform

: "${BUCKET_NAME:?BUCKET_NAME is required}"
: "${MINIO_USER:?MINIO_USER is required}"
: "${MINIO_PASSWORD:?MINIO_PASSWORD is required}"
: "${HETZNER_MANAGEMENT_PRINCIPAL_ARN:?HETZNER_MANAGEMENT_PRINCIPAL_ARN is required}"
: "${HETZNER_S3_LOCKING_EVIDENCE:?HETZNER_S3_LOCKING_EVIDENCE is required}"

unset TF_LOG TF_LOG_CORE TF_LOG_PROVIDER TF_LOG_PATH MINIO_DEBUG
require_management_s3_identity

export AWS_ACCESS_KEY_ID="$MINIO_USER"
export AWS_SECRET_ACCESS_KEY="$MINIO_PASSWORD"
export AWS_EC2_METADATA_DISABLED=true

bucket_length=${#BUCKET_NAME}
case "$BUCKET_NAME" in
  *[!a-z0-9-]* | -* | *-) fail "BUCKET_NAME is not a valid Hetzner bucket name" ;;
esac
if [ "$bucket_length" -lt 3 ] || [ "$bucket_length" -gt 63 ]; then
  fail "BUCKET_NAME is not a valid Hetzner bucket name"
fi

terraform_version=$(terraform version -json | jq -r '.terraform_version')
[ "$terraform_version" = "1.15.5" ] || fail "locking proof requires Terraform 1.15.5"

repository=$(pwd -P)
evidence=$(realpath -m "$HETZNER_S3_LOCKING_EVIDENCE")
case "$evidence" in
  "$repository" | "$repository"/* | /mnt/c/Users/*/OneDrive/*)
    fail "locking evidence must be stored outside the repository and OneDrive"
    ;;
esac
[ ! -e "$evidence" ] || fail "locking evidence already exists; preserve it and choose a new path"
evidence_directory=$(dirname "$evidence")
mkdir -p "$evidence_directory"
chmod 0700 "$evidence_directory"
umask 077

probe=infrastructure/hetzner/bootstrap/object-storage/lock-runtime-test
state_key=ecommerce/lock-tests/terraform.tfstate
lock_key=$state_key.tflock
expected_lock_path=$BUCKET_NAME/$state_key
backend_cache=$probe/.terraform/terraform.tfstate
export TF_DATA_DIR="$repository/$probe/.terraform"
[ -f "$backend_cache" ] ||
  fail "initialize the probe first with scripts/init-hetzner-s3-backend.sh lock-runtime-test"

jq --exit-status \
  --arg bucket "$BUCKET_NAME" \
  --arg key "$state_key" '
    .backend.type == "s3" and
    .backend.config.bucket == $bucket and
    .backend.config.key == $key and
    .backend.config.region == "nbg1" and
    .backend.config.endpoints.s3 == "https://nbg1.your-objectstorage.com" and
    .backend.config.use_lockfile == true
  ' "$backend_cache" >/dev/null ||
  fail "initialized probe backend does not match the canonical S3 lock target"

workspace=$(terraform -chdir="$probe" workspace show)
[ "$workspace" = "default" ] || fail "Terraform workspaces are forbidden for this backend"

evidence_name=$(basename "$evidence")
evidence_prefix=${evidence_name%.json}
holder_log=$evidence_directory/$evidence_prefix.holder.log
contender_one_log=$evidence_directory/$evidence_prefix.contender-1.log
contender_two_log=$evidence_directory/$evidence_prefix.contender-2.log
post_release_log=$evidence_directory/$evidence_prefix.post-release.log
holder_lock_observation=$evidence_directory/$evidence_prefix.holder-lock.json
after_contender_one_observation=$evidence_directory/$evidence_prefix.after-contender-1-lock.response
after_contender_two_observation=$evidence_directory/$evidence_prefix.after-contender-2-lock.response
for artifact in \
  "$holder_log" \
  "$contender_one_log" \
  "$contender_two_log" \
  "$post_release_log" \
  "$holder_lock_observation" \
  "$after_contender_one_observation" \
  "$after_contender_two_observation"; do
  [ ! -e "$artifact" ] || fail "locking artifact already exists; preserve it and choose a new evidence path"
done

case "$MINIO_USER$MINIO_PASSWORD" in
  *\"* | *\\* | *'
'*) fail "S3 credentials contain characters unsupported by the safe curl config" ;;
esac

work_directory=$(mktemp -d)
fifo=$work_directory/holder.stdin
curl_config=$work_directory/curl.config
scratch_response=$work_directory/s3-lock.response
lock_url=https://$BUCKET_NAME.nbg1.your-objectstorage.com/$lock_key
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
  rm -f "$fifo" "$curl_config" "$scratch_response"
  rmdir "$work_directory" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

printf '%s\n' \
  'silent' \
  'show-error' \
  'connect-timeout = 10' \
  'max-time = 30' \
  "user = \"$MINIO_USER:$MINIO_PASSWORD\"" \
  'aws-sigv4 = "aws:amz:nbg1:s3"' >"$curl_config"

s3_get_lock() {
  s3_get_destination=$1
  set +e
  s3_get_status=$(curl \
    --config "$curl_config" \
    --output "$s3_get_destination" \
    --write-out '%{http_code}' \
    "$lock_url")
  s3_get_exit=$?
  set -e
  [ "$s3_get_exit" -eq 0 ] || fail "authenticated S3 lock observation failed"
  case "$s3_get_status" in
    [0-9][0-9][0-9]) ;;
    *) fail "authenticated S3 lock observation returned an invalid HTTP status" ;;
  esac
}

validate_lock_body() {
  lock_body=$1
  expected_id=$2
  jq --exit-status \
    --arg path "$expected_lock_path" \
    --arg id "$expected_id" '
      (.ID | type == "string" and length > 0) and
      (.Path == $path) and
      (.Operation | type == "string" and length > 0) and
      ($id == "" or .ID == $id)
    ' "$lock_body" >/dev/null ||
    fail "authenticated S3 response is not the expected Terraform lock object"
}

wait_for_lock_absent() {
  absence_attempt=0
  while [ "$absence_attempt" -lt 15 ]; do
    s3_get_lock "$scratch_response"
    case "$s3_get_status" in
      404) return 0 ;;
      200) ;;
      *) fail "authenticated S3 lock absence check returned HTTP $s3_get_status" ;;
    esac
    absence_attempt=$((absence_attempt + 1))
    sleep 1
  done
  return 1
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

run_contender() {
  contender_log=$1
  set +e
  terraform -chdir="$probe" plan \
    -no-color \
    -input=false \
    -lock-timeout=0s >"$contender_log" 2>&1
  contender_status=$?
  set -e
}

artifact_permissions() {
  for artifact in \
    "$evidence" \
    "$holder_log" \
    "$contender_one_log" \
    "$contender_two_log" \
    "$post_release_log" \
    "$holder_lock_observation" \
    "$after_contender_one_observation" \
    "$after_contender_two_observation"; do
    if [ -f "$artifact" ]; then
      chmod 0600 "$artifact"
    fi
  done
}

record_incompatible() {
  incompatible_contender=$1
  incompatible_observation=$2

  kill -0 "$holder_pid" 2>/dev/null ||
    fail "contender succeeded only after the holder exited; locking remains unproven"

  s3_get_lock "$incompatible_observation"
  after_contender_status=$s3_get_status
  after_contender_lock_id=
  case "$after_contender_status" in
    200)
      validate_lock_body "$incompatible_observation" ""
      after_contender_lock_id=$(jq -r '.ID' "$incompatible_observation")
      ;;
    404) ;;
    *) fail "post-contender lock observation returned HTTP $after_contender_status" ;;
  esac

  cancel_holder
  holder_cancelled=false
  holder_release_error=false
  if grep -q 'Apply cancelled' "$holder_log"; then
    holder_cancelled=true
  fi
  if grep -q 'Error releasing the state lock' "$holder_log"; then
    holder_release_error=true
  fi

  s3_get_lock "$scratch_response"
  after_holder_status=$s3_get_status
  post_release_status_json=null
  if [ "$after_holder_status" = 404 ]; then
    run_contender "$post_release_log"
    post_release_status_json=$contender_status
  fi

  canonical=infrastructure/hetzner/backend/hetzner-s3.common.tfbackend
  canonical_hash=$(sha256sum "$canonical" | awk '{print $1}')
  holder_lock_hash=$(sha256sum "$holder_lock_observation" | awk '{print $1}')
  observed_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
  first_exit_json=${first_status:-null}
  second_exit_json=${second_status:-null}
  jq -n \
    --arg bucket "$BUCKET_NAME" \
    --arg principal "$HETZNER_MANAGEMENT_PRINCIPAL_ARN" \
    --arg hash "$canonical_hash" \
    --arg observed "$observed_at" \
    --arg state_key "$state_key" \
    --arg lock_key "$lock_key" \
    --arg lock_path "$expected_lock_path" \
    --arg lock_id "$holder_lock_id" \
    --arg lock_hash "$holder_lock_hash" \
    --arg incompatible_contender "$incompatible_contender" \
    --arg after_contender_status "$after_contender_status" \
    --arg after_contender_lock_id "$after_contender_lock_id" \
    --arg after_holder_status "$after_holder_status" \
    --argjson first_exit "$first_exit_json" \
    --argjson second_exit "$second_exit_json" \
    --argjson holder_exit "$holder_status" \
    --argjson holder_cancelled "$holder_cancelled" \
    --argjson holder_release_error "$holder_release_error" \
    --argjson post_exit "$post_release_status_json" '
      {
        version: 2,
        status: "INCOMPATIBLE",
        reason: "contender_acquired_while_holder_lock_was_observed",
        bucketName: $bucket,
        managementPrincipalArn: $principal,
        terraformVersion: "1.15.5",
        canonicalConfigSha256: $hash,
        probeKey: $state_key,
        lockObjectKey: $lock_key,
        lockInfoPath: $lock_path,
        observedAt: $observed,
        holderLockObservedViaAuthenticatedGet: true,
        holderLockId: $lock_id,
        holderLockObjectSha256: $lock_hash,
        incompatibleContender: $incompatible_contender,
        firstContenderExitCode: $first_exit,
        secondContenderExitCode: $second_exit,
        lockHttpStatusAfterIncompatibleContender: ($after_contender_status | tonumber),
        lockIdAfterIncompatibleContender: (if $after_contender_lock_id == "" then null else $after_contender_lock_id end),
        holderExitCode: $holder_exit,
        holderCancelled: $holder_cancelled,
        holderReleaseError: $holder_release_error,
        lockHttpStatusAfterHolderExit: ($after_holder_status | tonumber),
        postReleaseExitCode: $post_exit,
        conditionalWriteViolated: true
      }
    ' >"$evidence"
  artifact_permissions
  fail "S3 native locking is INCOMPATIBLE: contender $incompatible_contender acquired an observed live holder lock"
}

# Refuse to start on top of a pre-existing lock. A real orphan requires a
# separate human-reviewed recovery; this harness never force-unlocks it.
s3_get_lock "$scratch_response"
[ "$s3_get_status" = 404 ] || {
  if [ "$s3_get_status" = 200 ]; then
    fail "probe lock already exists; do not run force-unlock without proving it is orphaned"
  fi
  fail "authenticated preflight lock read returned HTTP $s3_get_status"
}

mkfifo "$fifo"
terraform -chdir="$probe" apply \
  -no-color \
  -input=true \
  -lock-timeout=0s <"$fifo" >"$holder_log" 2>&1 &
holder_pid=$!
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

# The prompt is only a Terraform lifecycle marker. The authenticated GET of
# the exact .tflock key is the positive acquisition proof used by this test.
lock_observed=false
attempt=0
while [ "$attempt" -lt 15 ]; do
  kill -0 "$holder_pid" 2>/dev/null || fail "lock holder exited before direct S3 observation"
  s3_get_lock "$holder_lock_observation"
  case "$s3_get_status" in
    200)
      validate_lock_body "$holder_lock_observation" ""
      lock_observed=true
      break
      ;;
    404) ;;
    *) fail "holder lock observation returned HTTP $s3_get_status" ;;
  esac
  attempt=$((attempt + 1))
  sleep 1
done
[ "$lock_observed" = true ] || fail "holder .tflock was not observed within 15 seconds"

holder_lock_id=$(jq -r '.ID' "$holder_lock_observation")
case "$holder_lock_id" in
  ????????-????-????-????-????????????) ;;
  *) fail "observed holder lock ID is not a Terraform UUID" ;;
esac
holder_lock_hash=$(sha256sum "$holder_lock_observation" | awk '{print $1}')

run_contender "$contender_one_log"
first_status=$contender_status
if [ "$first_status" -eq 0 ]; then
  record_incompatible "1" "$after_contender_one_observation"
fi
grep -q 'Error acquiring the state lock' "$contender_one_log" ||
  fail "first contender failed for a reason unrelated to state locking"
grep -Eq 'PreconditionFailed|StatusCode:[[:space:]]*412|HTTP[[:space:]]*412' "$contender_one_log" ||
  fail "first contender did not prove conditional PutObject contention with HTTP 412"
first_lock_id=$(awk '/^[[:space:]]*ID:[[:space:]]*/ {print $2; exit}' "$contender_one_log")
[ "$first_lock_id" = "$holder_lock_id" ] || fail "first contender did not report the observed holder lock ID"

s3_get_lock "$after_contender_one_observation"
[ "$s3_get_status" = 200 ] || fail "holder lock disappeared after the first rejected contender"
validate_lock_body "$after_contender_one_observation" "$holder_lock_id"
after_first_hash=$(sha256sum "$after_contender_one_observation" | awk '{print $1}')
[ "$after_first_hash" = "$holder_lock_hash" ] || fail "first contender changed the holder lock object"

run_contender "$contender_two_log"
second_status=$contender_status
if [ "$second_status" -eq 0 ]; then
  record_incompatible "2" "$after_contender_two_observation"
fi
grep -q 'Error acquiring the state lock' "$contender_two_log" ||
  fail "second contender failed for a reason unrelated to state locking"
grep -Eq 'PreconditionFailed|StatusCode:[[:space:]]*412|HTTP[[:space:]]*412' "$contender_two_log" ||
  fail "second contender did not prove conditional PutObject contention with HTTP 412"
second_lock_id=$(awk '/^[[:space:]]*ID:[[:space:]]*/ {print $2; exit}' "$contender_two_log")
[ "$second_lock_id" = "$holder_lock_id" ] || fail "second contender did not report the observed holder lock ID"

s3_get_lock "$after_contender_two_observation"
[ "$s3_get_status" = 200 ] || fail "holder lock disappeared after the second rejected contender"
validate_lock_body "$after_contender_two_observation" "$holder_lock_id"
after_second_hash=$(sha256sum "$after_contender_two_observation" | awk '{print $1}')
[ "$after_second_hash" = "$holder_lock_hash" ] || fail "second contender changed the holder lock object"

cancel_holder
# Terraform 1.15.5 deliberately reports a user-declined apply as operation
# failure (exit 1). Clean release is established by the cancellation marker,
# absence of an unlock error, and direct disappearance of the lock object.
[ "$holder_status" -eq 1 ] || fail "holder cancellation returned an unexpected exit code"
grep -q 'Apply cancelled' "$holder_log" || fail "holder cancellation was not confirmed"
if grep -q 'Error releasing the state lock' "$holder_log"; then
  fail "holder reported an error while releasing the state lock"
fi
wait_for_lock_absent || fail "holder lock remained visible after clean cancellation"

run_contender "$post_release_log"
post_release_status=$contender_status
[ "$post_release_status" -eq 0 ] || fail "contender did not succeed after holder release"
wait_for_lock_absent || fail "post-release plan left a lock object behind"

canonical=infrastructure/hetzner/backend/hetzner-s3.common.tfbackend
canonical_hash=$(sha256sum "$canonical" | awk '{print $1}')
observed_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
jq -n \
  --arg bucket "$BUCKET_NAME" \
  --arg principal "$HETZNER_MANAGEMENT_PRINCIPAL_ARN" \
  --arg hash "$canonical_hash" \
  --arg observed "$observed_at" \
  --arg state_key "$state_key" \
  --arg lock_key "$lock_key" \
  --arg lock_path "$expected_lock_path" \
  --arg lock_id "$holder_lock_id" \
  --arg lock_hash "$holder_lock_hash" \
  --argjson first_exit "$first_status" \
  --argjson second_exit "$second_status" \
  --argjson holder_exit "$holder_status" \
  --argjson post_exit "$post_release_status" '
    {
      version: 2,
      status: "PROVEN",
      bucketName: $bucket,
      managementPrincipalArn: $principal,
      terraformVersion: "1.15.5",
      canonicalConfigSha256: $hash,
      probeKey: $state_key,
      lockObjectKey: $lock_key,
      lockInfoPath: $lock_path,
      observedAt: $observed,
      holderLockObservedViaAuthenticatedGet: true,
      holderLockId: $lock_id,
      holderLockObjectSha256: $lock_hash,
      firstContenderExitCode: $first_exit,
      secondContenderExitCode: $second_exit,
      preconditionFailed412: true,
      stableLockId: true,
      lockObjectUnchangedAfterEachContender: true,
      holderExitCode: $holder_exit,
      holderCancelledCleanly: true,
      lockAbsentAfterHolderRelease: true,
      postReleaseExitCode: $post_exit,
      lockAbsentAfterPostReleasePlan: true
    }
  ' >"$evidence"
artifact_permissions

trap - EXIT HUP INT TERM
cleanup
info "S3 native lock contention PROVEN; evidence written outside the repository"
