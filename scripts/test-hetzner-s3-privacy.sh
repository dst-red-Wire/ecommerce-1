#!/bin/sh
set -eu

# shellcheck disable=SC1091
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

require curl
require jq
require realpath
require sha256sum
require terraform

: "${BUCKET_NAME:?BUCKET_NAME is required}"
: "${MINIO_USER:?MINIO_USER is required}"
: "${MINIO_PASSWORD:?MINIO_PASSWORD is required}"
: "${HETZNER_MANAGEMENT_PRINCIPAL_ARN:?HETZNER_MANAGEMENT_PRINCIPAL_ARN is required}"
: "${HETZNER_BUCKET_PRIVACY_EVIDENCE:?HETZNER_BUCKET_PRIVACY_EVIDENCE is required}"

unset TF_LOG TF_LOG_CORE TF_LOG_PROVIDER TF_LOG_PATH MINIO_DEBUG

bucket_length=${#BUCKET_NAME}
case "$BUCKET_NAME" in
  *[!a-z0-9-]* | -* | *-) fail "BUCKET_NAME is not a valid Hetzner bucket name" ;;
esac
if [ "$bucket_length" -lt 3 ] || [ "$bucket_length" -gt 63 ]; then
  fail "BUCKET_NAME is not a valid Hetzner bucket name"
fi

repository=$(pwd -P)
state_base=${XDG_STATE_HOME:-"$HOME/.local/state"}
state_directory=${BOOTSTRAP_STATE_DIR:-"$state_base/ecommerce-1/terraform/bootstrap-object-storage"}
state_directory=$(realpath -m "$state_directory")
case "$state_directory" in
  "$repository" | "$repository"/* | /mnt/c/Users/*/OneDrive/*)
    fail "authoritative bootstrap state must remain outside the repository and OneDrive"
    ;;
esac

state_file=$state_directory/terraform.tfstate
[ -f "$state_file" ] || fail "authoritative bootstrap state is unavailable"
[ ! -L "$state_file" ] || fail "authoritative bootstrap state must not be a symbolic link"

evidence=$(realpath -m "$HETZNER_BUCKET_PRIVACY_EVIDENCE")
case "$evidence" in
  "$repository" | "$repository"/* | /mnt/c/Users/*/OneDrive/*)
    fail "privacy evidence must be stored outside the repository and OneDrive"
    ;;
esac
[ ! -e "$evidence" ] || fail "privacy evidence already exists; preserve it and choose a new path"
mkdir -p "$(dirname "$evidence")"
chmod 0700 "$(dirname "$evidence")"

export TF_DATA_DIR="$state_directory/terraform-data"
export TF_VAR_management_principal_arn="$HETZNER_MANAGEMENT_PRINCIPAL_ARN"

set +e
terraform -chdir=infrastructure/hetzner/bootstrap/object-storage plan \
  -detailed-exitcode \
  -input=false \
  -lock-timeout=30s \
  -state="$state_file" \
  -var="bucket_name=$BUCKET_NAME" \
  -var="runtime_privacy_gate=true"
plan_status=$?
set -e
[ "$plan_status" -eq 0 ] ||
  fail "privacy/versioning policy read failed or bootstrap drift was detected"

endpoint="https://$BUCKET_NAME.nbg1.your-objectstorage.com"

# The Terraform data source provides an independent refresh path, but its
# schema does not expose the bucket ACL. Query the three S3 control-plane
# documents as well, using a short-lived curl config so credentials never
# appear in the process arguments.
case "$MINIO_USER$MINIO_PASSWORD" in
  *\"* | *\\* | *'
'*) fail "S3 credentials contain characters unsupported by the safe curl config" ;;
esac
curl_config=$(mktemp)
acl_response=$(mktemp)
versioning_response=$(mktemp)
policy_response=$(mktemp)
expected_policy=$(mktemp)
policy_template=infrastructure/hetzner/bootstrap/object-storage/management-bucket-policy.json.tftpl
cleanup_runtime_files() {
  rm -f "$curl_config" "$acl_response" "$versioning_response" "$policy_response" "$expected_policy"
}
trap cleanup_runtime_files EXIT HUP INT TERM
umask 077
printf '%s\n' \
  'silent' \
  'show-error' \
  'fail-with-body' \
  'connect-timeout = 10' \
  'max-time = 30' \
  "user = \"$MINIO_USER:$MINIO_PASSWORD\"" \
  'aws-sigv4 = "aws:amz:nbg1:s3"' >"$curl_config"

curl --config "$curl_config" --output "$acl_response" "$endpoint/?acl"
curl --config "$curl_config" --output "$versioning_response" "$endpoint/?versioning"
curl --config "$curl_config" --output "$policy_response" "$endpoint/?policy"

if grep -Eq 'http://acs\.amazonaws\.com/groups/global/(AllUsers|AuthenticatedUsers)' "$acl_response"; then
  fail "bucket ACL grants access to a public S3 group"
fi
grep -Eq '<Status>[[:space:]]*Enabled[[:space:]]*</Status>' "$versioning_response" ||
  fail "authenticated S3 versioning check did not return Enabled"

jq --null-input \
  --rawfile template "$policy_template" \
  --arg bucket "$BUCKET_NAME" \
  --arg principal "$HETZNER_MANAGEMENT_PRINCIPAL_ARN" \
  '$template
   | split("${bucket_name}") | join($bucket)
   | split("${management_principal}") | join($principal)
   | fromjson' >"$expected_policy"
actual_policy_hash=$(jq --sort-keys . "$policy_response" | sha256sum | awk '{print $1}')
expected_policy_hash=$(jq --sort-keys . "$expected_policy" | sha256sum | awk '{print $1}')
[ "$actual_policy_hash" = "$expected_policy_hash" ] ||
  fail "authenticated S3 policy differs from the canonical least-privilege policy"

anonymous_status() {
  curl --silent --show-error --head \
    --connect-timeout 10 \
    --max-time 30 \
    --output /dev/null \
    --write-out '%{http_code}' \
    "$1"
}

list_status=$(anonymous_status "$endpoint/?list-type=2&max-keys=1")
state_status=$(anonymous_status "$endpoint/ecommerce/management/terraform.tfstate")
lock_status=$(anonymous_status "$endpoint/ecommerce/management/terraform.tfstate.tflock")

[ "$list_status" = 403 ] || fail "anonymous bucket listing did not return HTTP 403"
[ "$state_status" = 403 ] || fail "anonymous state access did not return HTTP 403"
[ "$lock_status" = 403 ] || fail "anonymous lock access did not return HTTP 403"

canonical=infrastructure/hetzner/backend/hetzner-s3.common.tfbackend
canonical_hash=$(sha256sum "$canonical" | awk '{print $1}')
observed_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
umask 077
jq -n \
  --arg bucket "$BUCKET_NAME" \
  --arg principal "$HETZNER_MANAGEMENT_PRINCIPAL_ARN" \
  --arg hash "$canonical_hash" \
  --arg observed "$observed_at" \
  --argjson list "$list_status" \
  --argjson state "$state_status" \
  --argjson lock "$lock_status" \
  '{
    version: 1,
    status: "PROVEN",
    bucketName: $bucket,
    managementPrincipalArn: $principal,
    terraformVersion: "1.15.5",
    canonicalConfigSha256: $hash,
    observedAt: $observed,
    versioningEnabled: true,
    noWildcardPrincipal: true,
    leastPrivilegePolicyExact: true,
    anonymousHttpStatus: {
      list: $list,
      state: $state,
      lock: $lock
    }
  }' >"$evidence"
chmod 0600 "$evidence"

trap - EXIT HUP INT TERM
cleanup_runtime_files
info "privacy runtime gate passed; evidence written outside the repository"
