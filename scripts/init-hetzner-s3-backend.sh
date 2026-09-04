#!/bin/sh
set -eu

# shellcheck disable=SC1091
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

require jq
require realpath
require sha256sum
require terraform

usage() {
  fail "usage: $0 lock-runtime-test"
}

[ "$#" -eq 1 ] || usage
target=$1
[ "$target" = "lock-runtime-test" ] ||
  fail "Hetzner S3 is INCOMPATIBLE as the management backend; only the retained lock-runtime-test diagnostic may be initialized"

: "${BUCKET_NAME:?BUCKET_NAME is required}"
: "${MINIO_USER:?MINIO_USER is required}"
: "${MINIO_PASSWORD:?MINIO_PASSWORD is required}"
: "${HETZNER_MANAGEMENT_PRINCIPAL_ARN:?HETZNER_MANAGEMENT_PRINCIPAL_ARN is required}"
: "${HETZNER_BUCKET_PROTECTION_EVIDENCE:?HETZNER_BUCKET_PROTECTION_EVIDENCE is required}"
: "${HETZNER_BUCKET_PRIVACY_EVIDENCE:?HETZNER_BUCKET_PRIVACY_EVIDENCE is required}"

unset TF_LOG TF_LOG_CORE TF_LOG_PROVIDER TF_LOG_PATH MINIO_DEBUG
require_management_s3_identity

bucket_length=${#BUCKET_NAME}
case "$BUCKET_NAME" in
  *[!a-z0-9-]* | -* | *-) fail "BUCKET_NAME is not a valid Hetzner bucket name" ;;
esac
if [ "$bucket_length" -lt 3 ] || [ "$bucket_length" -gt 63 ]; then
  fail "BUCKET_NAME is not a valid Hetzner bucket name"
fi

repository=$(pwd -P)
canonical="$repository/infrastructure/hetzner/backend/hetzner-s3.common.tfbackend"
canonical_hash=$(sha256sum "$canonical" | awk '{print $1}')

external_evidence() {
  evidence=$(realpath "$1") || fail "runtime evidence file does not exist"
  [ -f "$evidence" ] || fail "runtime evidence path is not a regular file"
  case "$evidence" in
    "$repository"/* | /mnt/c/Users/*/OneDrive/*)
      fail "runtime evidence must be stored outside the repository and OneDrive"
      ;;
  esac
  printf '%s\n' "$evidence"
}

protection_evidence=$(external_evidence "$HETZNER_BUCKET_PROTECTION_EVIDENCE")
privacy_evidence=$(external_evidence "$HETZNER_BUCKET_PRIVACY_EVIDENCE")

jq --exit-status --arg bucket "$BUCKET_NAME" '
  .version == 1 and
  .status == "PROVEN_MANUAL" and
  .bucketName == $bucket and
  .protected == true and
  (.observedAt | type == "string" and length > 0) and
  ((.observedAt | fromdateiso8601) as $observed |
    $observed <= now and (now - $observed) <= 86400) and
  (.verifiedBy | type == "array" and length >= 1 and all(.[]; type == "string" and length > 0)) and
  (.evidenceReference | type == "string" and length > 0)
' "$protection_evidence" >/dev/null ||
  fail "Hetzner protected=true is not backed by valid human evidence with at least one verifier"

jq --exit-status \
  --arg bucket "$BUCKET_NAME" \
  --arg hash "$canonical_hash" \
  --arg principal "$HETZNER_MANAGEMENT_PRINCIPAL_ARN" '
  .version == 1 and
  .status == "PROVEN" and
  .bucketName == $bucket and
  .managementPrincipalArn == $principal and
  .terraformVersion == "1.15.5" and
  .canonicalConfigSha256 == $hash and
  ((.observedAt | fromdateiso8601) as $observed |
    $observed <= now and (now - $observed) <= 3600) and
  .versioningEnabled == true and
  .noWildcardPrincipal == true and
  .leastPrivilegePolicyExact == true and
  .anonymousHttpStatus.list == 403 and
  .anonymousHttpStatus.state == 403 and
  .anonymousHttpStatus.lock == 403
' "$privacy_evidence" >/dev/null ||
  fail "bucket privacy is not backed by valid runtime evidence"

root=infrastructure/hetzner/bootstrap/object-storage/lock-runtime-test

# Backend credentials remain process-only. EC2 metadata is also disabled at
# the SDK level in addition to the canonical backend setting.
export AWS_ACCESS_KEY_ID="$MINIO_USER"
export AWS_SECRET_ACCESS_KEY="$MINIO_PASSWORD"
export AWS_EC2_METADATA_DISABLED=true
export TF_DATA_DIR="$repository/$root/.terraform"

terraform -chdir="$root" init \
  -reconfigure \
  -input=false \
  -backend-config="$canonical" \
  -backend-config="bucket=$BUCKET_NAME"

workspace=$(terraform -chdir="$root" workspace show)
[ "$workspace" = "default" ] || fail "Terraform workspaces are forbidden for this backend"

info "canonical Hetzner S3 lock diagnostic initialized in the default workspace; management activation remains forbidden"
