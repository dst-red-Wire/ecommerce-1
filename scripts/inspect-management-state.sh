#!/bin/sh
set -eu

# Future read-only S3 ListObjectVersions gate. It lists every historical version and delete marker of
# the exact legacy key; it never downloads a state payload or writes to S3.
# shellcheck disable=SC1091
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

require curl
require jq
require python3
require realpath
require sha256sum

: "${BUCKET_NAME:?BUCKET_NAME is required}"
: "${MINIO_USER:?MINIO_USER is required}"
: "${MINIO_PASSWORD:?MINIO_PASSWORD is required}"
: "${MANAGEMENT_STATE_INSPECTION_EVIDENCE:?MANAGEMENT_STATE_INSPECTION_EVIDENCE is required}"

[ "$BUCKET_NAME" = "ecommerce-management-tfstate-20260820-70b94831" ] ||
  fail "state inspection must target the preserved management archive bucket"
case "$MINIO_USER$MINIO_PASSWORD" in
  *\"* | *\\* | *'
'*) fail "Object Storage credentials contain characters unsupported by the safe curl config" ;;
esac
unset TF_LOG TF_LOG_CORE TF_LOG_PROVIDER TF_LOG_PATH MINIO_DEBUG

repository=$(pwd -P)
evidence=$(realpath -m "$MANAGEMENT_STATE_INSPECTION_EVIDENCE")
case "$evidence" in
  "$repository" | "$repository"/* | /mnt/c/Users/*/OneDrive/*)
    fail "state inspection evidence must remain outside the repository and OneDrive"
    ;;
esac
[ ! -e "$evidence" ] || fail "state inspection evidence already exists; preserve it and choose a new path"
evidence_directory=$(dirname "$evidence")
mkdir -p "$evidence_directory"
chmod 0700 "$evidence_directory"
umask 077

work_directory=$(mktemp -d)
curl_config=$work_directory/curl.config
response_xml=$work_directory/list-object-versions.xml
normalized_page=$work_directory/version-page.json
version_pages=$work_directory/version-pages.jsonl
summaries=$work_directory/summaries.jsonl
cleanup() {
  rm -f "$curl_config" "$response_xml" "$normalized_page" "$version_pages" "$summaries"
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

summarize_state() {
  state_path=$1
  state_location=$2
  state_backend=$3
  [ ! -L "$state_path" ] || fail "state candidate at $state_location must not be a symbolic link"
  jq --exit-status '
    (.version | type == "number") and
    (.lineage | type == "string" and length > 0) and
    (.serial | type == "number" and . >= 0) and
    (.resources | type == "array")
  ' "$state_path" >/dev/null || fail "state at $state_location is not a valid Terraform state"
  state_hash=$(sha256sum "$state_path" | awk '{print $1}')
  state_lineage=$(jq -r '.lineage' "$state_path")
  state_serial=$(jq -r '.serial' "$state_path")
  state_resource_count=$(jq '[.resources[]?.instances[]?] | length' "$state_path")
  jq -n \
    --arg location "$state_location" \
    --arg backend "$state_backend" \
    --arg sha256 "$state_hash" \
    --arg lineage "$state_lineage" \
    --argjson serial "$state_serial" \
    --argjson resource_count "$state_resource_count" '
      {
        location: $location,
        backendSource: $backend,
        exists: true,
        sha256: $sha256,
        lineage: $lineage,
        serial: $serial,
        resourceCount: $resource_count
      }
    ' >>"$summaries"
}

record_absent() {
  absent_location=$1
  absent_backend=$2
  jq -n --arg location "$absent_location" --arg backend "$absent_backend" '
    {
      location: $location,
      backendSource: $backend,
      exists: false,
      sha256: null,
      lineage: null,
      serial: null,
      resourceCount: 0
    }
  ' >>"$summaries"
}

repository_candidate=$repository/infrastructure/hetzner/management/terraform.tfstate
if [ -f "$repository_candidate" ]; then
  summarize_state "$repository_candidate" "infrastructure/hetzner/management/terraform.tfstate" "local-repository-candidate"
elif [ -e "$repository_candidate" ] || [ -L "$repository_candidate" ]; then
  fail "local repository state candidate has an unsafe file type"
else
  record_absent "infrastructure/hetzner/management/terraform.tfstate" "local-repository-candidate"
fi

state_base=${XDG_STATE_HOME:-"$HOME/.local/state"}
external_candidate=$state_base/ecommerce-1/terraform/management/terraform.tfstate
# shellcheck disable=SC2016
external_location_label='${XDG_STATE_HOME:-$HOME/.local/state}/ecommerce-1/terraform/management/terraform.tfstate'
if [ -f "$external_candidate" ]; then
  summarize_state "$external_candidate" "$external_location_label" "local-external-candidate"
elif [ -e "$external_candidate" ] || [ -L "$external_candidate" ]; then
  fail "external local state candidate has an unsafe file type"
else
  record_absent "$external_location_label" "local-external-candidate"
fi

legacy_key=ecommerce/management/terraform.tfstate
encoded_legacy_key=ecommerce%2Fmanagement%2Fterraform.tfstate
version_endpoint=https://$BUCKET_NAME.nbg1.your-objectstorage.com/
page_number=1
next_key_marker=
next_version_marker=
history_transport_ok=true
: >"$version_pages"

while [ "$page_number" -le 100 ]; do
  query="versions=&encoding-type=url&prefix=$encoded_legacy_key"
  if [ -n "$next_key_marker" ]; then
    encoded_key_marker=$(jq -nr --arg value "$next_key_marker" '$value | @uri')
    encoded_version_marker=$(jq -nr --arg value "$next_version_marker" '$value | @uri')
    query="$query&key-marker=$encoded_key_marker&version-id-marker=$encoded_version_marker"
  fi
  set +e
  http_status=$(curl \
    --config "$curl_config" \
    --output "$response_xml" \
    --write-out '%{http_code}' \
    "$version_endpoint?$query")
  curl_status=$?
  set -e
  if [ "$curl_status" -ne 0 ] || [ "$http_status" != 200 ]; then
    history_transport_ok=false
    jq -nc '{apiStatus:"ERROR",isTruncated:false,nextKeyMarker:null,nextVersionIdMarker:null,entries:[]}' >>"$version_pages"
    break
  fi
  if ! python3 scripts/inspect-s3-version-history.py parse-xml \
    --input "$response_xml" \
    --key "$legacy_key" >"$normalized_page"; then
    history_transport_ok=false
    jq -nc '{apiStatus:"ERROR",isTruncated:false,nextKeyMarker:null,nextVersionIdMarker:null,entries:[]}' >>"$version_pages"
    break
  fi
  cat "$normalized_page" >>"$version_pages"
  is_truncated=$(jq -r '.isTruncated' "$normalized_page")
  if [ "$is_truncated" = false ]; then
    break
  fi
  next_key_marker=$(jq -er '.nextKeyMarker | select(type == "string" and length > 0)' "$normalized_page") || {
    history_transport_ok=false
    break
  }
  next_version_marker=$(jq -er '.nextVersionIdMarker | select(type == "string" and length > 0)' "$normalized_page") || {
    history_transport_ok=false
    break
  }
  page_number=$((page_number + 1))
done

if [ "$page_number" -gt 100 ]; then
  history_transport_ok=false
fi
version_history=$(python3 scripts/inspect-s3-version-history.py evaluate \
  --input "$version_pages" \
  --key "$legacy_key") || fail "legacy S3 version metadata evaluation failed"
history_verdict=$(printf '%s' "$version_history" | jq -r '.verdict')
history_entries=$(printf '%s' "$version_history" | jq -r '.totalHistoryEntryCount')
history_exists=null
case "$history_verdict" in
  ZERO_HISTORY) history_exists=false ;;
  HISTORICAL_STATE_PRESENT) history_exists=true ;;
  UNKNOWN) history_transport_ok=false ;;
  *) fail "legacy S3 version history returned an invalid verdict" ;;
esac
jq -n \
  --arg location "$BUCKET_NAME/$legacy_key" \
  --argjson exists "$history_exists" \
  --argjson history_count "$history_entries" '
    {
      location: $location,
      backendSource: "hetzner-object-storage-legacy-non-authoritative",
      exists: $exists,
      historicalMetadataOnly: true,
      totalHistoryEntryCount: $history_count,
      sha256: null,
      lineage: null,
      serial: null,
      resourceCount: null
    }
  ' >>"$summaries"

backend_cache_type=none
backend_cache=$repository/infrastructure/hetzner/management/.terraform/terraform.tfstate
if [ -f "$backend_cache" ]; then
  backend_cache_type=$(jq -er '.backend.type | select(type == "string" and length > 0)' "$backend_cache") ||
    fail "management backend cache exists but has no readable backend type"
fi

sources_json=$(jq -s '.' "$summaries")
local_sources_absent=$(printf '%s' "$sources_json" | jq 'all(.[:2][]; .exists == false)')
all_sources_absent=false
if [ "$local_sources_absent" = true ] && [ "$history_verdict" = ZERO_HISTORY ]; then
  all_sources_absent=true
fi
inspection_status=INSPECTED
[ "$history_verdict" != UNKNOWN ] || inspection_status=UNKNOWN
observed_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
jq -n \
  --arg observed "$observed_at" \
  --arg status "$inspection_status" \
  --arg bucket "$BUCKET_NAME" \
  --arg legacy_key "$legacy_key" \
  --arg backend_cache_type "$backend_cache_type" \
  --argjson history_authenticated "$history_transport_ok" \
  --argjson version_history "$version_history" \
  --argjson sources "$sources_json" \
  --argjson all_absent "$all_sources_absent" '
    {
      version: 2,
      status: $status,
      observedAt: $observed,
      bucket: $bucket,
      legacyObjectKey: $legacy_key,
      legacyVersionHistoryCheckedAuthenticated: $history_authenticated,
      legacyVersionHistory: $version_history,
      localCandidatesChecked: true,
      backendCacheType: $backend_cache_type,
      sources: $sources,
      allSourcesAbsent: $all_absent,
      decision: "HUMAN_REQUIRED"
    }
  ' >"$evidence"
chmod 0600 "$evidence"

trap - EXIT HUP INT TERM
cleanup
if [ "$history_verdict" = UNKNOWN ]; then
  fail "legacy S3 version history is UNKNOWN; initialize-empty is forbidden"
fi
info "management state history inspection recorded from authenticated metadata only; human decision is still required"
