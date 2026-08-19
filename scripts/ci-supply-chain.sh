#!/bin/sh
set -eu
# shellcheck source=scripts/lib.sh
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

mutable_images=$(grep -RInE 'image:[[:space:]]*[^#[:space:]]+:latest([[:space:]]|$)' gitops platform security tekton 2>/dev/null || true)
[ -z "$mutable_images" ] || {
  printf '%s\n' "$mutable_images" >&2
  fail "mutable :latest image references are forbidden"
}

production_files=$(find gitops -type f \( -iname '*prod*.yaml' -o -iname '*production*.yaml' \) -print 2>/dev/null || true)
if [ -z "$production_files" ]; then
  info "no production manifests found; immutable production image check skipped"
else
  printf '%s\n' "$production_files" | while IFS= read -r manifest; do
    image_lines=$(grep -E 'image:[[:space:]]*' "$manifest" 2>/dev/null || true)
    [ -z "$image_lines" ] || printf '%s\n' "$image_lines" | grep -q '@sha256:' || \
      fail "production image without immutable digest in $manifest"
  done
fi

info "supply-chain source checks completed; CI must additionally publish SBOM, provenance and Cosign verification artifacts"
