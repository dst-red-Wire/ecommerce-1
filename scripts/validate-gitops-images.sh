#!/bin/sh
set -eu

# shellcheck disable=SC1091
. "$(dirname "$0")/lib.sh"

cd "$(repo_root)"
apps_root=${1:-gitops/apps}
clusters_root=${2:-gitops/clusters}

have yq || fail "yq is required to validate GitOps image bindings"
have kubectl || fail "kubectl is required to render GitOps image bindings"
have python3 || fail "python3 is required to validate rendered workload images"

rendered_file=$(mktemp)
trap 'rm -f "$rendered_file"' EXIT HUP INT TERM
for environment in integration preproduction production; do
  cluster="$clusters_root/$environment"
  [ -f "$cluster/kustomization.yaml" ] || fail "missing cluster kustomization for $environment"
  kubectl kustomize "$cluster" >"$rendered_file" || fail "$environment Kustomize render failed"
  python3 scripts/validate-rendered-images.py "$rendered_file" --environment "$environment" || \
    fail "$environment rendered workload contains a mutable or invalid image"
done

services=$(find "$apps_root" -mindepth 1 -maxdepth 1 -type d ! -name '_*' -print 2>/dev/null || true)
if [ -z "$services" ]; then
  info "no business service GitOps bases found; workload deployment remains SKIPPED / NOT PROVEN"
  exit 0
fi

printf '%s\n' "$services" | while IFS= read -r service_directory; do
  service=${service_directory##*/}
  printf '%s\n' "$service" | grep -Eq '^[a-z0-9][a-z0-9-]*$' || \
    fail "invalid service directory name: $service"
  base="$service_directory/base"
  [ -f "$base/kustomization.yaml" ] || fail "missing base kustomization for $service"

  for environment in integration preproduction production; do
    overlay="$service_directory/overlays/$environment"
    overlay_file="$overlay/kustomization.yaml"
    cluster_file="$clusters_root/$environment/kustomization.yaml"
    [ -f "$overlay_file" ] || fail "missing $environment overlay for $service"
    [ -f "$cluster_file" ] || fail "missing cluster kustomization for $environment"
    expected_resource="../../apps/$service/overlays/$environment"
    export expected_resource
    yq -e '.resources[] | select(. == strenv(expected_resource))' "$cluster_file" \
      >/dev/null 2>&1 || fail "$cluster_file does not include $expected_resource"
    image_count=$(yq '.images | length' "$overlay_file")
    [ "$image_count" -gt 0 ] || fail "$overlay_file has no images[] binding"
    index=0
    while [ "$index" -lt "$image_count" ]; do
      image_name=$(yq -r ".images[$index].name" "$overlay_file")
      new_name=$(yq -r ".images[$index].newName" "$overlay_file")
      digest=$(yq -r ".images[$index].digest" "$overlay_file")
      [ "$image_name" = "$new_name" ] || fail "$overlay_file changes the canonical repository"
      printf '%s\n' "$image_name" | grep -Eq '^ghcr\.io/dst-red-wire/ecommerce-1/[a-z0-9][a-z0-9._-]*$' || \
        fail "invalid GHCR repository in $overlay_file"
      printf '%s\n' "$digest" | grep -Eq '^sha256:[0-9a-f]{64}$' || \
        fail "invalid digest in $overlay_file"
      grep -RqsF "image: $image_name" "$base" || \
        fail "$overlay_file digest does not target an image referenced by $base"
      rendered=$(kubectl kustomize "$overlay")
      printf '%s\n' "$rendered" | grep -Fq "image: $new_name@$digest" || \
        fail "$overlay_file digest has no effect on rendered workloads"
      index=$((index + 1))
    done
  done
done

info "GitOps image bindings affect referenced workloads in every environment"
