#!/bin/sh
set -eu

# shellcheck disable=SC1091
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT HUP INT TERM
apps="$fixture/gitops/apps"
clusters="$fixture/gitops/clusters"
repository=ghcr.io/dst-red-wire/ecommerce-1/catalog
digest=sha256:1111111111111111111111111111111111111111111111111111111111111111

mkdir -p "$apps/catalog/base"
for environment in integration preproduction production; do
  mkdir -p "$apps/catalog/overlays/$environment" "$clusters/$environment"
done

printf '%s\n' \
  'apiVersion: apps/v1' \
  'kind: Deployment' \
  'metadata:' \
  '  name: catalog' \
  'spec:' \
  '  selector:' \
  '    matchLabels: {app: catalog}' \
  '  template:' \
  '    metadata:' \
  '      labels: {app: catalog}' \
  '    spec:' \
  '      initContainers:' \
  '        - name: migrate' \
  "          image: $repository" \
  '      containers:' \
  '        - name: catalog' \
  "          image: $repository" \
  '        - name: sidecar' \
  "          image: $repository" >"$apps/catalog/base/deployment.yaml"
printf '%s\n' \
  'apiVersion: kustomize.config.k8s.io/v1beta1' \
  'kind: Kustomization' \
  'resources: [deployment.yaml]' >"$apps/catalog/base/kustomization.yaml"

for environment in integration preproduction production; do
  printf '%s\n' \
    'apiVersion: kustomize.config.k8s.io/v1beta1' \
    'kind: Kustomization' \
    'resources: [../../base]' \
    'images:' \
    "  - name: $repository" \
    "    newName: $repository" \
    "    digest: $digest" >"$apps/catalog/overlays/$environment/kustomization.yaml"
  printf '%s\n' \
    'apiVersion: kustomize.config.k8s.io/v1beta1' \
    'kind: Kustomization' \
    'resources:' \
    "  - ../../apps/catalog/overlays/$environment" >"$clusters/$environment/kustomization.yaml"
done

./scripts/validate-gitops-images.sh "$apps" "$clusters" >/dev/null

yq -i '.images[0].name = "ghcr.io/dst-red-wire/ecommerce-1/disconnected" |
  .images[0].newName = "ghcr.io/dst-red-wire/ecommerce-1/disconnected"' \
  "$apps/catalog/overlays/integration/kustomization.yaml"
if ./scripts/validate-gitops-images.sh "$apps" "$clusters" >/dev/null 2>&1; then
  fail "disconnected images[].digest fixture was incorrectly accepted"
fi

workloads="$fixture/workloads.yaml"
printf '%s\n' \
  'apiVersion: apps/v1' \
  'kind: StatefulSet' \
  'metadata: {name: stateful}' \
  'spec:' \
  '  template:' \
  '    spec:' \
  '      initContainers:' \
  "        - {name: init, image: $repository@$digest}" \
  '      containers:' \
  "        - {name: first, image: $repository@$digest}" \
  "        - {name: second, image: $repository@$digest}" \
  '---' \
  'apiVersion: batch/v1' \
  'kind: Job' \
  'metadata: {name: job}' \
  'spec:' \
  '  template:' \
  '    spec:' \
  "      containers: [{name: job, image: $repository@$digest}]" \
  '---' \
  'apiVersion: batch/v1' \
  'kind: CronJob' \
  'metadata: {name: cron}' \
  'spec:' \
  '  jobTemplate:' \
  '    spec:' \
  '      template:' \
  '        spec:' \
  "          containers: [{name: cron, image: $repository@$digest}]" >"$workloads"
python3 scripts/validate-rendered-images.py "$workloads" >/dev/null

sed "0,/@sha256:[0-9a-f]\\{64\\}/s//@latest/" "$workloads" >"$fixture/mixed-invalid.yaml"
if python3 scripts/validate-rendered-images.py "$fixture/mixed-invalid.yaml" >/dev/null 2>&1; then
  fail "one invalid image among valid containers was accepted"
fi

printf '%s\n' \
  'apiVersion: v1' \
  'kind: ConfigMap' \
  'metadata: {name: no-workload}' >"$fixture/no-workload.yaml"
python3 scripts/validate-rendered-images.py "$fixture/no-workload.yaml" | grep -q 'SKIPPED / NOT PROVEN' || \
  fail "overlay without a workload was not reported as skipped"

info "rendered image adversarial tests passed"
