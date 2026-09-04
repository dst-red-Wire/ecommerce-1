#!/bin/sh
set -eu
# shellcheck source=scripts/lib.sh
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

gitleaks_version=$(read_pinned_version GITLEAKS_VERSION) || fail "invalid Gitleaks version pin"
gitleaks_digest=$(read_pinned_version GITLEAKS_IMAGE_DIGEST) || fail "invalid Gitleaks image pin"
trivy_version=$(read_pinned_version TRIVY_VERSION) || fail "invalid Trivy version pin"
trivy_digest=$(read_pinned_version TRIVY_IMAGE_DIGEST) || fail "invalid Trivy image pin"

check_image() {
  file=$1
  image=$2
  version=$3
  digest=$4
  grep -Fq "# $image:$version" "$file" || fail "$file does not document $image:$version"
  grep -Fq "image: $image@$digest" "$file" || fail "$file does not use $image@$digest"
}

check_image .woodpecker/ci.yaml zricethezav/gitleaks "v$gitleaks_version" "$gitleaks_digest"
check_image gitops/infrastructure/tekton-ci/tasks/source-security.yaml \
  zricethezav/gitleaks "v$gitleaks_version" "$gitleaks_digest"
check_image gitops/infrastructure/tekton-ci/tasks/source-security.yaml \
  aquasec/trivy "$trivy_version" "$trivy_digest"
check_image gitops/infrastructure/tekton-ci/tasks/scan-image.yaml \
  aquasec/trivy "$trivy_version" "$trivy_digest"

if grep -RInF 'gitleaks:v8.24.3' .woodpecker gitops/infrastructure/tekton-ci docs/security 2>/dev/null; then
  fail "obsolete Gitleaks 8.24.3 reference remains in authoritative delivery sources"
fi
grep -Fq -- '--scanners vuln' scripts/ci-security.sh ||
  fail "local Trivy vulnerability scan must select --scanners vuln explicitly"
grep -Fq -- '--scanners vuln' gitops/infrastructure/tekton-ci/tasks/scan-image.yaml ||
  fail "Tekton image vulnerability scan must select --scanners vuln explicitly"

info "Gitleaks and Trivy versions are consistent across local tooling and delivery definitions"
