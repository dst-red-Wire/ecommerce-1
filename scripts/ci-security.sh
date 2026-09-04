#!/bin/sh
set -eu
# shellcheck source=scripts/lib.sh
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

./scripts/check-gitleaks-version.sh
if git rev-parse --verify HEAD >/dev/null 2>&1; then
  gitleaks git --config .gitleaks.toml --redact --no-banner --exit-code 1 .
fi
gitleaks dir --config .gitleaks.toml --redact --no-banner --exit-code 1 .

if have trivy; then
  ./scripts/check-trivy-version.sh
  trivy filesystem --exit-code 1 --severity CRITICAL,HIGH --scanners vuln --no-progress \
    --skip-dirs .git --skip-dirs .venv --skip-dirs platform/tekton/vendor .
  trivy config --exit-code 1 --severity CRITICAL,HIGH \
    --skip-dirs .git --skip-dirs .venv --skip-dirs platform/tekton/vendor .
else
  warn "trivy is unavailable; vulnerability and IaC scans skipped"
fi

info "secret scan completed"
