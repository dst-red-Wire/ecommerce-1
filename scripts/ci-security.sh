#!/bin/sh
set -eu
# shellcheck source=scripts/lib.sh
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

require gitleaks
if git rev-parse --verify HEAD >/dev/null 2>&1; then
  gitleaks git --config .gitleaks.toml --redact --no-banner .
else
  gitleaks dir --config .gitleaks.toml --redact --no-banner .
fi

if have trivy; then
  trivy filesystem --exit-code 1 --severity CRITICAL,HIGH --no-progress .
  trivy config --exit-code 1 --severity CRITICAL,HIGH --no-progress .
else
  warn "trivy is unavailable; vulnerability and IaC scans skipped"
fi

info "secret scan completed"
