#!/bin/sh
set -eu
# shellcheck source=./scripts/lib.sh
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

require gitleaks
if git rev-parse --verify HEAD >/dev/null 2>&1; then
  gitleaks git --config .gitleaks.toml --redact --no-banner .
else
  gitleaks dir --config .gitleaks.toml --redact --no-banner .
fi
info "secret scan completed"
