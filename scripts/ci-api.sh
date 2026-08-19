#!/bin/sh
set -eu
# shellcheck source=scripts/lib.sh
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

api_tests=$(find tests -type f \( -name '*api*test*' -o -name '*contract*test*' \) -print 2>/dev/null || true)
openapi_files=$(find . -type f \( -iname 'openapi*.yaml' -o -iname 'openapi*.yml' -o -iname 'openapi*.json' \) -not -path './vendor/*' -print 2>/dev/null || true)

if [ -z "$api_tests" ] && [ -z "$openapi_files" ]; then
  info "no API contracts or API tests found; API checks skipped"
  exit 0
fi

if [ -n "$openapi_files" ]; then
  if have spectral; then
    printf '%s\n' "$openapi_files" | while IFS= read -r specification; do
      spectral lint "$specification"
    done
  else
    warn "OpenAPI files exist but spectral is unavailable; schema lint skipped"
  fi
fi

info "API test inventory validated"
