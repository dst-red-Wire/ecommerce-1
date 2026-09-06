#!/bin/sh
set -eu
# shellcheck source=./scripts/lib.sh
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

require ruby
ruby scripts/validate-openapi.rb
ruby -Itest tests/openapi_validator_test.rb
info "OpenAPI contract checks completed"
