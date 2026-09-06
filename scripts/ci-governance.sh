#!/bin/sh
set -eu
# shellcheck source=./scripts/lib.sh
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

require ruby
ruby scripts/validate-architecture.rb
ruby -Itest tests/architecture_validator_test.rb
ruby -Itest tests/ci_authority_test.rb
ruby -Itest tests/ci_affected_test.rb
info "governance checks completed"
