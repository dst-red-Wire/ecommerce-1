#!/bin/sh
set -eu
# shellcheck source=./scripts/lib.sh
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

require ruby
ruby scripts/validate-architecture.rb
info "governance checks completed"
