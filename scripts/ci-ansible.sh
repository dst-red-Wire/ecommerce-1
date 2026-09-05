#!/bin/sh
set -eu
# shellcheck source=./scripts/lib.sh
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

ansible_files=$(find platform/ansible -type f \( -name '*.yml' -o -name '*.yaml' \) -print 2>/dev/null || true)
if [ -z "$ansible_files" ]; then
  info "no Ansible files found; validation skipped"
  exit 0
fi

require ansible-lint
# Word splitting is intentional: find emits repository-controlled paths.
# shellcheck disable=SC2086
ansible-lint $ansible_files
