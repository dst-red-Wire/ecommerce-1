#!/bin/sh
set -eu
# shellcheck source=scripts/lib.sh
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"
ansible_config_path="$(pwd)/ansible.cfg"
export ANSIBLE_CONFIG="$ansible_config_path"

ansible_files=$(find platform/ansible platform/bootstrap -type f \( -name '*.yml' -o -name '*.yaml' \) -print 2>/dev/null || true)
[ -f local-devsecops.yml ] && ansible_files="local-devsecops.yml
$ansible_files"
if [ -z "$ansible_files" ]; then
  info "no Ansible files found; validation skipped"
  exit 0
fi

require ansible-lint
require ansible-playbook

printf '%s\n' "$ansible_files" | while IFS= read -r playbook; do
  case "$playbook" in
    *tasks/*) continue ;;
  esac
  info "syntax-checking $playbook"
  ansible-playbook --syntax-check "$playbook"
done

# Word splitting is intentional: find emits repository-controlled paths.
# shellcheck disable=SC2086
ansible-lint $ansible_files
