#!/bin/sh
set -eu
# shellcheck disable=SC1091
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"
ansible_config_path="$(pwd)/ansible.cfg"
export ANSIBLE_CONFIG="$ansible_config_path"

scope=${1:-all}
case "$scope" in
  all)
    ansible_files=$(find platform/ansible platform/bootstrap -type f \( -name '*.yml' -o -name '*.yaml' \) -print 2>/dev/null || true)
    infrastructure_playbooks=$(find infrastructure/ansible -maxdepth 1 -type f \( -name '*.yml' -o -name '*.yaml' \) -print 2>/dev/null || true)
    ansible_files="$ansible_files
$infrastructure_playbooks"
    [ -f local-devsecops.yml ] && ansible_files="local-devsecops.yml
$ansible_files"
    ;;
  management)
    ansible_files=infrastructure/ansible/management.yml
    ;;
  terraform-state)
    ansible_files=infrastructure/ansible/terraform-state.yml
    ;;
  *) fail "unsupported Ansible validation scope: $scope" ;;
esac
if [ -z "$ansible_files" ]; then
  info "no Ansible files found; validation skipped"
  exit 0
fi

if [ -n "${ANSIBLE_TOOLING_VENV:-}" ]; then
  tooling_python="$ANSIBLE_TOOLING_VENV/bin/python"
  ansible_lint="$ANSIBLE_TOOLING_VENV/bin/ansible-lint"
  ansible_playbook="$ANSIBLE_TOOLING_VENV/bin/ansible-playbook"
  if [ ! -x "$tooling_python" ] || [ ! -x "$ansible_lint" ] || [ ! -x "$ansible_playbook" ]; then
    fail "pinned Ansible tooling is not prepared; run: python3 -m venv .venv && .venv/bin/python -m pip install -r requirements/ansible.txt"
  fi
  "$tooling_python" scripts/validate-ansible-tooling.py
else
  require ansible-lint
  require ansible-playbook
  ansible_lint=ansible-lint
  ansible_playbook=ansible-playbook
fi

printf '%s\n' "$ansible_files" | while IFS= read -r playbook; do
  case "$playbook" in
    *tasks/*) continue ;;
  esac
  info "syntax-checking $playbook"
  case "$scope" in
    management)
      "$ansible_playbook" -i infrastructure/ansible/inventory/management.example.yml \
        --syntax-check "$playbook"
      ;;
    terraform-state)
      "$ansible_playbook" -i infrastructure/ansible/inventory/terraform-state.example.yml \
        --syntax-check "$playbook"
      ;;
    *) "$ansible_playbook" --syntax-check "$playbook" ;;
  esac
done

# Word splitting is intentional: find emits repository-controlled paths.
# shellcheck disable=SC2086
"$ansible_lint" $ansible_files
