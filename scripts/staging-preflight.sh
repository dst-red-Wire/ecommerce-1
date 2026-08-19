#!/bin/sh
set -eu

# shellcheck disable=SC1091
. "$(dirname "$0")/lib.sh"

cd "$(repo_root)"
ansible_config_path=$(pwd)/ansible.cfg
export ANSIBLE_CONFIG="$ansible_config_path"

require ansible-playbook
require terraform

info "syntax-checking staging playbooks"
ansible-playbook --syntax-check infrastructure/ansible/staging-preflight.yml
ansible-playbook --syntax-check infrastructure/ansible/staging-devsecops.yml
ansible-playbook --syntax-check infrastructure/ansible/staging-status.yml

if have ansible-lint; then
  info "running ansible-lint on staging sources"
  ansible-lint infrastructure/ansible/staging-preflight.yml \
    infrastructure/ansible/staging-devsecops.yml \
    infrastructure/ansible/staging-status.yml \
    infrastructure/ansible/roles infrastructure/ansible/tasks
else
  warn "ansible-lint unavailable; Ansible lint skipped"
fi

info "checking Terraform formatting and validation"
terraform fmt -check -recursive -diff
terraform -chdir=infrastructure/hetzner/staging validate

info "checking whitespace and remote preflight"
git diff --check
ansible-playbook \
  -i infrastructure/ansible/inventory/staging.yml \
  infrastructure/ansible/staging-preflight.yml

info "staging preflight completed without an infrastructure mutation"
