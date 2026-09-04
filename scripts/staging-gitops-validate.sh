#!/bin/sh
set -eu

# shellcheck disable=SC1091
. "$(dirname "$0")/lib.sh"

cd "$(repo_root)"
ansible_config_path=$(pwd)/ansible.cfg
export ANSIBLE_CONFIG="$ansible_config_path"
require ansible-playbook
exec ansible-playbook \
  -i infrastructure/ansible/inventory/staging.yml \
  infrastructure/ansible/staging-gitops-validate.yml
