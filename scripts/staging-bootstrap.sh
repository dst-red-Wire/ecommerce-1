#!/bin/sh
set -eu

# shellcheck disable=SC1091
. "$(dirname "$0")/lib.sh"

cd "$(repo_root)"
ansible_config_path=$(pwd)/ansible.cfg
export ANSIBLE_CONFIG="$ansible_config_path"
require ansible-playbook

if [ "${STAGING_INSTALL_OBSERVABILITY:-1}" = "0" ]; then
  info "starting staging bootstrap with observability disabled by explicit override"
  exec ansible-playbook \
    -i infrastructure/ansible/inventory/staging.yml \
    infrastructure/ansible/staging-devsecops.yml \
    -e staging_install_observability=false
fi

info "starting staged bootstrap: Docker, Kind, Cilium, Flux, Tekton, Kyverno, Tetragon, observability"
exec ansible-playbook \
  -i infrastructure/ansible/inventory/staging.yml \
  infrastructure/ansible/staging-devsecops.yml
