#!/bin/sh
set -eu

# Static/local validation only. No plan, apply, SSH or remote API operation is
# performed by this entry point.
# shellcheck disable=SC1091
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

require python3
require sha256sum
require terraform

python3 scripts/validate-hetzner-s3-backend.py
python3 scripts/validate-terraform-pg-backend.py
python3 scripts/validate-management-foundation.py
./scripts/test-terraform-pg-blockers.sh

terraform fmt -check -recursive \
  infrastructure/hetzner/bootstrap/object-storage \
  infrastructure/hetzner/bootstrap/terraform-state \
  infrastructure/hetzner/management

terraform_data_root=$(mktemp -d)
cleanup_terraform_data() {
  rm -rf "$terraform_data_root"
}
trap cleanup_terraform_data EXIT HUP INT TERM

roots='infrastructure/hetzner/bootstrap/object-storage
infrastructure/hetzner/bootstrap/object-storage/lock-runtime-test
infrastructure/hetzner/bootstrap/terraform-state
infrastructure/hetzner/bootstrap/terraform-state/lock-runtime-test
infrastructure/hetzner/management'
printf '%s\n' "$roots" | while IFS= read -r terraform_root; do
  root_id=$(printf '%s' "$terraform_root" | sha256sum | awk '{print $1}')
  root_data=$terraform_data_root/$root_id
  mkdir -p "$root_data"
  info "validating $terraform_root without backend activation"
  TF_DATA_DIR="$root_data" terraform -chdir="$terraform_root" init \
    -backend=false -input=false >/dev/null
  TF_DATA_DIR="$root_data" terraform -chdir="$terraform_root" validate
  case "$terraform_root" in
    */lock-runtime-test)
      info "terraform providers skipped for backend-only runtime probe (no external provider)"
      ;;
    infrastructure/hetzner/management)
      provider_view=$terraform_data_root/management-provider-view
      provider_view_data=$terraform_data_root/management-provider-data
      mkdir -p "$provider_view" "$provider_view_data"
      for terraform_file in "$terraform_root"/*.tf; do
        [ "$(basename "$terraform_file")" = backend.tf ] ||
          cp "$terraform_file" "$provider_view/"
      done
      TF_DATA_DIR="$provider_view_data" terraform -chdir="$provider_view" init \
        -backend=false -input=false >/dev/null
      TF_DATA_DIR="$provider_view_data" terraform -chdir="$provider_view" providers
      ;;
    *) TF_DATA_DIR="$root_data" terraform -chdir="$terraform_root" providers ;;
  esac
done

ANSIBLE_TOOLING_VENV=${ANSIBLE_TOOLING_VENV:-"$(pwd)/.venv"}
export ANSIBLE_TOOLING_VENV
./scripts/ci-ansible.sh management
./scripts/ci-ansible.sh terraform-state

info "management and Terraform pg backend foundations are statically valid"
