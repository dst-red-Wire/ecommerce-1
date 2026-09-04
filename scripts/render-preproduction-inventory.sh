#!/bin/sh
set -eu

# shellcheck disable=SC1091
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

require terraform
require jq
require yq

terraform_root=infrastructure/hetzner/preproduction
[ -d "$terraform_root/.terraform" ] || \
  fail "preproduction Terraform is not initialized; inventory rendering is NOT PROVEN"

contract=$(terraform -chdir="$terraform_root" output -json inventory_contract 2>/dev/null) || \
  fail "preproduction state/output is unavailable; inventory rendering is NOT PROVEN"
printf '%s\n' "$contract" | jq -e '
  (.campaign.id | length > 0) and
  (.campaign.owner | length > 0) and
  (.campaign.expires_at | length > 0) and
  (.campaign.cost_center | length > 0) and
  (.api_endpoint | endswith(":6443")) and
  (.control_planes | length >= 3) and
  (.workers | length >= 2)
' >/dev/null || fail "incomplete preproduction inventory contract"

printf '%s\n' "$contract" | jq -S '
  {
    all: {
      children: {
        preproduction: {
          children: {
            kube_control_plane: {hosts: .control_planes},
            kube_workers: {hosts: .workers}
          }
        }
      },
      vars: {
        preproduction_api_endpoint: .api_endpoint,
        preproduction_api_private_ipv4: .api_private_ipv4,
        preproduction_campaign_id: .campaign.id,
        preproduction_owner: .campaign.owner,
        preproduction_expires_at: .campaign.expires_at,
        preproduction_cost_center: .campaign.cost_center,
        preproduction_bootstrap_status: "NOT_PROVEN"
      }
    }
  }
' | yq -P
