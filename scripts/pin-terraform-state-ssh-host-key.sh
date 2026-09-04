#!/bin/sh
set -eu

# Future controlled TOFU gate. The expected fingerprint must first be obtained
# independently through the Hetzner Console, never through this SSH path.
# shellcheck disable=SC1091
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

require awk
require install
require jq
require realpath
require ssh-keygen
require ssh-keyscan

: "${TERRAFORM_STATE_SSH_HOST_KEY_FINGERPRINT:?TERRAFORM_STATE_SSH_HOST_KEY_FINGERPRINT is required}"
: "${TERRAFORM_STATE_KNOWN_HOSTS:?TERRAFORM_STATE_KNOWN_HOSTS is required}"
case "$TERRAFORM_STATE_SSH_HOST_KEY_FINGERPRINT" in
  SHA256:*) ;;
  *) fail "expected SSH host key fingerprint must use SHA256:<base64> format" ;;
esac
fingerprint_payload=${TERRAFORM_STATE_SSH_HOST_KEY_FINGERPRINT#SHA256:}
case "$fingerprint_payload" in
  '' | *[!A-Za-z0-9+/=]*) fail "expected SSH host key fingerprint contains invalid base64 characters" ;;
esac
case "$TERRAFORM_STATE_KNOWN_HOSTS" in
  /*) ;;
  *) fail "TERRAFORM_STATE_KNOWN_HOSTS must use an absolute WSL path" ;;
esac
case "$TERRAFORM_STATE_KNOWN_HOSTS" in
  *[!A-Za-z0-9._/-]*) fail "TERRAFORM_STATE_KNOWN_HOSTS must use a shell-safe path" ;;
esac

repository=$(pwd -P)
known_hosts=$(realpath -m "$TERRAFORM_STATE_KNOWN_HOSTS")
case "$known_hosts" in
  "$repository" | "$repository"/* | /mnt/c/Users/*/OneDrive/*)
    fail "dedicated known_hosts must remain outside the repository and OneDrive"
    ;;
esac
[ ! -e "$known_hosts" ] || fail "dedicated known_hosts already exists; preserve it and review key rotation separately"

work_directory=$(mktemp -d)
contract=$work_directory/inventory-contract.json
candidate=$work_directory/known_hosts.candidate
cleanup() {
  rm -f "$contract" "$candidate"
  rmdir "$work_directory" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

./scripts/terraform-state-bootstrap-state.sh output-inventory >"$contract"
server_ipv4=$(jq -er '.server_ipv4 | select(type == "string")' "$contract") ||
  fail "authoritative inventory contract has no server IPv4"

ssh-keyscan -T 10 -t ed25519 "$server_ipv4" >"$candidate" 2>/dev/null ||
  fail "unable to retrieve the future server Ed25519 host key"
[ "$(awk 'NF >= 3 && $1 !~ /^#/ { count += 1 } END { print count + 0 }' "$candidate")" -eq 1 ] ||
  fail "SSH scan must return exactly one Ed25519 host key"
observed_fingerprint=$(ssh-keygen -lf "$candidate" -E sha256 | awk 'NR == 1 { print $2 }')
[ "$observed_fingerprint" = "$TERRAFORM_STATE_SSH_HOST_KEY_FINGERPRINT" ] ||
  fail "SSH host key differs from the independently verified fingerprint"

known_hosts_directory=$(dirname "$known_hosts")
mkdir -p "$known_hosts_directory"
chmod 0700 "$known_hosts_directory"
install -m 0600 "$candidate" "$known_hosts"
info "dedicated Terraform state SSH host key pinned after independent fingerprint match"

trap - EXIT HUP INT TERM
cleanup
