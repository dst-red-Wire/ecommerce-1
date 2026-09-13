# M1 qualification Terraform handoff

This independent state root declares two disposable Ubuntu 24.04 x86_64
servers, one network/subnet, and two firewalls: a private-only qualification
runner and a dedicated public Squid/SSH gateway. The subnet and the distinct
gateway/runner addresses are derived from the single
`qualification_network_cidr`; the subnet network zone is provider metadata for
the selected `hcloud_location`. The default `10.248.0.0/24` remains separate
from PREPROD, PROD, MGMT, Kubernetes, storage, and backup networks.

The runner has no public IPv4 or IPv6. Its provider firewall permits outbound
TCP only to gateway port 3128 and inbound SSH only from the gateway private
identity. Runner-local proxy settings are configuration, never the security
boundary: root-equivalent PR code cannot create a direct public or DNS bypass.
The gateway's public SSH is restricted to `qualification_ssh_allowed_cidrs`;
Squid is accepted only from the runner `/32`.

## Audited destination policy

The trusted controller's `qualification_gateway` role installs and holds the
exact Squid version from the immutable Ubuntu snapshot, validates its committed
configuration, enables the service, and verifies package/service state. The
policy denies by default, limits HTTP to 80/443, limits CONNECT to 443, and does
not accept destination IP literals as hostname matches.

All entries are TCP 443 except the same named Ubuntu endpoint may use TCP 80
while apt negotiates package access:

| Destination | Owner | Reason |
| --- | --- | --- |
| `snapshot.ubuntu.com` | gateway/runner apt | immutable Ubuntu package snapshot |
| `github.com`, `api.github.com` | Git/gh | source clone/fetch and GitHub API |
| `objects.githubusercontent.com`, `release-assets.githubusercontent.com` | GitHub releases | pinned repository-managed release assets |
| `pypi.org`, `files.pythonhosted.org` | `make seed`/pip | hash-locked Python seed packages and files |
| `proxy.golang.org`, `sum.golang.org` | Go | module archive and checksum verification |
| `go.dev`, `dl.google.com`, `storage.googleapis.com` | developer toolchain | official pinned Go archive and redirects |
| `nodejs.org`, `registry.npmjs.org` | frontend bootstrap | pinned Node archive and pnpm packages |
| `get.helm.sh` | developer toolchain | pinned Helm archive |
| `releases.hashicorp.com` | developer toolchain | pinned Terraform archive |
| `dl.k8s.io` | developer toolchain | pinned kubectl binary |
| `registry-1.docker.io`, `auth.docker.io`, `production.cloudflare.docker.com` | Docker/Testcontainers | registry authentication, manifests, layers, and PostgreSQL image |

## Trusted two-hop SSH enrollment and provisioning

After a separately authorized apply, record the non-secret Terraform outputs
for gateway public address/user, runner private address/user, ProxyJump, and
both inventory lines. Obtain each server's ED25519 SHA256 fingerprint from the
provider console or another authenticated out-of-band source. Never use the
scan itself as the trust authority and never place a private key, token, or
fabricated fingerprint in Terraform.

The following operator procedure first verifies the public gateway, then uses
only that verified gateway to scan and independently verify the private runner:

```text
set -euo pipefail
export QUALIFICATION_GATEWAY_HOST=replace-from-qualification_gateway_ipv4
export QUALIFICATION_GATEWAY_USER=replace-from-qualification_gateway_user
export QUALIFICATION_GATEWAY_FINGERPRINT=SHA256:replace-from-oob-source
export QUALIFICATION_RUNNER_HOST=replace-from-qualification_runner_private_ipv4
export QUALIFICATION_RUNNER_FINGERPRINT=SHA256:replace-from-oob-source
export QUALIFICATION_KNOWN_HOSTS="$HOME/.ssh/qualification_known_hosts"
case "$QUALIFICATION_GATEWAY_HOST:$QUALIFICATION_RUNNER_HOST" in *[!0-9a-fA-F.:]*) exit 1 ;; esac

gateway_key="$(mktemp)"
runner_key="$(mktemp)"
staged_known_hosts="$(mktemp)"
trap 'rm -f "$gateway_key" "$runner_key" "$staged_known_hosts"' EXIT
ssh-keyscan -t ed25519 "$QUALIFICATION_GATEWAY_HOST" > "$gateway_key"
test "$(wc -l < "$gateway_key")" -eq 1
test "$(ssh-keygen -lf "$gateway_key" -E sha256 | awk '{print $2}')" = "$QUALIFICATION_GATEWAY_FINGERPRINT"
ssh-keygen -H -f "$gateway_key"
mv "$gateway_key" "$staged_known_hosts"

ssh -o UserKnownHostsFile="$staged_known_hosts" -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no -o ClearAllForwardings=yes \
  "$QUALIFICATION_GATEWAY_USER@$QUALIFICATION_GATEWAY_HOST" \
  "ssh-keyscan -t ed25519 '$QUALIFICATION_RUNNER_HOST'" > "$runner_key"
test "$(wc -l < "$runner_key")" -eq 1
test "$(ssh-keygen -lf "$runner_key" -E sha256 | awk '{print $2}')" = "$QUALIFICATION_RUNNER_FINGERPRINT"
ssh-keygen -H -f "$runner_key"
cat "$runner_key" >> "$staged_known_hosts"
mkdir -p "$(dirname "$QUALIFICATION_KNOWN_HOSTS")"
chmod 0700 "$(dirname "$QUALIFICATION_KNOWN_HOSTS")"
chmod 0600 "$staged_known_hosts"
mv "$staged_known_hosts" "$QUALIFICATION_KNOWN_HOSTS"

export ANSIBLE_HOST_KEY_CHECKING=True
export ANSIBLE_SSH_ARGS="-o UserKnownHostsFile=$QUALIFICATION_KNOWN_HOSTS -o StrictHostKeyChecking=yes -o ForwardAgent=no -o ClearAllForwardings=yes"
ansible-playbook -i /secure/path/qualification.ini platform/ansible/qualification-egress.yml
ansible-playbook -i /secure/path/qualification.ini platform/ansible/qualification-runner.yml
```

The inventory must contain groups `qualification_gateways` and
`qualification_runners`, populated from the two Terraform inventory outputs.
The required order is Terraform static topology, minimal gateway account,
trusted gateway reconciliation, runner proxy-client reconciliation, canonical
`qualification-runner.yml`, and finally the PR #77 qualification. The canonical
#78 files remain unchanged.

Static validation is not apply authorization. Apply, destroy, and every real
provider mutation require a separate human-authorized runtime task.
