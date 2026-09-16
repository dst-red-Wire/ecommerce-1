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
| `registry-1.docker.io`, `auth.docker.io`, `production.cloudflare.docker.com` | Docker/Testcontainers | registry authentication, manifests, and legacy layer delivery |
| `docker-images-prod.6aa30f8b08e16409b46e0173d6de2f56.r2.cloudflarestorage.com` | Docker Hub image layer delivery | mandatory PostgreSQL Testcontainers image pull over HTTPS (TCP 443) |

## Trusted two-hop SSH enrollment and provisioning

Follow the [trusted controller admission policy](../../../../docs/project/M1_LINUX_QUALIFICATION_RUNNER.md#trusted-controller-admission).
Run the block below in a fresh controller shell: it selects and admits the immutable
head/base pair once for this two-hop procedure.
Use a separate clean `/trusted/ecommerce` checkout pinned to an independently
reviewed full `TRUSTED_RUNNER_REVISION`, selected outside PR-owned configuration.
The guard, Ansible configuration, collections, roles and both playbooks below
must come from that trusted checkout, never the candidate or a consumed runner.
Keep the candidate in a separate controller-owned checkout and repeat admission
when retaining the final evidence.

Before any separately authorized Terraform plan or apply, use the same independently
reviewed `/trusted/ecommerce` checkout for both
`platform/terraform/environments/qualification` and its local
`platform/terraform/modules/hcloud-qualification` module. Complete the external
admission below first; its exact-byte scope includes both Terraform directories.
Never plan or apply candidate-owned Terraform or execute its validation scripts on
the credentialed controller. The admission step is not apply authorization.

After a separately authorized apply of that trusted Terraform, record the non-secret Terraform outputs
for gateway public address/user, runner private address/user, ProxyJump, and
both inventory lines. Obtain each server's ED25519 SHA256 fingerprint from the
provider console or another authenticated out-of-band source. Never use the
scan itself as the trust authority and never place a private key, token, or
fabricated fingerprint in Terraform.

The following operator procedure first verifies the public gateway, then uses
only that verified gateway to scan and independently verify the private runner:

```text
set -euo pipefail
cd /trusted/ecommerce
readonly QUALIFICATION_HEAD=FULL_HEAD_SHA QUALIFICATION_BASE=FULL_BASE_SHA
python3 -I scripts/qualification_runner_guard.py --repo /candidate/ecommerce --base "$QUALIFICATION_BASE" --head "$QUALIFICATION_HEAD"
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

ssh -o UserKnownHostsFile="$staged_known_hosts" -o GlobalKnownHostsFile=/dev/null \
  -o KnownHostsCommand=none \
  -o StrictHostKeyChecking=yes \
  -o HostKeyAlias="$QUALIFICATION_GATEWAY_HOST" \
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
export ANSIBLE_SSH_ARGS="-o UserKnownHostsFile=$QUALIFICATION_KNOWN_HOSTS -o GlobalKnownHostsFile=/dev/null -o KnownHostsCommand=none -o StrictHostKeyChecking=yes -o ForwardAgent=no -o ClearAllForwardings=yes"
ansible-playbook -i /secure/path/qualification.ini platform/ansible/qualification-egress.yml
ansible-playbook -i /secure/path/qualification.ini platform/ansible/qualification-runner.yml \
    --extra-vars "qualification_pr_head=$QUALIFICATION_HEAD qualification_pr_base=$QUALIFICATION_BASE"
```

Only after both independently verified keys have been enrolled above, run the
final Product and repository proof on the private runner through the verified
gateway. Populate these values from `qualification_gateway_ipv4`,
`qualification_gateway_user`, `qualification_runner_private_ipv4`, and
`qualification_user`; use the same dedicated known-hosts file enrolled above:

```text
export GATEWAY_HOST="$QUALIFICATION_GATEWAY_HOST"
export GATEWAY_USER="$QUALIFICATION_GATEWAY_USER"
export RUNNER_PRIVATE_HOST="$QUALIFICATION_RUNNER_HOST"
export QUALIFICATION_USER=replace-from-qualification_user
ssh \
  -o UserKnownHostsFile="$QUALIFICATION_KNOWN_HOSTS" \
  -o GlobalKnownHostsFile=/dev/null \
  -o KnownHostsCommand=none \
  -o StrictHostKeyChecking=yes \
  -o HostKeyAlias="$RUNNER_PRIVATE_HOST" \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  -o ProxyCommand="ssh -o UserKnownHostsFile=$QUALIFICATION_KNOWN_HOSTS -o GlobalKnownHostsFile=/dev/null -o KnownHostsCommand=none -o StrictHostKeyChecking=yes -o HostKeyAlias=$GATEWAY_HOST -o ForwardAgent=no -o ClearAllForwardings=yes -l $GATEWAY_USER -W %h:%p $GATEWAY_HOST" \
  "${QUALIFICATION_USER}@${RUNNER_PRIVATE_HOST}" \
  "bash -se -- $QUALIFICATION_HEAD $QUALIFICATION_BASE" <<'QUALIFICATION_RUNNER'
set -euo pipefail
readonly qualification_head="$1" qualification_base="$2"
export GIT_NO_REPLACE_OBJECTS=1
readonly GIT_NO_REPLACE_OBJECTS
whoami
hostname
uname -a
docker version
docker info
sysctl -n net.ipv4.ip_forward

cd "$HOME/ecommerce-1"
git --no-replace-objects fetch origin \
  "$qualification_head" \
  "$qualification_base"
git --no-replace-objects checkout --detach "$qualification_head"
test "$(git --no-replace-objects rev-parse HEAD)" = "$qualification_head"
worktree_status="$(git --no-replace-objects status --porcelain=v1)"
printf '%s' "$worktree_status"
test -z "$worktree_status"
test -z "$(git --no-replace-objects for-each-ref --format='%(refname)' refs/replace/)"
make seed
make bootstrap
make env-check
test -z "$(git --no-replace-objects for-each-ref --format='%(refname)' refs/replace/)"
test "$(git --no-replace-objects rev-parse HEAD)" = "$qualification_head"
post_bootstrap_status="$(git --no-replace-objects status --porcelain=v1)"
printf '%s' "$post_bootstrap_status"
test -z "$post_bootstrap_status"
test "$(sysctl -n net.ipv4.ip_forward)" = "1"
cd services/product
$HOME/.local/bin/go test -race -tags=integration ./internal/infrastructure/postgres -count=1
cd ../..
BASE="$qualification_base" make ci
QUALIFICATION_RUNNER
```

The explicit `ProxyCommand` binds the gateway connection to the same dedicated
known-hosts file and strict policy as the outer runner connection. Each hop
also sets `GlobalKnownHostsFile=/dev/null`, disables `KnownHostsCommand`, and
names its exact enrolled address through `HostKeyAlias`; the dedicated
qualification file is therefore the only host-key trust source, with no
global-store, configured-command, or agent-forwarding fallback.

The inventory must contain groups `qualification_gateways` and
`qualification_runners`, populated from the two Terraform inventory outputs.
The required order is Terraform static topology, minimal gateway account,
trusted gateway reconciliation, runner proxy-client reconciliation, canonical
`qualification-runner.yml`, and finally the PR #77 qualification. The canonical
#78 files remain unchanged.

Static validation is not apply authorization. Apply, destroy, and every real
provider mutation require a separate human-authorized runtime task.
