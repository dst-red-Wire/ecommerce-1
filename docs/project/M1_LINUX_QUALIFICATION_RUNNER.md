# M1 Linux qualification runner

Status: `TEMPORARY — M1 PROOF ONLY`

This provider-neutral host definition closes the Product integration proof; it is not the
M4 Tekton runner. The host/platform owns Ubuntu, Docker Engine and its socket, non-root
daemon access, base packages, and persistent kernel configuration. The checked-out PR owns
its hash-locked Python/Ansible seed and managed qualification toolchain; the provisioning
playbook reconciles both on the runner before proof execution.

## Trusted controller admission

The controller must use a separate clean checkout at an independently reviewed, full
`TRUSTED_RUNNER_REVISION` SHA. Select that revision through review policy, never from
PR-owned configuration or output. Both the guard and the Ansible execution closure
come from that trusted checkout. Do not run candidate Python, Make, bootstrap, Ansible
configuration, inventory, roles or plugins on the controller.

Select the full head and base once in the same controller shell used for provisioning
and evidence collection. Keep these variables readonly. Before provisioning, use the
trusted system Python to execute:

```text
set -euo pipefail
readonly QUALIFICATION_HEAD=FULL_HEAD_SHA QUALIFICATION_BASE=FULL_BASE_SHA
python3 -I /trusted/ecommerce/scripts/qualification_runner_guard.py --repo /candidate/ecommerce --base "$QUALIFICATION_BASE" --head "$QUALIFICATION_HEAD"
```

`/candidate/ecommerce` is a clean controller-owned checkout fetched from the forge,
not a checkout or evidence file copied back from a tainted runner. The guard compares
real Git objects with replacement refs disabled, rejects replacement refs, and permits
only independently reviewed byte changes. Its source and allowlist are those in the
trusted checkout; a candidate copy cannot grant itself permission. A guard change
requires a separately reviewed trusted-controller revision before use.

Run the provisioning commands below with `/trusted/ecommerce` as the working directory,
using its pinned toolchain and external inventory. Repeat this trusted admission check
when retaining qualification evidence. PR-owned `make ci` remains a regression check,
not independent authentication of runner changes or remote CI provenance.

## Provision a clean host

One runner instance is valid for exactly one qualification attempt. Supply a fresh,
never-used Ubuntu 24.04 x86_64 VM on which no PR-owned code has previously executed, with
systemd, SSH/root escalation, the image's base
Python 3 interpreter (required for Ansible fact gathering), outbound access to the Ubuntu
snapshot service, and an existing regular non-root qualification account with non-interactive
sudo (the repository bootstrap reconciles OS packages through Ansible). Copy
`platform/ansible/inventories/qualification.example.ini` outside the repository, replace
the example address, and invoke the playbook from a trusted controller with the repository's
pinned Ansible Core. Set the host name and canonical SHA256 fingerprint obtained from the
provider console (or another authenticated, out-of-band channel), then verify and enroll exactly
one ED25519 candidate key before Ansible is allowed to connect:

Because PR-owned code receives passwordless sudo and Docker-root-equivalent access, execution
taints the entire host, not merely the Git worktree. A clean `git status` cannot establish safe
reuse: hooks, Git configuration, Docker state, root-owned state, and caches may have changed.
The playbook rejects an existing checkout or consumed marker and marks the instance consumed
before PR-owned bootstrap begins. Regardless of success or failure, retain external evidence,
then destroy the VM. A retry requires a newly provisioned runner instance; never scrub or reuse
the old instance.

The disposable host must have no cloud instance role; no AWS-, GCP-, Azure-, Hetzner-, or other
managed-identity or metadata-service credentials; no mounted provider secrets; and no
CI/controller credentials copied onto it. It must have no access to internal credential-bearing
services. Place it on an isolated, least-egress qualification network that permits only the
public package, source, and container endpoints required by this proof. These are host/network
admission requirements, not properties entrusted to untrusted PR code.

```text
set -euo pipefail
export QUALIFICATION_HOST=qualification.example.invalid
export QUALIFICATION_HOST_FINGERPRINT=SHA256:replace-with-out-of-band-value

candidate_key="$(mktemp)"
trap 'rm -f "$candidate_key" "${staged_known_hosts:-}"' EXIT
case "$QUALIFICATION_HOST" in -*) exit 1 ;; esac
ssh-keyscan -H -t ed25519 "$QUALIFICATION_HOST" > "$candidate_key"
test "$(wc -l < "$candidate_key")" -eq 1
test "$(awk '{print $2}' "$candidate_key")" = ssh-ed25519
candidate_fingerprint="$(ssh-keygen -lf "$candidate_key" -E sha256 | awk '{print $2}')"
test "$candidate_fingerprint" = "$QUALIFICATION_HOST_FINGERPRINT"

mkdir -p ~/.ssh
chmod 0700 ~/.ssh
export QUALIFICATION_KNOWN_HOSTS="$HOME/.ssh/qualification_known_hosts"
staged_known_hosts="$(mktemp ~/.ssh/qualification_known_hosts.XXXXXX)"
cat "$candidate_key" > "$staged_known_hosts"
chmod 0600 "$staged_known_hosts"
mv "$staged_known_hosts" "$QUALIFICATION_KNOWN_HOSTS"
ANSIBLE_HOST_KEY_CHECKING=True \
  ANSIBLE_SSH_ARGS="-o UserKnownHostsFile=$QUALIFICATION_KNOWN_HOSTS -o StrictHostKeyChecking=yes -o HostKeyAlias=$QUALIFICATION_HOST -o ForwardAgent=no -o ClearAllForwardings=yes" \
  ansible-playbook -i /secure/path/qualification.ini platform/ansible/qualification-runner.yml \
    --extra-vars "qualification_pr_head=$QUALIFICATION_HEAD qualification_pr_base=$QUALIFICATION_BASE"
```

Never trust an unverified `ssh-keyscan` result: obtain the host-key fingerprint through the
VM provider console or another authenticated, out-of-band channel before enrollment. The
repository keeps host-key checking enabled. The role intentionally requires Python 3 in the
base image because Ansible cannot install its own remote interpreter after fact gathering.

The role configures a timestamped Ubuntu archive snapshot, installs and holds exact package
versions (including Ruby and the C toolchain), enables Docker across reboot, grants
only the named account normal Docker socket access, and persists
`net.ipv4.ip_forward=1` in `/etc/sysctl.d/60-ecommerce-m1-qualification.conf`. Docker group
membership and passwordless sudo are root-equivalent; use a dedicated ephemeral qualification
account and destroy the host after evidence is retained.

On Ubuntu 24.04, the role installs the snapshot-pinned AppArmor package and loads
`/etc/apparmor.d/ecommerce-qualification-python`. This profile permits `userns` for
`/usr/bin/python3.12`, the canonical interpreter used by qualification virtualenvs.
It preserves the system-wide unprivileged-user-namespace restriction; it does not
disable AppArmor. Before repository bootstrap, a non-root isolated Python probe
must create the private user, mount and PID namespaces used by parallel gates.
A denied capability stops provisioning. This host prerequisite does not establish
trusted execution provenance after root-equivalent candidate code has run.

## Qualify the admitted immutable head

Record the live PR head and base before provisioning. The playbook reconciles the exact checkout
and repository bootstrap through Ansible. The controller must then initiate the following SSH
session as the same non-root qualification account named by `qualification_user`; every command
inside the quoted heredoc runs on that exact runner, not on the controller. For the audited head,
the runner clones normally and then detaches at the immutable object:

```text
# This must exactly match qualification_user in /secure/path/qualification.ini.
export QUALIFICATION_USER=ubuntu
ssh -o UserKnownHostsFile="$QUALIFICATION_KNOWN_HOSTS" -o StrictHostKeyChecking=yes \
  -o HostKeyAlias="$QUALIFICATION_HOST" -o ForwardAgent=no -o ClearAllForwardings=yes \
  "$QUALIFICATION_USER@$QUALIFICATION_HOST" "bash -se -- $QUALIFICATION_HEAD $QUALIFICATION_BASE" <<'QUALIFICATION_RUNNER'
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

if ! test -d "$HOME/ecommerce-1/.git"; then
  git --no-replace-objects clone https://github.com/dst-red-Wire/ecommerce-1.git "$HOME/ecommerce-1"
fi
cd "$HOME/ecommerce-1"
git --no-replace-objects fetch origin \
  "$qualification_head" \
  "$qualification_base"
git --no-replace-objects checkout --detach "$qualification_head"
git --no-replace-objects rev-parse HEAD
test "$(git --no-replace-objects rev-parse HEAD)" = "$qualification_head"
worktree_status="$(git --no-replace-objects status --porcelain=v1)"
printf '%s' "$worktree_status"
test -z "$worktree_status"
test -z "$(git --no-replace-objects for-each-ref --format='%(refname)' refs/replace/)"
make seed
make bootstrap
make env-check
test -z "$(git --no-replace-objects for-each-ref --format='%(refname)' refs/replace/)"
# Bootstrap is PR-owned and must not change either the qualified commit or worktree.
test "$(git --no-replace-objects rev-parse HEAD)" = "$qualification_head"
post_bootstrap_status="$(git --no-replace-objects status --porcelain=v1)"
printf '%s' "$post_bootstrap_status"
test -z "$post_bootstrap_status"
# Final fail-closed host capability proof immediately precedes Product integration.
test "$(sysctl -n net.ipv4.ip_forward)" = "1"
cd services/product
$HOME/.local/bin/go test -race -tags=integration ./internal/infrastructure/postgres -count=1
cd ../..
BASE="$qualification_base" make ci
QUALIFICATION_RUNNER
```

The controller validates and enrolls the runner's SSH identity, invokes Ansible, and initiates
the SSH session only. The qualification runner owns its Docker daemon and sysctl state, owns the
checkout, and emits `whoami`, `hostname`, `uname -a`, the exact repository SHA, Docker client and
server output, Docker access, IPv4 forwarding, Product test status, and `make ci` status.
`git rev-parse HEAD` must equal the recorded full SHA and status output must be empty before
qualification. Both Docker client and server sections, non-sudo `docker info`, and sysctl
value `1` are mandatory. Stop on any failure; never repair networking in Product code or a
runner container. For a newer live PR head, start a new controller shell and repeat admission and provisioning with its exact SHA.
`make seed` is supplied by the checked-out #77 snapshot; it creates the hash-locked
qualification virtualenv containing Ansible Core and PyYAML. Host provisioning deliberately
does not duplicate those repository-managed dependencies.

## Ownership and migration

This playbook deliberately contains no Tekton, Harbor, BuildKit, or supply-chain resources.
For M4, Rocky/RKE2 node provisioning owns kernel and runtime capabilities, Tekton tasks only
verify them, BuildKit owns OCI builds, and an explicitly approved runtime must separately
serve Testcontainers integration tasks.
