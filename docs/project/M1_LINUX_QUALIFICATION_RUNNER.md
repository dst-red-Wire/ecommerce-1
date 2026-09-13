# M1 Linux qualification runner

Status: `TEMPORARY — M1 PROOF ONLY`

This provider-neutral host definition closes the Product integration proof; it is not the
M4 Tekton runner. The host/platform owns Ubuntu, Docker Engine and its socket, non-root
daemon access, base packages, and persistent kernel configuration. The checked-out PR owns
its hash-locked Python/Ansible seed and managed qualification toolchain.

## Provision a clean host

Supply a clean Ubuntu 24.04 x86_64 VM with systemd, SSH/root escalation, the image's base
Python 3 interpreter (required for Ansible fact gathering), outbound access to the Ubuntu
snapshot service, and an existing non-root qualification account. Copy
`platform/ansible/inventories/qualification.example.ini` outside the repository, replace
the example address, and invoke the playbook from a trusted controller with the repository's
pinned Ansible Core:

```text
# First compare the presented key fingerprint with the provider/console value, then:
ssh-keyscan -H qualification.example.invalid >> ~/.ssh/known_hosts
ansible-playbook -i /secure/path/qualification.ini platform/ansible/qualification-runner.yml
```

Never trust an unverified `ssh-keyscan` result: obtain the host-key fingerprint through the
VM provider console or another authenticated, out-of-band channel before enrollment. The
repository keeps host-key checking enabled. The role intentionally requires Python 3 in the
base image because Ansible cannot install its own remote interpreter after fact gathering.

The role configures a timestamped Ubuntu archive snapshot, installs and holds exact package
versions (including Ruby and the C toolchain), enables Docker across reboot, grants
only the named account normal Docker socket access, and persists
`net.ipv4.ip_forward=1` in `/etc/sysctl.d/60-ecommerce-m1-qualification.conf`. Docker group
membership is root-equivalent; use a dedicated ephemeral qualification account and destroy
the host after evidence is retained.

## Qualify immutable PR #77 head

Record the live PR head before provisioning. For the audited head, clone normally and then
detach at the immutable object (fetch it explicitly if the clone does not contain it):

```text
git fetch origin 58e10fdb7122f9f3302e3fc5534b07021f7cc37f
git checkout --detach 58e10fdb7122f9f3302e3fc5534b07021f7cc37f
git rev-parse HEAD
git status --porcelain=v1
uname -a
docker version
docker info
sysctl -n net.ipv4.ip_forward
make seed
make bootstrap
make env-check
cd services/product
$HOME/.local/bin/go test -race -tags=integration ./internal/infrastructure/postgres -count=1
cd ../..
make ci
```

`git rev-parse HEAD` must equal the recorded full SHA and status output must be empty before
qualification. Both Docker client and server sections, non-sudo `docker info`, and sysctl
value `1` are mandatory. Stop on any failure; never repair networking in Product code or a
runner container. A newer live PR head replaces the SHA in every command and evidence item.
`make seed` is supplied by the checked-out #77 snapshot; it creates the hash-locked
qualification virtualenv containing Ansible Core and PyYAML. Host provisioning deliberately
does not duplicate those repository-managed dependencies.

## Ownership and migration

This playbook deliberately contains no Tekton, Harbor, BuildKit, or supply-chain resources.
For M4, Rocky/RKE2 node provisioning owns kernel and runtime capabilities, Tekton tasks only
verify them, BuildKit owns OCI builds, and an explicitly approved runtime must separately
serve Testcontainers integration tasks.
