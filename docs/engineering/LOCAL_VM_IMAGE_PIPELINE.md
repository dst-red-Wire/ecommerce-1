# Local Rocky Linux 10.2 image pipeline

The canonical authority is
`architecture.lock.yaml#tooling.local_vm_image_pipeline`.
Image inputs, profiles, output names, timeouts and evidence requirements are owned
by `config/contracts/machine-image-lock.yaml`; exact host-tool versions and release
asset checksums are owned only by `config/contracts/toolchain-lock.json`.

## Profiles and responsibility boundary

The same Packer template exposes two host-native profiles. WSL2 is part of the
Windows profile; it is not treated as a native Linux virtualization host.

```text
Windows profile: VS Code / WSL2
     |
     | make image-rocky-build
     v
scripts/repoctl.py (stateless path bridge)
     |
     v
PowerShell Windows
     |
     v
Packer Windows
     |
     v
VirtualBox Windows
     |
     v
Rocky Linux 10.2 .box + SHA-256 + build evidence
```

```text
make image-rocky-qualify
     |
     v
PowerShell Windows
     |
     v
Vagrant Windows -> VirtualBox Windows -> temporary Rocky VM
     |
     v
bounded SSH smoke tests -> owned cleanup -> qualification evidence
```

```text
Native Linux
     |
     | make image-rocky-linux-build
     v
repoctl.py -> Packer Linux -> QEMU/KVM
     |
     v
Rocky Linux 10.2 qcow2 + SHA-256 + build evidence
     |
     | make image-rocky-linux-qualify
     v
temporary qcow2 overlay -> bounded QEMU process -> bounded SSH smoke tests
     |
     v
owned process/overlay cleanup -> qualification evidence
```

The allocation is strict:

- Packer builds the immutable OS, stable packages and Kubernetes/RKE2 host
  prerequisites.
- On Windows, VirtualBox is the hypervisor and Vagrant owns only the disposable
  VM lifecycle and smoke-test transport. Vagrant has no provisioner.
- On native Linux, QEMU/KVM owns both the hypervisor process and disposable
  overlay lifecycle. The immutable candidate is never booted writable.
- Ansible owns guest identity, network roles, RKE2, Cilium, HAProxy, DNS and
  cluster security configuration.
- PowerShell orchestrates native Windows executables and owns their bounded
  process lifecycle.
- Make is the repository API. For Windows, `repoctl.py` is its stateless
  WSL/Windows path adapter; for Linux, it delegates to the native Python
  orchestrator.
- WSL2 owns Git, Make, Python contract materialization and Ansible. Packer,
  VirtualBox and Vagrant must not be installed there.

One responsibility has one authority within each host profile. Both profiles
produce the same logical Rocky base and never invoke Ansible from Packer.

## Repository layout

```text
platform/packer/rocky-10.2/
  rocky-10.2.pkr.hcl
  variables.pkr.hcl
  http/rocky-10.2.ks

platform/vagrant/rocky-image-smoke/
  Vagrantfile

scripts/windows/
  RockyImagePipeline.psm1
  packer-preflight.ps1
  build-rocky-image.ps1
  qualify-rocky-image.ps1
  release-rocky-image.ps1

scripts/linux_image_pipeline.py
```

The repository forbids tracked Shell automation, so there is deliberately no
`provision.sh`. Kickstart installs the minimal bootable base. Packer's inline,
checksum-gated offline commands establish only immutable image state. Ansible
remains the guest and cluster configuration authority.

The generated `rocky-10.2.auto.pkrvars.hcl` exists only in the host-local build
staging directory. It is a deterministic projection of the central contract plus
ephemeral paths and SSH key material, so it is never source-controlled. Likewise,
the staged `SHA256SUMS` files are generated from the locked ISO/RPM/tool manifests
rather than maintained as a competing checksum authority.

## Windows/WSL2 prerequisites and preflight

Install the centrally approved Windows releases outside the repository. The
repository never installs or upgrades them automatically. Then run:

```console
make image-rocky-windows-preflight
```

The preflight starts no VM. It requires exact Packer, VirtualBox and Vagrant
versions, emits UTF-8 JSON, returns non-zero on any mismatch, and rejects a
competing Packer executable in WSL2. A workstation previously bootstrapped by an
older repository revision can remove only the superseded WSL Packer installation
through the Ansible-owned reconciliation:

```console
python3 scripts/repoctl.py reconcile --tags image_pipeline
```

## Windows build, qualification and release

```console
make image-rocky-windows-build
make image-rocky-windows-qualify
make image-rocky-windows-release
```

The shorter `image-rocky-{preflight,build,qualify,release}` targets remain stable
aliases for the Windows profile. `image-rocky-windows-build` performs preflight,
`packer init`, `packer fmt -check`,
`packer validate`, the VirtualBox-only Packer build, SHA-256 calculation and
structured build evidence. The ISO, RPMs, signing keys and guest tools are
materialized from central checksum locks. During guest provisioning, all RPM
repositories are disabled and no guest download is allowed.

For a cache-only replay, use:

```console
make image-rocky-windows-build OFFLINE=1
```

Missing cache bytes fail closed. Packer plugins remain exact-version declarations
and `packer init` uses Packer's verified release-install mechanism. It must find
the exact versions in its existing Windows plugin cache during a fully
disconnected replay.

Large WSL-to-Windows cache copies use bounded buffers, periodic durable flushes,
and source page-cache release hints so the declared pipeline remains reproducible
under the supported low-memory WSL profile.

`image-rocky-windows-qualify` checks the exact build SHA-256, adds it to an isolated
`VAGRANT_HOME`, boots one temporary VM, waits for SSH with finite attempts and
checks Rocky 10.2, kernel/CPU architecture, systemd, disk, network, fundamental
tools, SELinux/SSH security and RKE2 prerequisites. It always attempts bounded
VM and box cleanup. Vagrant uses no provisioner.

The Packer communicator key is generated per build and stored with owner-only ACL
under Windows LocalAppData, never in Git or the repository artifact directory.
Qualification destroys both key halves in its cleanup path. A failed
qualification therefore requires a rebuild. Release fails if either key still
exists.

`image-rocky-windows-release` publishes nothing. It only writes local release evidence
after matching a clean exact source SHA, build evidence, artifact checksum,
qualification evidence and cleanup evidence.

## Native Linux build, qualification and release

The Linux profile requires a native Ubuntu 24.04 x86_64 host with
readable/writable `/dev/kvm`, Packer 1.16.1 and the exact contracted QEMU 8.2.2
package. It intentionally rejects WSL so Packer cannot become a second authority
next to Packer Windows. Host packages are verified by preflight and are never
installed or upgraded automatically by this pipeline.

```console
make image-rocky-linux-preflight
make image-rocky-linux-build
make image-rocky-linux-qualify
make image-rocky-linux-release
```

The Linux build selects only `rocky-10.2-base.qemu.base`, verifies that Packer
produced exactly one qcow2, and promotes it by exact SHA-256. Qualification boots
a temporary copy-on-write overlay with one user-mode NAT interface and a
loopback-only forwarded SSH port. Every external command, SSH attempt and QEMU
process is bounded. The overlay, process and ephemeral key are removed before
qualification can pass. `OFFLINE=1` has the same fail-closed cache semantics as
the Windows profile.

## Shared VM resource and storage authority

`config/contracts/machine-image-lock.yaml#packer_image.build.resources` is the
only configurable authority for VM vCPU, memory and disk sizing. Its sibling
`packer_image.build.storage` owns firmware, partition table, partition sizes and
root filesystem. The renderer validates both sections and emits their values
into the generated `.pkrvars.hcl`; both VirtualBox and QEMU consume the same
projection, including the shared headless build mode. Kickstart receives the storage projection through Packer's
`templatefile`, creates an explicit BIOS/GPT/XFS layout, and creates neither LVM
nor swap. The adjacent `packer_image.build.timeouts` section supplies the same
bounded SSH timeout to both builders so slow hypervisor hosts do not require an
imperative local override. Local and per-hypervisor overrides are forbidden.

## ORAS distribution and local cache

Release validation remains local and never publishes an artifact. Distribution
is a separate, explicit step shared by the Windows and Linux profiles. Reconcile
the pinned ORAS and rsync tools through Ansible, then select a dedicated cache:

```console
python3 scripts/repoctl.py reconcile --tags artifact_transport
export ORAS_CACHE="$PWD/.context/cache/oras"
```

Push accepts a Harbor repository without a scheme, tag, or digest. The
controller requires PASS release evidence for the clean current SHA, synchronizes
the artifact and `SHA256SUMS` into the SHA-256-addressed cache with `rsync`,
verifies both copies, and derives the push tag as `git-<source-sha>`:

```console
PROFILE=windows ORAS_REPOSITORY=harbor.example.com/machine-images/rocky make image-rocky-oras-push
PROFILE=linux ORAS_REPOSITORY=harbor.example.com/machine-images/rocky make image-rocky-oras-push
```

The command reports and records the immutable manifest reference returned by
ORAS. Pull accepts only that `repository@sha256:<digest>` form; mutable tags such
as `latest` or `git-<sha>` are rejected at the pull boundary:

```console
PROFILE=windows ORAS_REF='harbor.example.com/machine-images/rocky@sha256:<digest>' make image-rocky-oras-pull
```

ORAS uses `ORAS_CACHE` as its content-addressable cache. The controller also
keeps materialized artifacts below
`$ORAS_CACHE/materialized/sha256/<artifact-sha256>/`, uses bounded `rsync`
operations without deletion, and verifies SHA-256 before and after every cache
or artifact synchronization. Registry authentication remains external to this
workflow; passwords and tokens are never accepted as command arguments.

Generated outputs are ignored by Git:

```text
.artifacts/packer/rocky-10.2/
  windows/
    rocky-10.2-rke2-virtualbox.box
    SHA256SUMS
  linux/
    rocky-10.2-rke2-kvm.qcow2
    SHA256SUMS

.context/evidence/rocky-image/rocky-10.2/
  windows/{preflight,build,qualification,release,oras-push,oras-pull}.json
  linux/{preflight,build,qualification,release,oras-push,oras-pull}.json
```

## Windows/WSL path boundary

The repository may live under `\\wsl.localhost\...`, but Packer, VirtualBox and
Vagrant never receive that UNC path as their working directory. `repoctl.py`
converts the repository and script paths with `wslpath -w`. PowerShell copies the
small source templates and materializes checksum-locked inputs into a validated
local Windows staging directory below LocalAppData, executes the Windows tools
there, copies only the final box and evidence into `.artifacts`, then removes the
owned staging tree.

RPM provisioning reconciles the older DVD package set to the signed locked
closure with all network repositories disabled. The contract permits
`allowerasing` only to replace incompatible ISO-era companion packages;
`skip-broken` and `nobest` remain forbidden, and exact profile-root NEVRAs are
qualified immediately after every transaction.
The four kernel install-only roots may retain at most one previous DVD version;
the locked NEVRA must be present and selected as the default boot kernel. All
other contract roots remain strictly mono-version.

## RKE2 relationship

The image pipeline stays separate from cluster qualification:

```text
Packer image -> image qualification -> Vagrant lab -> Ansible
             -> RKE2/Cilium/HA qualification
```

The image smoke test does not claim multi-node join, three-member etcd quorum,
HAProxy behavior, internal DNS/NTP availability, control-plane loss/recovery or
RKE2 runtime security proof. Those remain owned by the existing Ansible/RKE2
qualification workflow. A build that was not executed is `NOT EXECUTED`; static
tests can never manufacture runtime `PASS` evidence.
