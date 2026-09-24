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
  windows/{preflight,build,qualification,release}.json
  linux/{preflight,build,qualification,release}.json
```

## Windows/WSL path boundary

The repository may live under `\\wsl.localhost\...`, but Packer, VirtualBox and
Vagrant never receive that UNC path as their working directory. `repoctl.py`
converts the repository and script paths with `wslpath -w`. PowerShell copies the
small source templates and materializes checksum-locked inputs into a validated
local Windows staging directory below LocalAppData, executes the Windows tools
there, copies only the final box and evidence into `.artifacts`, then removes the
owned staging tree.

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
