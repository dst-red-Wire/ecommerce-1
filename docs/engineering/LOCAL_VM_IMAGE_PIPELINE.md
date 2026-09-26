# Local Rocky Linux 10.2 image pipeline

The canonical authority is
`architecture.lock.yaml#tooling.local_vm_image_pipeline`.
Image inputs, profiles, output names, timeouts and evidence requirements are owned
by `config/contracts/machine-image-lock.yaml`; exact host-tool versions and release
asset checksums are owned only by `config/contracts/toolchain-lock.json`.

## Profiles and responsibility boundary

The same Packer template exposes two host-native profiles. WSL2 is part of the
Windows profile; it is not treated as a native Linux virtualization host.

Every preparation/qualification entrypoint runs the offline guest-command
preflight before downloading inputs, staging a candidate or starting a VM:
Windows preflight/native prepare, Linux static validation/preflight/build/qualify,
and local-service asset preparation/qualification. It rejects PowerShell host
interpolation of guest commands and checks their Bash syntax without executing
guest commands. A passing syntax preflight is not a substitute for runtime smoke
evidence; a failed runtime cycle must still not be imported or released.

```text
Windows normal boot: VS Code / WSL2 / Hyper-V
     |
     | make image-rocky-windows-native-prepare
     v
exact-SHA C:\ecommerce-lab staging + BCD backup + one-shot task
     |
     | make image-rocky-windows-native-reboot (explicit authorization)
     v
Windows native boot: Hyper-V/WSL2 unavailable
     |
     v
PowerShell -> VirtualBox backend probe -> NATIVE_VTX required
     |
     v
Packer -> Vagrant smoke -> cleanup -> result.json
     |
     v
bootsequence normal -> automatic reboot
     |
     v
Windows normal boot / WSL2
     |
     | make image-rocky-windows-native-import
     v
exact-SHA local artifact and build/qualification/release evidence
```

The native cycle checks free space on its Windows staging drive before
preparation (40 GiB), reboot (24 GiB), build (24 GiB), and Vagrant smoke import
(16 GiB). Insufficient space is `BLOCKED_RUNTIME`; it cannot be treated as an
image or guest `PASS`. A failed native attempt remains recorded under its exact
SHA, and the one-attempt contract requires a new source SHA for another cycle.
Keep prior evidence when cleaning obsolete local staging directories.

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
  native-vtx-cycle.ps1
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

The reference build requires VirtualBox to own VT-x directly. The normal Windows
boot deliberately retains Hyper-V and WSL2, so a full reference preflight fails
there instead of silently accepting VirtualBox NEM. Preparation checks exact
Packer, VirtualBox and Vagrant versions, emits UTF-8 JSON, and rejects a competing
Packer executable in WSL2, but records acceleration as deferred until the native
boot runtime probe. A workstation previously bootstrapped by an
older repository revision can remove only the superseded WSL Packer installation
through the Ansible-owned reconciliation:

```console
python3 scripts/repoctl.py reconcile --tags image_pipeline
```

## Windows build, qualification and release

The reference workflow uses a guarded two-boot cycle:

```console
make image-rocky-windows-native-self-test
make image-rocky-windows-native-prepare
make image-rocky-windows-native-reboot
```

`native-prepare` may request Windows UAC because BCD backup, the dedicated loader
entry and the highest-privilege one-shot scheduled task require administrator
rights. It never reboots. It requires a clean Git worktree, creates or reuses
exactly one entry named `Windows - VirtualBox VT-x native`, modifies only that
entry with `hypervisorlaunchtype off`, and stages the exact Git SHA and tree below
the contract-owned `C:\ecommerce-lab\staging\<sha>`. The staging manifest covers
every immutable input needed while WSL2 is unavailable. `vsmlaunchtype off` is
recorded as `PASS` or `UNSUPPORTED`; it is never treated as runtime proof.

`native-reboot` is the explicit reboot authorization boundary. It verifies the
staging and task, arms only `bcdedit /bootsequence` for the native entry, and
reboots. It never changes the permanent default loader. After interactive Windows
logon, the temporary task:

1. rejects a second attempt for the same SHA;
2. verifies the staging manifest and exact tool versions;
3. proves `HypervisorPresent=false` and starts a disposable VirtualBox probe;
4. requires `VBox.log` to identify `NATIVE_VTX` and rejects NEM before Packer;
5. records T0 through T13 while building the box;
6. boots and smoke-tests the box with centrally derived CPU, memory, disk,
   `virtio` NIC, XFS/no-LVM/no-swap and RPM profile; captures the guest RPM
   manifest, contracted profile roots and CycloneDX SBOM bound to the box digest;
7. destroys owned VMs and the isolated Vagrant box and removes the ephemeral key;
8. arms the exact normal loader in a `finally`, removes the task, writes evidence,
   and reboots even when qualification fails.

After the normal boot and WSL2 return:

```console
make image-rocky-windows-native-import
```

Import rejects stale SHA/tree/manifest bindings, any non-PASS runtime field,
NEM, checksum drift, missing or inconsistent supply-chain evidence, leftover
keys or incomplete cleanup. Only then does it place
the `.box`, `SHA256SUMS`, and compatible build/qualification/release evidence in
the repository's ignored artifact/evidence roots.

Recovery does not restore the whole BCD or delete the reusable native entry:

```console
make image-rocky-windows-native-recover
```

It arms the normal Windows loader for the next boot and removes the temporary
task. Full BCD restoration remains a manual last resort using the verified backup
under `C:\ecommerce-lab\bcd`.

The legacy stage-specific commands remain available for bounded diagnostics:

```console
make image-rocky-windows-build
make image-rocky-windows-qualify
make image-rocky-windows-release
```

The shorter `image-rocky-{preflight,build,qualify,release}` targets remain stable
aliases for the Windows profile. They do not bypass the native-VT-x preflight.
`image-rocky-windows-build` performs preflight,
`packer init`, `packer fmt -check`,
`packer validate`, the VirtualBox-only Packer build, SHA-256 calculation and
structured build evidence. The ISO, RPMs, signing keys and guest tools are
materialized from central checksum locks. During guest provisioning, all RPM
repositories are disabled and no guest download is allowed.
The root provisioner explicitly includes `/usr/local/bin` in `PATH` because
`sudo` may replace the caller's path; locked external-tool checks run only after
their offline installation. Static contract tests enforce this ordering before
another native-boot campaign is authorized.

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
qualification evidence, cleanup evidence, and artifact-bound SBOM, package
manifest and profile inventory. Root-owned credential/config paths are tested
through noninteractive `sudo`; host-user-global image phases are serialized by
the governed runtime lock.

## Native Linux build, qualification and release

The Linux profile requires a native Ubuntu 24.04 x86_64 host with
readable/writable `/dev/kvm`, Packer 1.16.1 and the exact contracted QEMU 8.2.2
package revision for both `qemu-system-x86` and `qemu-utils`. It intentionally rejects WSL so Packer cannot become a second authority
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

On a WSL workstation, QEMU runtime remains ineligible even when a `/dev/kvm`
device node is visible. The bounded static entrypoint still validates the QEMU
source, derived variables, ISO checksum, Packer initialization and exact plugin
through native Windows Packer without claiming a VM build:

```console
make image-rocky-linux-static-validate
```

Its evidence records `host_capability: NOT_AVAILABLE` and
`runtime_build: NOT_EXECUTED`. Only the native Ubuntu entrypoints above may turn
those runtime fields into a real result.

## Local Gitea, Harbor and ORAS qualification

`config/contracts/local-services-qualification.yaml` is a local qualification
contract subordinate to the architecture and machine-image locks; it is not a
second production MGMT authority. It pins Gitea 1.24.6, Harbor 2.13.2, Docker
29.8.1, containerd 2.3.5, Compose 2.40.3, every Harbor image identity and all
download checksums. Materialize its offline inputs before the native build:

```console
make local-services-assets
make local-services-assets OFFLINE=1
```

The base image contains cloud-init but no shared Vagrant private key. Each owned
service VM reads a runtime-only public key from a bounded loopback-only
NoCloud-Net endpoint through the VirtualBox NAT host address, regenerates SSH
host keys, and disables password login.
The endpoint and Vagrant state live below Windows LocalAppData, which avoids UNC
working-directory failures. Private keys, service credentials, TLS material and
Ansible extra-vars stay below ignored `.context/runtime` paths with owner-only
permissions.

After importing and publishing exact-SHA image release evidence, run:

```console
make local-services-capabilities
make local-services-qualify
```

`local-services-capabilities` remains a read-only diagnostic for the normal
WSL2 boot. It records `BLOCKED_RUNTIME` when native VT-x is unavailable.
The native Windows cycle stages an exact-SHA Git bundle, hash-locked offline
assets and Python wheels before WSL2 stops. During native boot, a Rocky Linux
VirtualBox controller runs the repository's canonical Ansible roles and
qualification program. Every VM must have a `NATIVE_VTX` VirtualBox log with
no NEM marker. A blocked result cannot be promoted to `PASS`.

On this workstation, the normal Windows boot keeps the Microsoft hypervisor
active for WSL2. The native VT-x boot disables the hypervisor and WSL2. The
cycle creates an ephemeral Rocky controller on the existing host-only adapter
(`192.168.22.241`) and one service VM at a time (`192.168.22.242`). The
controller receives the exact-SHA Git bundle without a network clone and uses
the same checked-in playbooks and roles. NoCloud seed traffic uses VirtualBox
NAT only during first boot; NAT is disconnected before qualification. The
controller proves Gitea first, destroys its VM, then proves Harbor and the
ORAS digest round trip and destroys both remaining VMs. The normal-boot task
imports evidence, checks the original BCD loader and hypervisor state, removes
the owned native loader and verifies that WSL2 can start.

The controller uses Ansible twice per service and requires zero changes on the
second apply. It probes Gitea and proves repository creation plus
push/clone/fetch SHA integrity. It then installs Harbor from the verified
offline archive, verifies loaded image IDs, uses a runtime private CA, creates
the project, and performs ORAS login, push, immutable-digest pull, SHA-256
comparison and wrong-digest rejection. Guest output and forwarding use a
persistent default-deny nftables policy after bootstrap. Every VM disk is
destroyed after evidence capture.

Recovery is bounded to owned service VMs and the dedicated native BCD loader:

```console
make local-services-recover
```

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
For a runtime private CA and isolated credential file, the controller consumes
`ORAS_CA_FILE` and `ORAS_REGISTRY_CONFIG`; it validates both paths and rejects a
group/world-readable registry configuration. TLS verification cannot be disabled.

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
