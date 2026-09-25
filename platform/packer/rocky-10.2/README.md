# Rocky Linux 10.2 golden images

`config/contracts/machine-image-lock.yaml` owns the image profiles and RPM roots.
`config/contracts/toolchain-lock.json` owns every directly downloaded tool version,
artifact, architecture, checksum, scope and installation method. The RPM lock in
`config/artifacts/rocky-10.2-base-packages.lock.json` is a generated projection,
not a second authority.

`variables.pkr.hcl` is the typed Packer interface. Its values are rendered from
the central contract into a host-local `rocky-10.2.auto.pkrvars.hcl`; generated
paths, checksums and temporary key material are never committed.

The same contract is the single authority for CPU, RAM, disk size, BIOS/GPT
firmware layout and XFS partition sizes. Packer projects it identically to the
VirtualBox and QEMU builders and renders the Kickstart storage instructions.
The explicit layout contains `biosboot`, `/boot` and a growable `/` partition;
LVM and swap are forbidden for this Kubernetes-ready base image.

The central contract also owns the bounded SSH communicator timeout shared by
both hypervisors. Slow Windows hosts therefore use the same reviewed value as
native Linux instead of requiring an untracked Packer override.

The shared boot command opens the GRUB console and executes the exact `linux`,
`initrd` and `boot` commands projected from the locked Rocky ISO. It does not
depend on menu selection or cursor positioning. VirtualBox uses a bounded 500 ms
key-group interval so a loaded Windows host cannot drop the start of a command.

## Profiles

- `rocky-10.2-base` is a logical shared component: minimal administration,
  RKE2/Kubernetes host prerequisites, SELinux, nftables, system/network diagnostics
  and generic CLI tools.
- `rocky-10.2-rke2` adds the signed Rocky OpenSCAP/SCAP Security Guide packages
  and the checksum-pinned `kube-bench` binary required for node-side security
  evidence. It does not contain controller-side developer or CI tooling.
- `rocky-10.2-admin-qualification` adds `git`, `gh`, `strace`, `sysstat`, `mtr`,
  `shellcheck` and `shfmt`.

The QEMU profile alone adds `qemu-guest-agent`. VirtualBox Guest Additions stay
disabled. Neither hypervisor agent belongs to the shared component.

Rocky Linux 10.2 does not publish a `curl-minimal` binary package in the locked
repositories. The central contract therefore records the real Rocky package
`curl` as an explicit compatibility substitution; no external repository is used.

## Responsibility boundary

Packer owns the immutable OS, stable host prerequisites and baseline diagnostics.
Ansible owns machine identity, addresses, RKE2 roles, Cilium and host-specific
network/security policy. The RKE2 bundle owns Kubernetes binaries, images and
`rke2-selinux`. The RKE2 image owns only the three node-side security inputs
listed above. The admin image owns GitHub diagnostics; controller-side
qualification tools remain outside every Packer image in the governed user cache.

## Reproducible host profiles

The Windows path is WSL2 Make -> native Windows PowerShell -> native Windows
Packer/VirtualBox/Vagrant. Packer is intentionally absent from WSL. Run:

```text
make image-rocky-windows-preflight
make image-rocky-windows-build
make image-rocky-windows-qualify
make image-rocky-windows-release
```

The historical targets without `-windows-` are aliases for this profile. The
explicit targets delegate their stateless WSL/Windows path conversion to
`scripts/repoctl.py`. PowerShell stages the build under Windows LocalAppData so
Packer, VirtualBox and Vagrant never use a UNC working directory. Generated boxes
are copied to `.artifacts/packer/rocky-10.2/windows`; generated evidence stays
under `.context/evidence/rocky-image/rocky-10.2/windows` as required by the
repository evidence policy.

The second path is a native Ubuntu 24.04 x86_64 host -> Packer Linux -> QEMU/KVM.
It rejects WSL and requires `/dev/kvm`:

```text
make image-rocky-linux-preflight
make image-rocky-linux-build
make image-rocky-linux-qualify
make image-rocky-linux-release
```

It produces a qcow2 under `.artifacts/packer/rocky-10.2/linux`, records evidence
under `.context/evidence/rocky-image/rocky-10.2/linux`, and qualifies it through a
disposable overlay, a bounded QEMU process and loopback-only SSH.

Use `OFFLINE=1` only after the exact ISO, RPMs, tools and Packer plugins have been
cached and verified:

```text
make image-rocky-windows-build OFFLINE=1
make image-rocky-linux-build OFFLINE=1
```

Offline materialization fails if any cache entry is absent. Packer variables use
host-local paths and a local `file:///` ISO. `packer init`, `packer fmt -check`
and `packer validate` are mandatory before either profile-specific build.

Regenerate the RPM projection only when the central package roots change:

```text
python3 scripts/generate_packer_rpm_lock.py \
  --output config/artifacts/rocky-10.2-base-packages.lock.json
```

The temporary communicator key is generated on Windows. Its private half remains
outside the repository under LocalAppData with an owner-only ACL, is used only for
the exact Vagrant smoke candidate, and is destroyed during qualification cleanup.
Release refuses any candidate whose key remains.

Every staged file is SHA-256 checked before use. RPM repositories are disabled
during image provisioning, and external tools are installed only from the staged
bundle. Qualification checks versions and capabilities locally; `gh api --help`
does not require a token or a GitHub API call. Clone hygiene removes machine ID,
SSH host keys and leases/caches before export. The full operator procedure and
authority boundary are documented in `docs/engineering/LOCAL_VM_IMAGE_PIPELINE.md`.
