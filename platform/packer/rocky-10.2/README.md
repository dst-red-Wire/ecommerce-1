# Rocky Linux 10.2 golden images

`config/contracts/machine-image-lock.yaml` owns the image profiles and RPM roots.
`config/contracts/toolchain-lock.json` owns every directly downloaded tool version,
artifact, architecture, checksum, scope and installation method. The RPM lock in
`config/artifacts/rocky-10.2-base-packages.lock.json` is a generated projection,
not a second authority.

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

## Reproducible offline flow

Regenerate the RPM projection only when the central package roots change:

```text
python3 scripts/generate_packer_rpm_lock.py \
  --output config/artifacts/rocky-10.2-base-packages.lock.json
```

Materialize every approved artifact before entering the isolated Packer build:

```text
python3 scripts/materialize_packer_rpm_repo.py \
  --contract config/contracts/machine-image-lock.yaml \
  --package-lock config/artifacts/rocky-10.2-base-packages.lock.json \
  --toolchain-lock config/contracts/toolchain-lock.json \
  --cache .context/cache/packer \
  --output .context/packer/rocky-10.2-offline

ssh-keygen -q -t ed25519 -N '' -f .context/packer/build-key

python3 scripts/render_packer_vars.py \
  --contract config/contracts/machine-image-lock.yaml \
  --bundle .context/packer/rocky-10.2-offline \
  --build-public-key-file .context/packer/build-key.pub \
  --build-private-key-file .context/packer/build-key \
  --output .context/packer/rocky-10.2.auto.pkrvars.hcl
```

`--offline` makes materialization fail if any cache entry is absent. The resulting
Packer variables reference a local `file://` ISO. Initialize the exact Packer
plugins before removing network access, then build with network access denied:

```text
packer init platform/packer/rocky-10.2/rocky-10.2.pkr.hcl
packer build \
  -var-file=.context/packer/rocky-10.2.auto.pkrvars.hcl \
  -var=image_profile=rke2 \
  platform/packer/rocky-10.2/rocky-10.2.pkr.hcl
```

Use `image_profile=admin-qualification` for the admin image. Generate the temporary
SSH key only below ignored `.context`; its private half is never copied into the
guest. Kickstart injects only the public half, and final cleanup removes the
authorized key, sudo grant and interactive build-user login before export.

Every staged file is SHA-256 checked before use. RPM repositories are disabled
during image provisioning, and external tools are installed only from the staged
bundle. Qualification checks versions and capabilities locally; `gh api --help`
does not require a token or a GitHub API call. Clone hygiene removes machine ID,
SSH host keys, leases/caches and temporary build credentials before export.
