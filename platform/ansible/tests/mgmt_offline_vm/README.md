# Local Rocky/RKE2 VirtualBox qualification

Owner: platform / M2.5. This fixture runs the repository's real offline artifact,
private firewall and RKE2 server paths in a disposable Rocky VM with its own kernel,
systemd and SELinux `Enforcing`. Architecture and production values remain governed
by `architecture.lock.yaml`, `config/infrastructure/mgmt-bootstrap.yaml` and
`config/infrastructure/network-plan.yaml`.

The supported controller is WSL2 with Windows VirtualBox and native Windows Vagrant.
The fixture contract in `contract.yml` pins Vagrant 2.4.9, the official Rocky 9.8
box and its SHA256, and the accepted local resource bounds. The Guest Additions lock
pins VirtualBox `7.2.18r175117`, Guest Additions `7.2.18`, the host ISO SHA256 and the
complete Rocky build dependency closure. The authoritative launcher requires the canonical Windows Vagrant
installation at `C:\\Program Files\\Vagrant\\bin\\vagrant.exe` and verifies that
it reports exactly Vagrant 2.4.9 before the lifecycle starts. Caller-controlled
Vagrant executable overrides are rejected. The repository's qualified Python/Ansible
environment and locked collections must already be prepared.

SSH readiness is also contract-driven from `contract.yml`: connect timeout,
connection attempts, total readiness window and retry sleep are defined once under
`mgmt_local_vm_contract.transport.ssh`. The same contract also owns the shared
fixture `runtime_sources` list consumed by HA exact-SHA fingerprinting, so the mono-VM
and six-node workflows do not carry independent copies of transport policy or shared
source dependencies.

## Rebuild the offline bundle

`config/artifacts/mgmt-rke2-offline-v1.37.0-rke2r1.lock.json` is the single source
for every release asset, RPM, signing key, URL and digest. The RKE2 version itself
comes from `config/infrastructure/mgmt-bootstrap.yaml`. Generated archives, RPMs,
manifests, caches and logs stay below `.context` and are never Git sources.

On a connected preparation machine, run:

```console
PYTHONDONTWRITEBYTECODE=1 .venv/qualification/bin/ansible-playbook -i localhost, platform/ansible/tests/mgmt_offline_vm/build_bundle.yml
```

The builder downloads exact locked bytes, verifies every checksum, decompresses the
two image archives, recreates the canonical manifest and requires its independently
approved SHA256. It then validates image contents, RPM metadata and RPM signatures
inside the digest-pinned Rocky preparer image. To prove a cached rebuild without any
network access, supply an existing byte source containing the verified uncompressed
image archives and a fresh output directory. Offline mode fails closed rather than
starting the connected decompressor used during preparation:

```console
PYTHONDONTWRITEBYTECODE=1 .venv/qualification/bin/ansible-playbook -i localhost, platform/ansible/tests/mgmt_offline_vm/build_bundle.yml \
  -e bundle_source=/absolute/path/to/locked/source \
  -e bundle_output=$PWD/.context/rke2-offline-rebuilt \
  -e bundle_offline=true
```

The command writes only a bounded result to
`.context/mgmt-airgap-bundle-result.json`. The manifest digest must be
`738a5cd2aa1be1eb93b08247193c1585574ad1668650993226eafe3f3cfa0bad`.

## Prepare pinned Guest Additions prerequisites

`config/artifacts/virtualbox-guest-additions-7.2.18-rocky-9.8.lock.json` is the
single authority for the host/guest versions, ISO identity, exact Rocky kernel,
signing key and all 78 RPM digests. Prepare its ignored offline bundle once on a
connected controller:

```console
PYTHONDONTWRITEBYTECODE=1 .venv/qualification/bin/ansible-playbook \
  -i localhost, platform/ansible/tests/mgmt_offline_vm/build_guest_additions_bundle.yml
```

Use `-e bundle_offline=true` to prove that an already populated cache is complete.
Every non-cleanup VM action validates the exact VirtualBox version, ISO SHA256,
transport commands and complete bundle before Vagrant runs. `destroy` deliberately
remains available when prerequisites are broken so cleanup cannot be blocked.

Each fresh Rocky VM receives the dependency closure over one private SSH tar stream.
The guest revalidates the manifest, every SHA256, RPM metadata and every RPM signature
before importing the approved Rocky key and invoking DNF with every repository
disabled. The mounted ISO identity is checked before installation. Provisioning then
requires the exact kernel/user service versions and enables bounded
`Guest/RAM/Usage/{Total,Free,Cache}` sampling. Evidence is written to
`.context/mgmt-offline-vm/<name>/guest-additions.json`.

## Create and test the VM

Create an ignored `.context/mgmt-vm-inputs.json`:

```json
{
  "vm_name": "ecommerce-mgmt-test-local",
  "vm_hostonly_adapter": "VirtualBox Host-Only Ethernet Adapter",
  "vm_host_address": "192.168.22.1",
  "vm_address": "192.168.22.243",
  "vm_mac": "02EECC009801",
  "vm_cpus": 4,
  "vm_memory": 4096,
  "mgmt_offline_bundle_dir": "/absolute/path/to/rke2-offline-bundle",
  "mgmt_offline_manifest_sha256": "738a5cd2aa1be1eb93b08247193c1585574ad1668650993226eafe3f3cfa0bad"
}
```

Choose an existing host-only adapter and an unused address in its IPv4 `/24`.
The example addresses are fixture transport values, not actual MGMT DNS/NTP
services. Use a fresh name and MAC per concurrent test. The `server` action requires
at least the contract's 4 vCPU and 4096 MiB profile; higher values remain bounded by
the same contract and are passed through `vm_cpus` and `vm_memory`. The `resize`
action can reconcile an already owned stopped/running fixture to those values and
verifies them from the guest after restart.

Run the authoritative lifecycle through the single registered entrypoint:

```console
.venv/qualification/bin/python scripts/repoctl.py rke2-local-virtualbox-qualification --inputs .context/mgmt-vm-inputs.json
```

Direct `ansible-playbook` invocations are diagnostic-only. They do not create
merge-authoritative RKE2 qualification evidence and must not replace the registered
`repoctl` lifecycle.

`create` boots with every network adapter disconnected. Through the private serial
pipe, it installs a fresh SSH key and a persistent output/forward default-deny nftables
boundary before attaching the existing host-only adapter. There is no NAT, forwarded
port or shared folder. Host keys are pinned from the serial console, password access
is disabled, and the guest must report its own Rocky kernel, systemd and SELinux
`Enforcing` before artifact work begins.

Only a fresh `create` followed by the first `test` is a cold artifact qualification.
The artifact role validates the independently approved manifest, image contents,
RPM metadata and signatures before installing with every repository disabled.
`server` activates the canonical nftables and firewalld templates, invokes the real
`rke2_server` role, and requires `Node Ready`, Cilium ready, CoreDNS available, every
deployed component to have an available replica, SELinux `Enforcing`, and denied
public egress. Immediately before the first privileged installation it revalidates
the complete staged bundle; its trust variable is derived only from that successful
validation. A second `server` action follows the idempotent existing-server path and
rechecks the cluster, the canonical output/forward `drop` policies, and all eight VM
adapters without requiring deleted transfer bytes. The second Cilium operator replica
may remain Pending because required
anti-affinity cannot place two replicas on one node; this is recorded in the result.

The official box has a 10 GiB disk. After the verified RPM transaction and first
successful image import, the fixture removes only its disposable transfer copy and
the already-imported tar archives so kubelet does not enter `DiskPressure`. The
installed RPMs, RKE2 binary and containerd content remain. To reconstruct transfer
bytes after cleanup, run `vm_action=restage`; it stops the local server, executes the
same complete offline validation and staging role, and leaves restart to the next
`server` action. To remain inside the official box's 10 GiB disk, it removes only the
stopped fixture's reconstructible image-import directory before rebuilding it, and
hardlinks the validated staging archives into that directory instead of storing a
second copy. The containerd store is preserved because an existing etcd member needs
its imported runtime images during restart. Both paths remain root-only, and the
postcondition proves identical inodes and approved digests. RKE2 server state and etcd
remain. A normal `test` action refuses an
active server so a cold trial cannot be confused with recovery.

The fail-closed mutation proof is a separate recovery sequence. Run `restage`, then
`tamper`, then `restage` again before `server`. The `tamper` action flips one byte in
the guest's staged RKE2 binary and passes only when the complete `server` action
stops at its immediate bundle-revalidation task while RKE2 remains inactive. It
writes the before/after digests and blocked task to `tamper-result.json`; it never
modifies the source bundle.

Evidence is written under `.context/mgmt-offline-vm/<name>`: VM identity and adapter
state, cold preflight, source hashes, role result, resource measurement, logs,
`server-source.json` and `rke2-result.json`. Secrets and raw logs remain ignored.
`destroy` checks the exact Vagrant UUID and machine name before removing only the owned
VM, then removes the generated SSH key, RKE2 token and rendered token-bearing inputs.

## Qualification boundary

This fixture proves one local Rocky control plane can install and start the pinned
RKE2/Cilium stack without target Internet access. It also exercises the pod-to-API
and pod-to-kubelet firewall grants from the canonical template. It does not prove
six-node installation, multi-node join, etcd quorum, worker scheduling, failure
recovery, production capacity, or availability of real DNS/NTP/artifact services.

Official references: [RKE2 air-gap installation](https://docs.rke2.io/install/airgap),
[RKE2 SELinux](https://docs.rke2.io/security/selinux),
[Rocky images](https://dl.rockylinux.org/pub/rocky/9/images/x86_64/), and
[Vagrant VirtualBox provider](https://developer.hashicorp.com/vagrant/docs/providers/virtualbox).
