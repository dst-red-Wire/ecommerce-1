# Local Rocky/RKE2 VirtualBox qualification

Owner: platform / M2.5. This fixture runs the repository's real offline artifact,
private firewall and RKE2 server paths in a disposable Rocky VM with its own kernel,
systemd and SELinux `Enforcing`. Architecture and production values remain governed
by `architecture.lock.yaml`, `config/infrastructure/mgmt-bootstrap.yaml` and
`config/infrastructure/network-plan.yaml`.

The supported controller is WSL2 with Windows VirtualBox and native Windows Vagrant.
The fixture contract in `contract.yml` pins Vagrant 2.4.9, the official Rocky 9.8
box and its SHA256, and the accepted local resource bounds. The validated host used
VirtualBox 7.2.18. Vagrant 2.4.8 does not support VirtualBox 7.2; pass an isolated
2.4.9 executable with `vm_vagrant_windows` when the global installation is older.
The repository's qualified Python/Ansible environment and locked collections must
already be prepared.

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
  "vm_vagrant_windows": "C:\\absolute\\path\\to\\vagrant.exe",
  "mgmt_offline_bundle_dir": "/absolute/path/to/rke2-offline-bundle",
  "mgmt_offline_manifest_sha256": "738a5cd2aa1be1eb93b08247193c1585574ad1668650993226eafe3f3cfa0bad"
}
```

Choose an existing host-only adapter and an unused address in its IPv4 `/24`.
The example addresses are fixture transport values, not actual MGMT DNS/NTP
services. Use a fresh name and MAC per concurrent test. The `server` action requires
the contract's 4 vCPU and 4096 MiB profile. The `resize` action can reconcile an
already owned stopped/running fixture to those values and verifies them from the
guest after restart.

Run the lifecycle in order:

```console
PYTHONDONTWRITEBYTECODE=1 .venv/qualification/bin/ansible-playbook -i localhost, platform/ansible/tests/mgmt_offline_vm/main.yml -e @.context/mgmt-vm-inputs.json -e vm_action=validate
PYTHONDONTWRITEBYTECODE=1 .venv/qualification/bin/ansible-playbook -i localhost, platform/ansible/tests/mgmt_offline_vm/main.yml -e @.context/mgmt-vm-inputs.json -e vm_action=create
PYTHONDONTWRITEBYTECODE=1 .venv/qualification/bin/ansible-playbook -i localhost, platform/ansible/tests/mgmt_offline_vm/main.yml -e @.context/mgmt-vm-inputs.json -e vm_action=test
PYTHONDONTWRITEBYTECODE=1 .venv/qualification/bin/ansible-playbook -i localhost, platform/ansible/tests/mgmt_offline_vm/main.yml -e @.context/mgmt-vm-inputs.json -e vm_action=server
PYTHONDONTWRITEBYTECODE=1 .venv/qualification/bin/ansible-playbook -i localhost, platform/ansible/tests/mgmt_offline_vm/main.yml -e @.context/mgmt-vm-inputs.json -e vm_action=server
PYTHONDONTWRITEBYTECODE=1 .venv/qualification/bin/ansible-playbook -i localhost, platform/ansible/tests/mgmt_offline_vm/main.yml -e @.context/mgmt-vm-inputs.json -e vm_action=destroy
```

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
`server` action. A normal `test` action refuses an active server so a cold trial cannot
be confused with recovery.

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
