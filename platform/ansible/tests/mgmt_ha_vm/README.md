# Local six-node RKE2 HA qualification

Owner: platform / M2.5 persistent MGMT bootstrap.

This fixture extends the already-completed #128 single-node proof without replaying it.
It reuses the exact #128 Rocky box, offline RKE2/Cilium bundle and single-node VM
creation/staging machinery, then proves the missing multi-node behavior locally.

## What it proves

The authoritative campaign targets exactly six simultaneously running Rocky VMs:

- three RKE2 server/control-plane nodes: `192.168.22.61-63`;
- three RKE2 workers: `192.168.22.71-73`;
- embedded etcd with three running control-plane members;
- a write through the HA endpoint while one control plane is stopped;
- recovery of that control plane;
- an on-demand etcd snapshot;
- Cilium ready across all six Kubernetes nodes;
- worker joins through the HA endpoint;
- a digest-pinned HAProxy endpoint on worker-03, fronting TCP/9345 and TCP/6443;
- simulated internal DNS on worker-02 and NTP on worker-03;
- SELinux Enforcing and denied public egress on every node.

It does **not** prove production capacity, Hetzner networking, provider failure domains,
or physical-machine failure.

## Host contract

The current local host contract is:

- WSL2 as controller;
- native Windows Vagrant 2.4.9;
- native Windows VirtualBox 7.2.18r175117;
- existing `VirtualBox Host-Only Ethernet Adapter` at `192.168.22.1/24`, DHCP off;
- Docker Desktop available from WSL for preparing the pinned HAProxy image.

No Vagrant plugin is required. The #128 Windows bridge sets `VAGRANT_NO_PLUGINS=1`
when Vagrant is invoked.

## Resource boundary

The six-VM profile is intentionally a constrained functional laboratory profile:

- each control plane: 2 vCPU / 2048 MiB;
- each worker: 2 vCPU / 1280 MiB;
- aggregate guest allocation: 9984 MiB.

This is below the vendor-recommended RKE2 memory profile and therefore cannot be used
as capacity evidence. The campaign is allowed to fail closed under host memory
pressure; increasing the host RAM is preferable to weakening functional assertions.

## Existing offline bundle

The campaign never downloads or silently rebuilds the #128 RKE2 bundle. It requires
the ignored bundle already produced by:

```console
PYTHONDONTWRITEBYTECODE=1 .venv/qualification/bin/ansible-playbook \
  -i localhost, platform/ansible/tests/mgmt_offline_vm/build_bundle.yml
```

For the pinned version, the expected local path is:

```text
.context/rke2-offline-bundle-v1-37-0-rke2r1
```

The approved manifest remains:

```text
738a5cd2aa1be1eb93b08247193c1585574ad1668650993226eafe3f3cfa0bad
```

If the current worktree does not contain that ignored bundle but the completed #128
worktree still does, restore it explicitly and offline instead of rebuilding or
downloading it:

```console
make rke2-local-ha-restore-bundle \
  SOURCE=/absolute/path/to/pr128/.context/rke2-offline-bundle-v1-37-0-rke2r1
```

The restore command refuses a dirty checkout, a relative or missing source, an
existing destination, or a source whose `manifest.json` does not hash to the
approved value above. It does not rebuild the #128 bundle: the source directory must
contain exactly the regular files declared by the canonical lock plus
`manifest.json`, with no symlink, extra file or subdirectory. Every source SHA-256
is checked before copying, every copied SHA-256 is checked again, and the fully
verified staging directory is published atomically into the current checkout.
No Docker, network, download, reconstruction or ambient-cache fallback is used.
The destination remains:

```text
.context/rke2-offline-bundle-v1-37-0-rke2r1
```

## HA endpoint

The local fixed endpoint is `192.168.22.73` / `rke2-ha.internal.test`.
HAProxy runs as a host-network pod on worker-03 and forwards:

- TCP/9345 to all three RKE2 supervisor endpoints;
- TCP/6443 to all three Kubernetes API servers.

The HAProxy image is pulled on the controller by exact digest, saved as an archive,
copied into worker-03 and imported into RKE2 containerd. The pod uses
`imagePullPolicy: Never`, so the isolated node never contacts Docker Hub.

The bootstrap order is deliberate:

1. cp-01 starts as the initial RKE2 server;
2. cp-02 joins cp-01 directly;
3. worker-03 joins directly and becomes the HAProxy host;
4. HAProxy starts in front of cp-01/cp-02 with cp-03 initially unhealthy;
5. cp-03 joins through HAProxy;
6. worker-01 and worker-02 join through HAProxy.

All servers carry the HA endpoint IP and DNS name in their TLS SANs before the final
HA proof.

## DNS and NTP fixtures

The fixtures use only Python's standard library and bind on the isolated host-only
network:

- DNS: `192.168.22.72:53`, answering
  `rke2-ha.internal.test -> 192.168.22.73`;
- NTP: `192.168.22.73:123`.

Every node must successfully query both fixtures. They are test services only and do
not claim that the future internal DNS/NTP production services exist.

## Quorum/failure proof

After all six nodes are Ready, the campaign:

1. verifies the HA Kubernetes API endpoint;
2. requires three running embedded-etcd static pods;
3. creates an on-demand RKE2 etcd snapshot;
4. stops `ha-cp-02`;
5. writes and reads a ConfigMap through HAProxy while that control plane is down;
6. restarts `ha-cp-02`;
7. requires all six nodes, three etcd pods and all six Cilium agents Ready again.

The write/read during the one-server outage is the functional quorum proof.

## Run

Prepare HAProxy once while Docker Desktop is available:

```console
make rke2-local-ha-prepare
```

The preparation step pulls the immutable digest, exports the archive below
`.context/mgmt-ha-cache`, records its SHA-256 and source reference, and then exits.
Docker Desktop may be closed after this step to free RAM.

Then use the registered qualification entrypoint from a clean exact-SHA checkout:

```console
make rke2-local-ha-qualification
```

The authoritative result is written to:

```text
.context/mgmt-ha/<exact-head-sha>/result.json
```

Source hashes and the bounded Ansible runtime log are stored beside it. The six VMs
and the invocation-local RKE2 token/HAProxy tar are cleaned after the campaign, while
the evidence remains ignored under `.context`.

## Safety properties

- no Internet/NAT is added to any Rocky VM;
- the existing host-only adapter is reused, never created or reconfigured;
- only the six fixed local addresses are used;
- the #128 source fixture is reused rather than modified;
- HAProxy is digest-pinned and imported offline into RKE2;
- all runtime waits are bounded;
- one control-plane stop is deliberate and recovered before PASS;
- a PASS cannot claim production capacity, Hetzner networking or physical failure.
