# PREPROD TOPOLOGY V2 — EXACT

Status: `EXACT`

This document is authoritative for the standard E-COMMERCE PREPROD JIT topology. It refines `BASELINE_V2.md` without changing its architecture.

## Physical layer

Three phoenixNAP AMS JIT bare-metal hosts:

- `PVE-01`
- `PVE-02`
- `PVE-03`

Minimum target per host: >=64 physical cores, >=256 GiB RAM, >=6 NVMe plus boot media, >=2x25Gb/s where the provider exposes the validated topology.

Each host runs Proxmox VE 9. RKE2 worker stateful data devices are raw/pass-through devices; do not place them on a shared Proxmox HA datastore.

## VM placement

The placement below is mandatory unless a replacement placement preserves every strict anti-affinity invariant and is approved through architecture change control.

| Host | VMs |
|---|---|
| PVE-01 | `cp-01`, `worker-01`, `edge-01`, `dns-01`, `gw-01` |
| PVE-02 | `cp-02`, `worker-02`, `edge-02`, `squid-01` |
| PVE-03 | `cp-03`, `worker-03`, `dns-02`, `squid-02`, `gw-02` |

Strict pair anti-affinity:

- edge-01 / edge-02
- dns-01 / dns-02
- squid-01 / squid-02
- gw-01 / gw-02
- cp-01 / cp-02 / cp-03 each on a different physical host
- worker-01 / worker-02 / worker-03 each on a different physical host

## VM sizing

| Role | vCPU | RAM | OS disk |
|---|---:|---:|---:|
| RKE2 control plane | 8 | 16 GiB | 100 GiB |
| RKE2 worker | 24 | 96 GiB | 200 GiB |
| Edge | 4 | 8 GiB | 64 GiB |
| DNS | 2 | 4 GiB | 32 GiB |
| Squid | 4 | 8 GiB | 64 GiB |
| GW | 2 | 4 GiB | 32 GiB |

All VMs use Rocky Linux 9.x minimal or GenericCloud-derived immutable images, SELinux Enforcing, nftables where applicable, chrony, Wazuh agent and Fluent Bit where the role requires host telemetry.

## RKE2 topology

- 3 control-plane nodes: `cp-01..03`.
- 3 standard workers: `worker-01..03`.
- PERF campaign may add exactly two temporary JIT worker hosts after preceding qualification gates pass; they are not part of standard minimum capacity and are deleted immediately after the required PERF phase.
- Control-plane bootstrap: `cp-01` initializes; `cp-02` and `cp-03` join in parallel after API/etcd bootstrap becomes healthy; workers join after 3/3 control-plane quorum.

## Network attachment

Each physical host uses `bond0` LACP over 2x25Gb/s when available, carrying the validated VLAN trunk:

- 401 MGMT
- 402 K8S-NODES
- 403 STORAGE
- 404 REPLICATION
- 405 BACKUP
- 406 EDGE-DMZ

Exact private CIDRs and address allocations are owned by `NETWORK_IPAM_CONTRACT.md` and `config/infrastructure/network-plan.yaml`.

## Public IPv4 slots

The dedicated PREPROD public `/29` is allocated by role, not hard-coded to provider addresses in Git:

1. `edge-01-public`
2. `edge-02-public`
3. `dns-01-public`
4. `dns-02-public`
5. `public-reserve-01`

Network/broadcast/provider gateway addresses remain provider-derived.

## Edge/DNS/Egress roles

- Edge: HAProxy + Caddy + Coraza + ATS + FRR where required by the edge routing design.
- DNS: dnsdist + PowerDNS Authoritative for delegated PREPROD public zone.
- Squid: controlled egress proxy, deny-by-default model.
- GW: WireGuard + FRR + nftables. GW is not merged into Edge.

Public PREPROD names include `www`, `api`, `cdn`, `auth`, `admin` under a dedicated delegated PREPROD sub-zone.

## Storage mapping

Authoritative mapping is in `STORAGE_TOPOLOGY_V2.md`. Summary per standard worker host:

- NVMe-1: LocalPV-A
- NVMe-2: LocalPV-B
- NVMe-3: reserved/conditional block-RWX campaign only; no default Ceph
- NVMe-4: SeaweedFS volume data 1
- NVMe-5: SeaweedFS volume data 2
- NVMe-6: hot spare / replacement reserve

SeaweedFS uses three volume servers, one per worker failure domain, each with two dedicated data devices. Masters/filer/S3 gateways run as Kubernetes workloads with anti-affinity according to the storage contract.

## Lifecycle

Mandatory lifecycle:

`CREATE -> VALIDATE -> ARCHIVE -> DESTROY COMPLET -> VERIFY ZERO RESOURCE`

External watchdog owns TTL enforcement. Standard campaign TTL <=24 h. Endurance and PROD-equivalent certification follow the specialized lifecycle defined by `preprod-jit-governance`.

## Source-of-truth boundaries

Permanent MGMT remains external to PREPROD and owns Git/Gitea, Harbor, Fleet source configuration, OpenBao, NetBox, Grafana and Terraform state prerequisites.

PREPROD never becomes the durable source of truth for its own desired state.

## Exit criteria for topology implementation

A Codex M3 implementation is conformant only when:

- placement matches this table;
- anti-affinity is validated automatically;
- VM resources match or exceed the declared profiles without silent role merging;
- VLAN attachments match the network contract;
- storage devices match the storage contract;
- create/destroy is idempotent;
- `VERIFY ZERO RESOURCE` checks provider/control APIs and reports no orphan temporary resource.
