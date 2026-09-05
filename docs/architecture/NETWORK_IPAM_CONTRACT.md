# NETWORK / IPAM CONTRACT V2 — EXACT

Status: `EXACT CONFIG CONTRACT`

This contract explains the address-allocation invariants consumed by IaC. `config/infrastructure/network-plan.yaml` is the sole machine-canonical source for every CIDR, fixed private address and dynamic pool. Values shown here are a review-oriented presentation of that YAML and must not be edited independently. Public provider-assigned addresses are injected at runtime and are never recorded as address values in either contract.

## Address domains

- Permanent MGMT: `10.243.0.0/16`
- PREPROD JIT: `10.240.0.0/16`
- PROD A: `10.241.0.0/16`
- PROD B: `10.242.0.0/16`

No overlap is allowed between these domains, provider management networks, WireGuard pools or Kubernetes Pod/Service CIDRs.

## PREPROD VLAN subnets

| VLAN | Purpose | CIDR | Gateway convention |
|---:|---|---|---|
| 401 | MGMT | `10.240.1.0/24` | `.1` via PREPROD GW pair/VRRP-equivalent design |
| 402 | K8S-NODES | `10.240.2.0/24` | `.1` |
| 403 | STORAGE | `10.240.3.0/24` | routed only where explicitly required |
| 404 | REPLICATION | `10.240.4.0/24` | routed only where explicitly required |
| 405 | BACKUP | `10.240.5.0/24` | `.1` controlled egress/backup path |
| 406 | EDGE-DMZ | `10.240.6.0/24` | `.1` |

## Reserved static ranges

Within each `/24`:

- `.1-.9`: gateways/network appliances/VIPs
- `.10-.39`: physical hosts/hypervisors
- `.40-.99`: infrastructure VMs
- `.100-.199`: Kubernetes nodes/workload-facing reserved addresses
- `.200-.239`: temporary PERF/DR/JIT allocations
- `.240-.254`: reserved future expansion

DHCP, if used for bootstrap, must not allocate from static ranges unless the allocation is reservation-backed and exported to the same inventory source.

## PREPROD deterministic allocations

The complete fixed assignments are held under `static_allocations.preprod` in `config/infrastructure/network-plan.yaml`, grouped by VLAN. The allocation set covers:

- VLAN 401: the three Proxmox hosts plus edge, DNS, Squid, gateway, control-plane and worker VMs;
- VLAN 402: control-plane and worker node addresses;
- VLANs 403 and 404: worker storage and replication addresses;
- VLAN 405: worker, Squid and gateway backup addresses;
- VLAN 406: edge, DNS and gateway DMZ addresses.

The gated PERF-worker range is `dynamic_pools.preprod.402.perf-workers` in that same machine contract. IaC and inventory generation must read these mappings directly; this document intentionally does not maintain a second list of address literals.

## PROD private ranges

PROD uses the same functional segmentation with site-specific `/16` blocks:

- PROD A: `10.241.<segment>.0/24`
- PROD B: `10.242.<segment>.0/24`

Segment numbers mirror PREPROD: 1 MGMT, 2 K8S nodes, 3 storage, 4 replication, 5 backup, 6 edge-DMZ. Exact node addresses are generated from `prod-inventory.yaml` once the physical host-count arbitration is locked.

## Kubernetes CIDRs

To prevent site overlap:

- PREPROD Pod CIDR: `10.250.0.0/16`
- PREPROD Service CIDR: `10.251.0.0/16`
- PROD A Pod CIDR: `10.252.0.0/16`
- PROD A Service CIDR: `10.253.0.0/16`
- PROD B Pod CIDR: `10.254.0.0/16`
- PROD B Service CIDR: `10.255.0.0/16`

If RKE2/Cilium compatibility or provider routing requires different ranges, Codex may change these only in a single versioned network-plan change with automated overlap validation and no architecture redesign.

## WireGuard

Use a dedicated non-overlapping pool under MGMT coordination. The implementation must derive it from versioned config and validate against all ranges above. Do not reuse Pod, Service, storage or replication CIDRs.

## Validation requirements

Codex must provide automated checks for:

- duplicate IPs;
- overlapping CIDRs;
- address outside declared subnet;
- static address inside provider-reserved gateway/network/broadcast range;
- same node assigned conflicting identities;
- PROD A/B overlap;
- Pod/Service overlap with underlay;
- public IP slots present only when provider values are injected.
