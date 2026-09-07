# NETWORK / IPAM CONTRACT V2 - EXACT

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

## WireGuard MGMT operator access

Permanent operator access to Z5 uses the exact `wireguard.mgmt` block in `config/infrastructure/network-plan.yaml`:

- dedicated access gateway `wg-01`, reserved at `10.243.1.41` on MGMT segment 401;
- tunnel CIDR `10.246.0.0/24`;
- gateway tunnel address `10.246.0.1`;
- workforce operator pool `10.246.0.16/28`;
- separately controlled break-glass pool `10.246.0.240/29`;
- provider-assigned public endpoint injected at runtime only;
- UDP port `51820`;
- allowed route `10.243.0.0/16` only.

The WireGuard tunnel is a separate address domain for operator transport. It must not overlap PREPROD, PROD-A, PROD-B, permanent MGMT underlay, or any Kubernetes Pod/Service CIDR. The operator and break-glass sub-pools must be contained by the tunnel CIDR and must not overlap each other. The gateway tunnel address must not belong to either peer pool.

No Kubernetes Pod/Service route is exposed to operator peers. Kubernetes API access is reached through an approved MGMT underlay address in `10.243.0.0/16`.

`wg-01` is an access gateway rather than the default L3 gateway for segment 401, so its private address is reserved in the infrastructure-VM allocation range. The complete security/ownership/threat-model contract is `MGMT_WIREGUARD_ACCESS.md` plus `config/contracts/mgmt-wireguard-access.yaml`.

## Validation requirements

Codex must provide automated checks for:

- duplicate IPs;
- overlapping CIDRs, including the WireGuard tunnel against every versioned network;
- WireGuard operator/break-glass pools outside the tunnel or overlapping each other;
- address outside declared subnet;
- static address inside provider-reserved gateway/network/broadcast range;
- same node assigned conflicting identities;
- PROD A/B overlap;
- Pod/Service overlap with underlay or operator routes;
- public IP slots present only when provider values are injected.
