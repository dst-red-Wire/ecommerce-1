# NETWORK / IPAM CONTRACT V2 — EXACT

Status: `EXACT CONFIG CONTRACT`

This contract removes address-allocation ambiguity for IaC. Public provider-assigned addresses are injected at runtime; private ranges below are the default project allocation and may change only through versioned configuration change, not agent guesswork.

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

## PREPROD static allocations

### VLAN 401 MGMT

- `pve-01`: `10.240.1.11`
- `pve-02`: `10.240.1.12`
- `pve-03`: `10.240.1.13`
- `edge-01`: `10.240.1.41`
- `edge-02`: `10.240.1.42`
- `dns-01`: `10.240.1.43`
- `dns-02`: `10.240.1.44`
- `squid-01`: `10.240.1.45`
- `squid-02`: `10.240.1.46`
- `gw-01`: `10.240.1.47`
- `gw-02`: `10.240.1.48`
- `cp-01`: `10.240.1.61`
- `cp-02`: `10.240.1.62`
- `cp-03`: `10.240.1.63`
- `worker-01`: `10.240.1.71`
- `worker-02`: `10.240.1.72`
- `worker-03`: `10.240.1.73`

### VLAN 402 K8S-NODES

- `cp-01`: `10.240.2.61`
- `cp-02`: `10.240.2.62`
- `cp-03`: `10.240.2.63`
- `worker-01`: `10.240.2.71`
- `worker-02`: `10.240.2.72`
- `worker-03`: `10.240.2.73`
- PERF workers: allocate sequentially from `10.240.2.200/29` equivalent host range, beginning `.201`.

### VLAN 403 STORAGE

- `worker-01`: `10.240.3.71`
- `worker-02`: `10.240.3.72`
- `worker-03`: `10.240.3.73`

### VLAN 404 REPLICATION

- `worker-01`: `10.240.4.71`
- `worker-02`: `10.240.4.72`
- `worker-03`: `10.240.4.73`
- stateful services use node-local transport and Kubernetes/service identities; do not assign ad-hoc fixed workload IPs unless the owning operator requires them.

### VLAN 405 BACKUP

- workers: `.71-.73`
- `squid-01`: `.45`
- `squid-02`: `.46`
- `gw-01`: `.47`
- `gw-02`: `.48`

### VLAN 406 EDGE-DMZ

- `edge-01`: `10.240.6.41`
- `edge-02`: `10.240.6.42`
- `dns-01`: `10.240.6.43`
- `dns-02`: `10.240.6.44`
- `gw-01`: `10.240.6.47`
- `gw-02`: `10.240.6.48`

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
