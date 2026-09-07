# MGMT WireGuard Operator Access - EXACT

Status: `EXACT`

## Decision

Permanent administrative access to Z5 uses a dedicated WireGuard gateway named `wg-01`. The gateway is a persistent MGMT infrastructure VM, is not an RKE2 member, and must not host customer-facing or Kubernetes control-plane workloads.

`config/infrastructure/network-plan.yaml` remains the sole machine-canonical source for WireGuard addresses, pools, routes, return-path policy and endpoint port. `config/contracts/mgmt-wireguard-access.yaml` is the machine-canonical source for access policy, ownership, human gates, secret delivery and threat-model controls. `config/infrastructure/mgmt-access-gateways.yaml` is the machine-canonical inventory/profile source for the dedicated non-Kubernetes access gateway.

## Gateway inventory and profile

`wg-01` is intentionally separate from `config/infrastructure/mgmt-inventory.yaml`, whose exact node set remains the six RKE2 nodes. The dedicated access-gateway inventory defines:

- node: `wg-01`;
- role: `wireguard-operator-access`;
- trust zone: `Z5`;
- lifecycle: persistent;
- profile: `wireguard-gateway`;
- resources: 2 vCPU, 2 GiB RAM, 40 GiB OS disk;
- MGMT segment: VLAN/segment 401;
- MGMT address: `10.243.1.41`;
- Kubernetes membership: false;
- public endpoint value: provider runtime output only.

The later Terraform implementation must consume this dedicated inventory explicitly and map the canonical `wireguard-gateway` profile to an exact provider server type. The architecture PR itself does not wire the inventory into Terraform and therefore does not add a provider resource to an existing plan.

## Network boundary

The exact plan is:

- gateway node: `wg-01`;
- MGMT segment-401 reservation: `10.243.1.41`;
- WireGuard tunnel: `10.246.0.0/24`;
- gateway tunnel address: `10.246.0.1`;
- workforce operator pool: `10.246.0.16/28`;
- separately controlled break-glass pool: `10.246.0.240/29`;
- public endpoint: provider-assigned address injected only at runtime;
- transport: UDP/51820;
- routes exposed through the tunnel: permanent MGMT `10.243.0.0/16` only.

The WireGuard pool must remain disjoint from PREPROD, PROD-A, PROD-B, permanent MGMT underlay, and every Kubernetes Pod/Service CIDR. Direct routes to Kubernetes Pod/Service networks are forbidden by this contract. Kubernetes API access is reached through its MGMT underlay address, not by routing Pod/Service CIDRs to operators.

`wg-01` is an access gateway, not the default L3 gateway for segment 401. Its `10.243.1.41` reservation therefore belongs to the infrastructure-VM range rather than the `.1-.9` network gateway/VIP range.

## Exact return path

The return path is **SNAT on `wg-01`**, not a static route from MGMT to the WireGuard tunnel. For packets with source `10.246.0.0/24` and destination `10.243.0.0/16`, `wg-01` translates the source to `10.243.1.41`. Stateful connection tracking on `wg-01` returns response traffic to the originating WireGuard peer.

This policy is deliberately narrow:

- SNAT source domain: `10.246.0.0/24` only;
- SNAT destination domain: `10.243.0.0/16` only;
- translated source: `10.243.1.41` only;
- no NAT policy is authorized for Pod, Service, PREPROD, PROD or Internet destinations;
- no static route to `10.246.0.0/24` is required on MGMT nodes.

The attribution consequence is explicit: downstream MGMT services see `10.243.1.41` as the network source. Per-operator attribution therefore belongs to audited WireGuard peer and forwarding records on `wg-01`, correlated with workforce identity. Any future change from SNAT to routed peer addresses is an architecture/network-policy change and requires the routing human gate.

## Identity and key boundary

WireGuard is only the encrypted network transport. Authorization to issue or revoke privileged operator access belongs to workforce IAM. Customer identities are never accepted for this path, and privileged workforce authorization requires the hardware-backed WebAuthn/passkey policy already defined for Z5.

OpenBao is the secret authority for gateway material and centrally controlled peer metadata. Ansible owns runtime retrieval and rendering on the non-Kubernetes gateway; ESO is explicitly not used for `wg-01`.

Canonical secret references are names/paths only; secret values never enter Git:

- gateway private key: OpenBao KV `mgmt/wireguard/wg-01`, field `private_key`;
- normal peer public keys: OpenBao KV prefix `mgmt/wireguard/peers/`, field `public_key`;
- operator peer private keys: generated/stored on the operator device only; central storage is forbidden;
- break-glass private keys: OpenBao KV prefix `mgmt/wireguard/break-glass/`, separately controlled.

Ansible authenticates to OpenBao using a runtime-injected, non-persisted credential and renders gateway secret state with root-only mode `0600`. No WireGuard private key material is committed, logged, placed in Terraform state, or passed through Kubernetes/ESO for this host.

## Ownership

Terraform/OpenTofu owns provider resources: the `wg-01` VM, provider network attachment, runtime public endpoint and provider firewall. Ansible owns Rocky Linux state: WireGuard package/configuration, stateful forwarding/SNAT, host firewall, OpenBao secret retrieval and root-only host rendering. OpenBao owns the authoritative centrally managed secret records. Kubernetes/Fleet is not an authority for this host.

A later implementation PR may encode those resources only after this contract is merged. This architecture PR does not create a VM, open UDP/51820, modify routes/NAT, retrieve secrets, or generate keys.

## Human gates

Explicit human authorization is required immediately before:

- provider apply that creates or changes `wg-01`;
- activation or widening of public ingress;
- changes to allowed MGMT routes or return-path/NAT policy;
- creation, rotation, revocation or replacement of gateway/operator/break-glass key material.

Static validation and plans may run before those gates; remote state mutation may not.

## Threat-model delta

The new boundary is an Internet-reachable encrypted transport from Z0 into permanent MGMT Z5. The required threats and controls are machine-recorded in `config/contracts/mgmt-wireguard-access.yaml`:

- Internet scanning: expose only the WireGuard UDP endpoint behind default-deny provider policy and no public management services.
- Stolen operator key: use per-operator peer identity, workforce-authorized issuance and deterministic peer revocation.
- Over-broad routes: expose only the permanent MGMT route, deny forwarding by default, and never route Pod/Service CIDRs.
- Gateway compromise: isolate WireGuard on a dedicated non-Kubernetes host, keep least privilege/audit, and rebuild rather than manually clean after compromise.
- Break-glass misuse: use a separate address pool, separate control path, audited activation and explicit human authorization.

The SNAT design adds an audit requirement because downstream services see the gateway address. `wg-01` must therefore retain peer-to-flow audit evidence sufficient to correlate the translated flow with the authorized workforce or break-glass peer.

## Bootstrap and runtime evidence

Provider-assigned public addresses are runtime values and must never be copied into versioned contracts. Any bootstrap transport used before WireGuard is ready must consume reviewed provider outputs, remain runtime-only, and be removed or denied once the controlled WireGuard path is proven.

Runtime acceptance for the later implementation requires evidence that:

- the tunnel reaches approved `10.243.0.0/16` destinations;
- return traffic succeeds through the exact stateful SNAT policy;
- downstream traffic is translated only to `10.243.1.41`;
- peer-to-flow audit correlation is present on `wg-01`;
- Pod/Service CIDRs are not routed or NATed;
- no unapproved public management endpoint remains active;
- OpenBao retrieval leaves no secret value in Git, Terraform state or logs.
