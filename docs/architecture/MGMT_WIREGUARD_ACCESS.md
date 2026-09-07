# MGMT WireGuard Operator Access - EXACT

Status: `EXACT`

## Decision

Permanent administrative access to Z5 uses a dedicated WireGuard gateway named `wg-01`. The gateway is a persistent MGMT infrastructure VM, is not an RKE2 member, and must not host customer-facing or Kubernetes control-plane workloads.

`config/infrastructure/network-plan.yaml` remains the sole machine-canonical source for WireGuard addresses, pools, routes and endpoint port. `config/contracts/mgmt-wireguard-access.yaml` is the machine-canonical source for access policy, ownership, human gates and threat-model controls.

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

## Identity and key boundary

WireGuard is only the encrypted network transport. Authorization to issue or revoke privileged operator access belongs to workforce IAM. Customer identities are never accepted for this path, and privileged workforce authorization requires the hardware-backed WebAuthn/passkey policy already defined for Z5.

No WireGuard key material is stored in Git. Gateway private keys and peer key material are runtime-only and are injected through an approved secret channel. Break-glass peers are controlled separately from normal workforce peers.

## Ownership

Terraform/OpenTofu owns provider resources: the `wg-01` VM, provider network attachment, runtime public endpoint and provider firewall. Ansible owns Rocky Linux state: WireGuard package/configuration, host routing and host firewall. Kubernetes/Fleet is not an authority for this host.

A later implementation PR may encode those resources only after this contract is merged. This architecture PR does not create a VM, open UDP/51820, modify routes, or generate keys.

## Human gates

Explicit human authorization is required immediately before:

- provider apply that creates or changes `wg-01`;
- activation or widening of public ingress;
- changes to allowed MGMT routes;
- creation, rotation, revocation or replacement of operator/break-glass peer material.

Static validation and plans may run before those gates; remote state mutation may not.

## Threat-model delta

The new boundary is an Internet-reachable encrypted transport from Z0 into permanent MGMT Z5. The required threats and controls are machine-recorded in `config/contracts/mgmt-wireguard-access.yaml`:

- Internet scanning: expose only the WireGuard UDP endpoint behind default-deny provider policy and no public management services.
- Stolen operator key: use per-operator peer identity, workforce-authorized issuance and deterministic peer revocation.
- Over-broad routes: expose only the permanent MGMT route, deny forwarding by default, and never route Pod/Service CIDRs.
- Gateway compromise: isolate WireGuard on a dedicated non-Kubernetes host, keep least privilege/audit, and rebuild rather than manually clean after compromise.
- Break-glass misuse: use a separate address pool, separate control path, audited activation and explicit human authorization.

## Bootstrap and runtime evidence

Provider-assigned public addresses are runtime values and must never be copied into versioned contracts. Any bootstrap transport used before WireGuard is ready must consume reviewed provider outputs, remain runtime-only, and be removed or denied once the controlled WireGuard path is proven.

Runtime acceptance for the later implementation requires evidence that the tunnel reaches approved `10.243.0.0/16` destinations, that Pod/Service CIDRs are not routed, and that no unapproved public management endpoint remains active.
