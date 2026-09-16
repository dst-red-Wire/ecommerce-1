# Architecture Boundaries V1

Status: `ACTIVE`

Architecture authority: `architecture.lock.yaml`

## Purpose

This document summarizes the cross-domain responsibility boundaries enforced by machine contracts and `make governance`.

## Locked authorities

| Concern | Authority | Notes |
| --- | --- | --- |
| Human identity | Keycloak | OIDC/JWT |
| Workload identity | SPIRE | SPIFFE identity |
| Edge JWT validation | Kong | Human token validation at API edge |
| Public TLS / HTTP2 / HTTP3 | Caddy | Coraza provides WAF policy |
| Transport LB / VIP | HAProxy | No TLS termination or API policy |
| Public API policy / rate limit | Kong | No canary traffic weighting |
| Mesh ingress | Istio Gateway | Entry to Ambient mesh |
| Mesh transport | Istio Ambient ztunnel | Strict mTLS |
| Internal justified L7 | Istio waypoint | Only when machine policy requires it |
| Kubernetes networking L3/L4 | Cilium | CNI/eBPF/NetworkPolicy |
| Runtime security | Tetragon | Runtime enforcement/visibility |
| Public certificate automation | Caddy ACME | Provider configurable, renewal automatic |
| Mesh workload certificates | SPIRE/Istio Ambient | Automatic workload identity lifecycle |
| Secret source | OpenBao | Source of truth |
| Kubernetes secret sync | External Secrets Operator | Materialization only |
| Public authoritative DNS | PowerDNS | DNSSEC required |
| DNS frontend | dnsdist | Query routing/health |
| Kubernetes discovery | CoreDNS | Cluster service discovery |
| Recursive DNS | Unbound | Internal recursive/cache |
| DNS record writer | ExternalDNS | Controlled writer to PowerDNS |
| Rollout decision | Argo Rollouts | Single rollout decision authority |
| Canary traffic shifting | Istio | Argo controls weights, Istio executes |
| GitOps desired state | Rancher Fleet | CI does not deploy directly |
| CI authority | Tekton | Validation/build only |
| Public API rate limiting | Kong | Versioned route/budget required |
| Internal L7 rate limiting | Istio waypoint | Only for services already requiring waypoint |
| Business rate limits | Application | Never encoded as NetworkPolicy |
| Checkout transaction orchestration | checkout | Does not own order/payment state |
| Durable order lifecycle | order | Durable commercial snapshot |
| Payment state | payment | Stripe is current external PSP dependency |
| Inventory state | inventory | Reserve/release authority |
| Fulfillment lifecycle | fulfillment | Starts only after order confirmation |

## Automated derivation

The architecture favors generated policy over hand-maintained duplication:

- caller/callee authorization is derived from `dependency-map.yaml`;
- business egress destinations are derived from `sync_external`;
- waypoint presence is derived from versioned L7 requirements;
- waypoint observability follows the effective mesh dataplane;
- resilience class follows traffic class;
- external NetworkPolicy must be generated from `egress-runtime-policy.yaml`;
- rollout traffic weights are owned by Argo Rollouts and realized by Istio;
- secrets are sourced from OpenBao and synchronized automatically by ESO;
- public certificate issuance/renewal is automated by Caddy.

## Fail-closed runtime inputs

Two runtime areas intentionally remain unresolved rather than guessed:

1. Internal NTP source addresses/names.
2. Concrete external FQDNs for Stripe, carrier adapters, Qonto and the Keycloak reference endpoint.

`time-authority-policy.yaml` and `egress-runtime-policy.yaml` mark these values as `unresolved-runtime-input`. Real provisioning must fail until approved values are versioned.

## Commerce saga boundary

```text
checkout
   ├─ cart
   ├─ pricing
   ├─ tax
   ├─ inventory reserve
   ├─ fraud decision
   ├─ shipping quote/selection
   └─ order creation
          │
          ▼
       payment
          │
    authorized/failed
          │
          ▼
        order
      confirmed
          │
          ▼
     fulfillment
```

There is no distributed two-phase commit. Domain events use transactional outbox and consumers are idempotent. Compensation is explicit for stock reservation, payment failure/cancellation and downstream fulfillment failure.

## Governance

`python3 scripts/repoctl.py governance` discovers the architecture authority tests, including the boundary validator. `make governance` therefore enforces these contracts without a separate manually maintained execution path.

Primary validators:

- `scripts/validate-architecture-boundaries.rb`
- `scripts/validate-service-policy-chain.rb`
- `scripts/validate-service-mesh-policy.rb`

Any new authority overlap should be resolved by assigning exactly one owner and then adding a mutation test that proves governance rejects the competing assignment.
