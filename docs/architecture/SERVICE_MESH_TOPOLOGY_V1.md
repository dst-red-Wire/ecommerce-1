# Service Mesh Topology V1

Status: `ACTIVE`

Architecture authority: `architecture.lock.yaml`

Machine policy: `config/contracts/service-mesh-policy.yaml`

## Purpose

This document describes the service-mesh dataplane assignment for every canonical business service. The machine-readable contract remains authoritative for enforcement.

The baseline is Cilium for Kubernetes networking and Istio Ambient for service-to-service mesh capabilities. Every service uses ztunnel with strict mTLS. A waypoint is added only when a versioned L7 routing, authorization, or traffic-policy requirement exists.

## Decision rule

```text
all L7 flags false
  -> ztunnel-only

one or more L7 flags true
  -> versioned justification required
  -> waypoint-required
```

Business criticality, sensitive data, public exposure, high traffic, or possible future L7 needs do not by themselves justify a waypoint.

## Responsibility split

| Layer | Authority | Responsibility |
| --- | --- | --- |
| Kubernetes networking | Cilium | CNI, eBPF dataplane, L3/L4 connectivity and network policy |
| Mesh transport | Istio Ambient ztunnel | workload-to-workload transport and strict mTLS |
| Mesh L7 | Istio waypoint | only justified HTTP/gRPC routing, authorization, or traffic policy |
| Runtime security | Tetragon | runtime observability and enforcement |
| Workload identity | SPIRE | workload identity source |

Cilium and Istio must not both own L7 policy for the same flow.

## Canonical service assignments

| Service | L7 routing | L7 authorization | L7 traffic policy | Dataplane | Source contracts |
| --- | --- | --- | --- | --- | --- |
| `catalog` | false | false | false | `ztunnel-only` | none |
| `product` | false | false | false | `ztunnel-only` | none |
| `inventory` | false | false | false | `ztunnel-only` | none |
| `cart` | false | false | false | `ztunnel-only` | none |
| `checkout` | false | false | false | `ztunnel-only` | none |
| `pricing` | false | false | false | `ztunnel-only` | none |
| `tax` | false | false | false | `ztunnel-only` | none |
| `order` | false | false | false | `ztunnel-only` | none |
| `payment` | false | true | true | `waypoint-required` | `contracts/payment-security.yaml`, `contracts/payment-runtime.yaml` |
| `fulfillment` | false | false | false | `ztunnel-only` | none |
| `shipping` | false | false | false | `ztunnel-only` | none |
| `tracking` | false | false | false | `ztunnel-only` | none |
| `returns` | false | false | false | `ztunnel-only` | none |
| `billing` | false | false | false | `ztunnel-only` | none |
| `fraud-risk` | false | false | false | `ztunnel-only` | none |
| `search` | false | false | false | `ztunnel-only` | none |
| `review` | false | false | false | `ztunnel-only` | none |
| `user-profile` | false | false | false | `ztunnel-only` | none |
| `notification` | false | false | false | `ztunnel-only` | none |

## Payment waypoint

`payment` is currently the only canonical service with an L7 requirement. Its waypoint is required for two independently versioned reasons:

1. `l7.authorization`: method-aware authorization, defined by `contracts/payment-security.yaml`.
2. `l7.traffic_policy`: service-specific timeout and retry behavior, defined by `contracts/payment-runtime.yaml`.

The timeout/retry requirement is subject to payment idempotency. A retry policy must not be introduced for non-idempotent payment operations without an explicit idempotency contract.

## Change process for any service

To promote any other service from `ztunnel-only` to `waypoint-required`:

1. Add a versioned source contract that states the concrete L7 requirement.
2. Set the corresponding `l7.routing`, `l7.authorization`, or `l7.traffic_policy` flag to `true` in `config/contracts/service-mesh-policy.yaml`.
3. Set `dataplane: waypoint-required`.
4. Add a justification entry with `owner`, `capability`, `reason`, and `source_contract`.
5. Update this topology document.
6. Run `make governance`.

To remove a waypoint, remove the last versioned L7 requirement, set all three flags to `false`, remove the obsolete justifications, and restore `dataplane: ztunnel-only`.

## Governance

`make governance` and `python3 scripts/repoctl.py governance` enforce the machine policy. They must fail if the dataplane conflicts with the L7 flags, if a true L7 capability lacks justification, or if the service set diverges from the canonical 19 services.
