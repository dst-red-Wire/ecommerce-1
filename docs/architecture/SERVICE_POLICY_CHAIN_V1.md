# Service Policy Chain V1

Status: `ACTIVE`

Architecture authority: `architecture.lock.yaml`

## Purpose

This document connects the service dependency model to the service-mesh decision. It is the human-readable companion to the machine contracts under `config/contracts/`.

## Decision chain

```text
config/contracts/dependency-map.yaml
        │
        ├── config/contracts/service-authz-policy.yaml
        ├── config/contracts/service-resilience-policy.yaml
        ├── config/contracts/service-exposure-policy.yaml
        ├── config/contracts/egress-policy.yaml
        ├── config/contracts/traffic-class-policy.yaml
        ├── config/contracts/service-slo.yaml
        └── config/contracts/mesh-observability-policy.yaml
                │
                ▼
      config/contracts/service-mesh-policy.yaml
                │
        besoin L7 réel ?
          │            │
         non          oui
          │            │
     ztunnel-only   waypoint-required
                         │
                         ▼
              config/contracts/waypoint-scope.yaml
```

Policy authority is defined separately by `config/contracts/mesh-policy-authority.yaml` so Cilium and Istio cannot both own L7 enforcement for the same flow.

## Current project decisions

- CNI and L3/L4 network-policy authority: Cilium.
- Service mesh: Istio Ambient.
- Baseline transport for all 19 business services: ztunnel with strict mTLS.
- L7 authority for Ambient-managed flows: Istio waypoint only.
- Cilium L7 enforcement on the same Ambient-managed flow: forbidden.
- Default service exposure: internal-only.
- `product`: admin-only because the currently registered public API contract is admin-scoped.
- `notification`: async-only.
- Default business egress: deny.
- Declared business egress exceptions: `payment -> stripe`, `shipping -> carrier-adapters`, `billing -> qonto-pa`, `user-profile -> keycloak-reference`.
- `payment`: only current `waypoint-required` service because it has versioned L7 authorization and traffic-policy requirements.
- SLO and generic resilience numeric targets are provisional policy targets, not measured production evidence.

## Contracts

| Contract | Role |
| --- | --- |
| `dependency-map.yaml` | Canonical synchronous and event dependencies |
| `service-authz-policy.yaml` | Default-deny caller/callee authorization matrix |
| `service-resilience-policy.yaml` | Timeouts, bounded retries, circuit-breaking and rate-limit defaults |
| `service-exposure-policy.yaml` | Internal, admin, edge or async exposure class |
| `egress-policy.yaml` | Explicit external business destinations under default-deny |
| `traffic-class-policy.yaml` | Interactive, transactional, internal-read, async, bulk, observability and external-critical classes |
| `service-slo.yaml` | Versioned service reliability/latency targets; provisional until PREPROD measurement |
| `mesh-observability-policy.yaml` | ztunnel/waypoint telemetry behavior and L7 logging constraints |
| `mesh-policy-authority.yaml` | Single authority by network/mesh layer |
| `service-mesh-policy.yaml` | Machine decision for `ztunnel-only` vs `waypoint-required` |
| `waypoint-scope.yaml` | Service/namespace/shared waypoint scope decision |

## Rules

1. A service does not receive a waypoint merely because it is critical, public, high traffic, or handles sensitive data.
2. A waypoint requires a concrete versioned L7 requirement.
3. Every L7 requirement must name its owning service and source contract.
4. External egress remains denied unless declared in `egress-policy.yaml` and grounded in the dependency model.
5. Retries on non-idempotent payment operations are forbidden.
6. Generic telemetry alone does not justify adding a waypoint; application OpenTelemetry remains independent of waypoint presence.
7. PREPROD measurements replace provisional SLO/resilience targets before PROD certification.

## Current mesh result

See `docs/architecture/SERVICE_MESH_TOPOLOGY_V1.md` for the per-service dataplane table and diagram.
