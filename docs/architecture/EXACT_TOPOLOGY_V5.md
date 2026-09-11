# EXACT TOPOLOGY V5 — DERIVED INDEX

Status: `EXACT`

`architecture.lock.yaml` is the single canonical architecture authority. This index is derived from version 5 of that lock; it explains and links its contracts, has no independent authority, and cannot override the lock. These are approved targets, not evidence of deployed infrastructure.

## Global flow

```text
Clients Web/Mobile
  -> ClouDNS registrar / public DNS
  -> PowerDNS + dnsdist + external secondary
  -> PROD-A or PROD-B

api:
  HAProxy -> Caddy + Coraza -> Kong -> Istio Gateway -> Go services

www:
  ATS -> Storefront Go + templ + HTMX

admin:
  ATS -> Admin Go + templ + HTMX

cdn:
  ATS -> SeaweedFS S3 assets
```

The critical DNS/GSLB TTL is locked at 60 seconds by `architecture.lock.yaml`; DNS changes remain after fencing and write-authority decisions in the recovery sequence.

## PROD sites

```text
PROD-A                                      PROD-B
3 physical failure domains                 3 physical failure domains
3 CP + 5 workers                           3 CP + 5 workers
3 data workers + 2 general                3 data workers + 2 general
2 gateways + 2 edge                       2 gateways + 2 edge

         <--- MirrorMaker2 / controlled replication --->
         <--- home_site + fencing authority ---------->
```

Exact placement: `PROD_TOPOLOGY_V2.md` + `config/infrastructure/prod-inventory.yaml`.

## PREPROD JIT

```text
PVE-01: cp-01 + worker-01 + edge-01 + dns-01 + gw-01
PVE-02: cp-02 + worker-02 + edge-02 + squid-01
PVE-03: cp-03 + worker-03 + dns-02 + squid-02 + gw-02

CREATE -> VALIDATE -> ARCHIVE -> DESTROY -> VERIFY ZERO RESOURCE
```

Exact placement/sizing: `PREPROD_TOPOLOGY_V2.md` + `config/infrastructure/preprod-inventory.yaml`.

## Network

Private blocks:

- PREPROD `10.240.0.0/16`
- PROD-A `10.241.0.0/16`
- PROD-B `10.242.0.0/16`
- permanent MGMT `10.243.0.0/16`

VLAN functions 401-406 and exact allocations are in `NETWORK_IPAM_CONTRACT.md` and `config/infrastructure/network-plan.yaml`.

Permanent operator access to Z5 is defined by `MGMT_WIREGUARD_ACCESS.md`. WireGuard CIDRs, reservations and routes remain machine-canonical only in `config/infrastructure/network-plan.yaml`; access policy and threat controls are machine-canonical in `config/contracts/mgmt-wireguard-access.yaml`. Dedicated gateway identity/sizing is machine-canonical in `config/infrastructure/mgmt-access-gateways.yaml`.

## Storage

PREPROD worker:

```text
NVMe-1 LocalPV-A
NVMe-2 LocalPV-B
NVMe-3 reserved conditional block/RWX campaign only
NVMe-4 SeaweedFS volume disk 1
NVMe-5 SeaweedFS volume disk 2
NVMe-6 spare
```

PROD data host:

```text
NVMe-1 LocalPV-A
NVMe-2 LocalPV-B
NVMe-3 SeaweedFS volume disk 1
NVMe-4 spare
NVMe-5 SeaweedFS volume disk 2
```

No default Ceph. No active MinIO CE. See `STORAGE_TOPOLOGY_V2.md` and `config/infrastructure/storage-plan.yaml`.

## Application ownership

Exactly 19 backend services, as listed in `architecture.lock.yaml` business.services:

`catalog`, `product`, `inventory`, `cart`, `checkout`, `pricing`, `tax`, `order`, `payment`, `fulfillment`, `shipping`, `tracking`, `returns`, `billing`, `fraud-risk`, `search`, `review`, `user-profile`, `notification`.

Checkout and fulfillment are autonomous services. Checkout owns pre-order orchestration; order owns the durable order snapshot; fulfillment owns physical execution orchestration.

The storefront and admin target Go + templ + HTMX in `frontend/go.mod`. Next.js/React/Node is only the migration source, not the target PROD runtime.

- authority/dependencies: `SERVICE_OWNERSHIP_MATRIX.md`
- data ownership: `DATA_OWNERSHIP_MATRIX.md`
- durable events: `EVENT_CONTRACT_MATRIX.md`
- machine dependency map: `config/contracts/dependency-map.yaml`

## Security

Trust zones and IAM/workload identity boundaries: `SECURITY_TRUST_ZONES.md`. The exact Z0-to-Z5 WireGuard operator-access boundary, ownership and threat-model delta are defined by `MGMT_WIREGUARD_ACCESS.md`.

## Delivery

```text
Gitea -> Tekton -> Harbor -> Fleet -> RKE2 -> Argo Rollouts
```

`DEPLOYMENT_DAG.md` and `config/infrastructure/deployment-waves.yaml` define dependency waves, gates and destruction order.

## AIOps

`AIOPS_TOPOLOGY_V1.md` defines permanent MGMT control-plane, GPU JIT, evidence path, deterministic verifier, L1/L2/L3 authority and kill-switch boundaries.

## MLOps

The lock’s `mlops` block selects lakeFS for dataset versioning, SeaweedFS S3 for objects, CloudNativePG PostgreSQL for metadata, MLflow for experiments/lineage and Harbor for artifacts. Gitea GitOps owns promotion, Tekton orchestration, Rancher Fleet desired state and Argo Rollouts progressive delivery. Runtime is KServe/vLLM; drift uses Evidently in Tekton batch jobs. DVC is superseded by lakeFS. `MLOPS_TOPOLOGY_V1.md` supplies subordinate lifecycle detail.

## Observability

The derived role assignments below mirror the lock’s `observability` mapping exactly:

- `telemetry`: `opentelemetry`
- `application_gateway`: `rotel`
- `infrastructure_collector`: `opentelemetry-collector`
- `metrics_protocol`: `prometheus`
- `metrics_scraper`: `vmagent`
- `metrics`: `victoriametrics`
- `infrastructure_logs`: `victorialogs`
- `application_observability_storage`: `clickhouse`
- `application_observability_ui`: `hyperdx`
- `hyperdx_metadata_store`: `mongodb-oss-self-hosted`
- `alerts`: `vmalert`
- `notifications`: `alertmanager`
- `dashboards`: `grafana`
- `security_pipeline`: `data-prepper`
- `security_logs`: `opensearch`
- `security`: `wazuh`

`OBSERVABILITY_TOPOLOGY_V1.md` is subordinate detail; the lock prevails.

## Build dependencies

M2.5 is `M2-5-persistent-mgmt-bootstrap`, a persistent management-plane bootstrap independent of PREPROD JIT. Provider and bootstrap human gates remain unchanged in the lock.

The lock’s `milestone_dependencies` maps each milestone to its prerequisites: M0 → M1; M1 → M2 and M2.5; M2.5 → M3 → M4; M2 + M4 → M5 → M6 → M7 → M8 → M9.

## Machine governance contracts

`config/contracts/resilience-governance.yaml` encodes existing compromise, evidence and recovery constraints. `config/contracts/security-trust-zones.yaml` indexes Z0–Z6 and encodes existing identity boundaries. Both are subordinate to `architecture.lock.yaml`; neither creates deployment authority.

## Status rule

If implementation differs from an exact contract, Codex must report `BLOCKED_ARCHITECTURE`; it must not silently reinterpret the topology.

## Superseded visual references

Any diagram that shows MinIO CE, FluxCD, Flagger, Splunk baseline, Loki baseline, default Rook-Ceph, or 5 physical PROD hosts/site is historical unless explicitly marked as a functional historical view.
