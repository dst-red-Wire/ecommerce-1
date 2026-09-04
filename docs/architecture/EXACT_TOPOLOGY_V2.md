# EXACT TOPOLOGY V2 — AUTHORITATIVE INDEX

Status: `EXACT`

This file is the entrypoint for deterministic infrastructure/application topology. It is not a second baseline; it indexes the exact contracts that refine `BASELINE_V2.md`.

## Global flow

```text
Clients Web/Mobile
  -> ClouDNS registrar / public DNS
  -> PowerDNS + dnsdist + external secondary
  -> PROD-A or PROD-B

api:
  HAProxy -> Caddy + Coraza -> Kong -> Istio Gateway -> Go services

www:
  ATS -> Storefront Next.js

admin:
  ATS -> Admin Next.js

cdn:
  ATS -> SeaweedFS S3 assets
```

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

Exactly 17 Go services. No checkout service. `order` orchestrates checkout.

- authority/dependencies: `SERVICE_OWNERSHIP_MATRIX.md`
- data ownership: `DATA_OWNERSHIP_MATRIX.md`
- durable events: `EVENT_CONTRACT_MATRIX.md`
- machine dependency map: `config/contracts/dependency-map.yaml`

## Security

Trust zones and IAM/workload identity boundaries: `SECURITY_TRUST_ZONES.md`.

## Delivery

```text
Gitea -> Tekton -> Harbor -> Fleet -> RKE2 -> Argo Rollouts
```

`DEPLOYMENT_DAG.md` and `config/infrastructure/deployment-waves.yaml` define dependency waves, gates and destruction order.

## AIOps

`AIOPS_TOPOLOGY_V1.md` defines permanent MGMT control-plane, GPU JIT, evidence path, deterministic verifier, L1/L2/L3 authority and kill-switch boundaries.

## MLOps

`MLOPS_TOPOLOGY_V1.md` defines DVC/Git/SeaweedFS dataset lineage, MLflow metadata, Harbor Modelcars, deterministic gates, champion/challenger, bounded retraining and recovery.

## Status rule

If implementation differs from an exact contract, Codex must report `BLOCKED_ARCHITECTURE`; it must not silently reinterpret the topology.

## Superseded visual references

Any diagram that shows MinIO CE, FluxCD, Flagger, Splunk baseline, Loki baseline, default Rook-Ceph, or 5 physical PROD hosts/site is historical unless explicitly marked as a functional historical view.
