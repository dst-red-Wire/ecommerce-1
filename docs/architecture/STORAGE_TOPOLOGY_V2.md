# STORAGE TOPOLOGY V2 — EXACT

Status: `EXACT`

## Principles

- PostgreSQL, Kafka and other engine-replicated state use LocalPV/raw NVMe where defined by their operators.
- SeaweedFS S3 is the object-storage target for new PROD/PREPROD qualification.
- Ceph is not part of the default launch baseline.
- Redis and OpenSearch are reconstructible/replaceable according to their owning data contract; neither may become a hidden source of truth.
- Replication is not backup.

## PREPROD physical mapping per worker host

| Device | Active use |
|---|---|
| NVMe-1 | LocalPV-A |
| NVMe-2 | LocalPV-B |
| NVMe-3 | reserved for explicitly approved block/RWX campaign; unused by launch baseline |
| NVMe-4 | SeaweedFS volume-server data disk 1 |
| NVMe-5 | SeaweedFS volume-server data disk 2 |
| NVMe-6 | spare/replacement reserve |

LocalPV volumes use XFS, static PVs, `nodeAffinity`, `kubernetes.io/no-provisioner`, `WaitForFirstConsumer` and `Retain` where applicable.
SeaweedFS volume servers bind only to `localpv-seaweedfs`, whose dedicated pools are `seaweedfs-volume-1` and
`seaweedfs-volume-2`; reuse of generic `localpv-a`/`localpv-b` is forbidden. PREPROD maps those pools to NVMe-4/NVMe-5,
while PROD retains the exact NVMe-3/NVMe-5 per-data-host mapping.

## SeaweedFS

Minimum topology:

- 3 masters using Raft, strict anti-affinity across worker/physical failure domains;
- 3 volume servers, one per worker/failure domain;
- each volume server owns two dedicated devices: NVMe-4 and NVMe-5 of its host;
- >=2 filers with anti-affinity;
- >=2 S3 gateways with anti-affinity;
- bucket-level identity/isolation;
- ATS has read-only access to the `cdn-assets` scope and no access to backup, archive, or MLOps scopes;
- versioning/Object Lock/immutability only where the workload/evidence/backup policy requires it;
- encryption and restore validation required before PROD admission.

SeaweedFS objects used as immutable evidence/backup must have an independent copy outside the failure domain they protect. PROD uses the opposite PROD site; PREPROD uses the persistent `preprod-jit-external-archive` authority, never the nonexistent opposite site of mono-site `preprod-jit`. This same authority binds SeaweedFS object data, lakeFS/MLflow metadata and the Keycloak IAM database. Its provider, endpoint, bucket and credential remain explicit unresolved prerequisites rather than fabricated values. Teardown fails closed until archive integrity and restore-validation evidence exist; static contracts never claim that evidence is already proven.

## PostgreSQL / CNPG

- one domain-owned database boundary per owning service or approved shared platform database; `keycloak-database` is a dedicated platform-IAM CNPG boundary and never one of the 19 service-owned databases;
- no cross-service table reads;
- 3 instances for critical deployments where the environment/capacity model requires HA;
- synchronous durability for Tier-0 paths according to release/stateful policy;
- Barman/PITR-compatible backup path to independent S3/object storage;
- single-writer/home-site authority across PROD sites.

## Kafka / Strimzi

Per site:

- KRaft mode;
- 3 controllers;
- 3 brokers;
- replication factor 3 for critical topics;
- `min.insync.replicas=2` for critical topics;
- LocalPV-backed broker storage;
- MirrorMaker2 for inter-site replication where defined by event policy.

Kafka replication is not a substitute for archival/backup or reproducible topic/schema configuration.

## RabbitMQ

- 3-node resilient deployment per site where production topology applies;
- Quorum Queues for durable operational jobs;
- DLQ/retry policies declared as code;
- no authoritative business state exists only in RabbitMQ.

## Redis

- local/site Redis Cluster;
- cache, cart acceleration, rate-limit or ephemeral coordination only when the owning service contract allows it;
- any value required for recovery must be derivable from an authoritative store/event stream.

## OpenSearch

- search/read models only;
- templates/mappings versioned;
- index rebuild path from authoritative data/events mandatory;
- rebuild RTO measured in M7/M8.

## Observability stateful storage

The exact machine contract is `config/infrastructure/storage-plan.yaml`. The `localpv-observability` class uses
static RWO LocalPV paths on `localpv-a`/`localpv-b`, XFS with project quotas, LUKS2 at rest,
`WaitForFirstConsumer` and `Retain`. A single PV or LocalPV path is never reused. Multiple isolated PV paths may
share a physical NVMe; same-engine replicas must remain in distinct worker/physical failure domains.

| Engine | HA model | PREPROD retention / RPO / RTO | PROD retention / RPO / RTO | Backup method |
|---|---|---|---|---|
| VictoriaMetrics | 3 vmstorage, RF=2 | 14d / 12h / 4h | 90d / 6h / 2h | vmbackup/vmrestore -> SeaweedFS S3 |
| VictoriaLogs | 3 sharded vlstorage, no replication | 14d / 12h / 4h | 30d / 6h / 2h | partition snapshots -> SeaweedFS S3 |
| ClickHouse | 1 shard x 3 replicas + Keeper 3 | 7d / 12h / 4h | 30d / 6h / 4h | native BACKUP/RESTORE -> SeaweedFS S3 |
| MongoDB Community | 3-member replica set | metadata lifecycle / 12h / 2h | metadata lifecycle / 6h / 2h | oplog-consistent dump/restore -> SeaweedFS S3 |
| OpenSearch Security | 3 manager/data nodes, index replica=1 | 14d / 12h / 4h | 30d hot + 365d snapshots / 1h / 4h | snapshot repository-s3 -> SeaweedFS S3 |

MGMT status is `deferred`; PREPROD and PROD are `required`. PROD deploys independent per-site clusters and
forbids stretched database quorums. PROD backup objects must reside in the opposite PROD site failure domain.
Secrets come from OpenBao through ESO and are never versioned. Network access is private and least-privilege.
MongoDB is HyperDX-metadata-only; OpenSearch Security is SIEM/security-only.

VictoriaLogs sharding is not replication. A missing `vlstorage` makes queries fail closed until the affected
partition data is restored. This failure mode is intentional and machine-validated.

## Backup separation

Backups for Tier-0/Tier-1 authoritative data must be restorable without relying on the cluster/site being recovered. Encryption keys/trust material must not be co-located only with the backups they protect.

## Admission checks

Codex must provide static/runtime checks proving:

- no active MinIO CE dependency;
- no default Ceph deployment;
- SeaweedFS masters/volumes/filers/gateways satisfy anti-affinity;
- LocalPV claims bind to the intended node/device class;
- backup targets are distinct from source failure domains;
- restore checks exist for PostgreSQL and object evidence;
- reconstructible stores have deterministic rebuild procedures.
