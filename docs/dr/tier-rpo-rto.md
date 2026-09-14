# Tier / RPO / RTO Matrix

This document is the repository source of truth for the initial DR classification. Targets are baselines until validated by measured exercises.

| Component / data | Tier | RPO target | RTO DR target | Recovery strategy | Owner |
|---|---|---:|---:|---|---|
| DNS / GSLB | Tier-0 | <= 15 min | <= 30 min | multi-site authoritative DNS, replication, snapshots/versioning, independent off-site copy | Platform/SRE |
| Edge/API: HAProxy, Caddy, Coraza, Kong, Istio Gateway | Tier-0 | 0 for Git config | <= 30 min | stateless replicas, GitOps, certificate recovery | Platform/SRE |
| OpenBao / PKI | Tier-0 | <= 15 min | <= 30 min | Raft HA, encrypted snapshots, off-site copy, HSM separated from backups | Security/Platform |
| SPIRE | Tier-0 | <= 15 min non-reconstructible state | <= 30 min | HA, Git config, datastore backup, protected trust roots | Security/Platform |
| Keycloak / IAM | Tier-0 | <= 15 min | <= 30 min | replicas, PostgreSQL HA/PITR, versioned realm/config export where appropriate | IAM/Platform |
| GitOps / FluxCD | Tier-0 recovery dependency | 0 for committed Git state | <= 30 min bootstrap; <= 2 h platform rebuild | Git source of truth, mirrored/backup repository, automated bootstrap | Platform |
| Kubernetes declarative state | Tier-0 | 0 for Git state | <= 2 h full site rebuild | GitOps plus Velero/CSI for non-reconstructible state | Platform |
| Cilium / network policy | Tier-0 | 0 for Git config | <= 30 min after cluster available | GitOps rebuild | Platform/Network |
| Rook-Ceph | Tier-0 | must satisfy hosted workload RPO | <= 1 h degraded service; <= 4 h rebuild | Ceph replication, scrubbing, monitoring, independent application backups | Storage/Platform |
| PostgreSQL critical | Tier-0 | <= 5 min | <= 30 min | CloudNativePG, WAL/PITR, off-site backups, fencing | Database/Platform |
| PostgreSQL non-critical | Tier-1 | <= 15 min | <= 2 h | CloudNativePG PITR and tested restore | Database/Platform |
| Kafka critical topics | Tier-0 | <= 5 min inter-site | <= 30 min | RF=3, minISR=2, MirrorMaker2, idempotence, controlled replay | Messaging/Platform |
| Kafka non-critical topics | Tier-1 | <= 60 min | <= 4 h | MirrorMaker2, replay/rebuild | Messaging/Platform |
| Apicurio Registry | Tier-0 | <= 15 min | <= 30 min | HA registry backup/export; Protobuf/Buf contracts in Git | Platform/API Governance |
| RabbitMQ Quorum Queues | Tier-1 | <= 15 min for critical persistent queues | <= 1 h | 3-node quorum queues, declarative definitions, DLQ/retry, idempotent publishers | Messaging/Platform |
| Redis Cluster | Tier-1 | no durable business data permitted | <= 30 min | HA cluster and rebuild from authoritative sources | Platform |
| OpenSearch / CQRS projections | Tier-1 reconstructible | 0 relative to authoritative sources | <= 4 h full rebuild | rebuild from PostgreSQL/Kafka, versioned templates | Search/Platform |
| MinIO critical objects | Tier-1 | <= 15 min | <= 2 h | versioning, replication, Object Lock per bucket | Storage/Platform |
| MinIO DR backup repository | Tier-0 recovery dependency | source-system RPO | <= 2 h | Object Lock, encryption, independent/off-site copy | Storage/Platform |
| Harbor registry | Tier-0 recovery dependency | <= 1 h metadata; artifacts addressed by digest | <= 1 h | registry replication, metadata backup, immutable artifacts, reproducible builds | Platform/CI |
| Prometheus / Alertmanager | Tier-1 with Tier-0 alerting role | <= 1 h metrics; 0 for Git rules | <= 1 h | HA, GitOps rules, durable/remote storage if used | Observability |
| Splunk / SIEM | Tier-1 security | <= 1 h critical security logs | <= 4 h | buffering, durable storage, tested SIEM recovery | Security/Observability |
| ATS cache | Tier-1 reconstructible | 0 for Git config | <= 1 h | GitOps, cache rebuilt from origins | Edge/Platform |

## Rules

- `RPO = 0` is allowed only for state that is truly reconstructible from Git or another authoritative source.
- Replication alone is not a backup.
- Caches and projections must not become hidden sources of truth.
- A Tier-0 recovery dependency must be restored or made available before dependent workloads in a clean-site bootstrap.
- Component owners must validate their target by measurement and raise a corrective issue when observed results exceed the target.

## Validation status

The classification above is **proposed and versioned**, but not yet contractually validated. Validation requires successful restore/failover evidence as defined in `testing-policy.md`.