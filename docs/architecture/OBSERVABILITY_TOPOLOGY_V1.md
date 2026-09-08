# Observability topology v1

This document explains the exact machine contract in `config/contracts/observability-topology.yaml`.
The YAML contract is authoritative when prose and machine-readable state disagree.

## Responsibility split

Application telemetry uses OpenTelemetry instrumentation and OTLP. Rotel is the application edge gateway.
Application traces and logs flow to ClickHouse and are explored in HyperDX. Application metrics flow through
vmagent to VictoriaMetrics.

Infrastructure and SRE metrics use the Prometheus exposition ecosystem. vmagent scrapes native endpoints and
only the exporters explicitly required by the contract. VictoriaMetrics is the primary metrics store. Grafana
is the SRE dashboard surface.

Infrastructure logs are collected and enriched by OpenTelemetry Collector, stored in VictoriaLogs, and viewed
in Grafana. vmalert evaluates metric and log rules; Alertmanager owns grouping, deduplication, routing, and
notification delivery.

Data Prepper remains active only for security/SIEM ingestion and enrichment before OpenSearch/Wazuh. It is not
the general application or infrastructure log pipeline.

## Deliberate non-duplication

There is no Prometheus server TSDB in the target topology. Prometheus-compatible endpoints and exporters remain
part of the metrics ecosystem and are scraped by vmagent. Fluent Bit is removed as the general log shipper.
OpenSearch is retained for security search/analytics only, not as the general log store.

HyperDX may use MongoDB for HyperDX metadata only. That database is not a business datastore and must never own
or receive ecommerce domain data.

## Stateful storage contract

`config/infrastructure/storage-plan.yaml` is the machine authority for persistent storage, HA, retention,
backup/restore, RPO/RTO, encryption, network access, operational ownership, dependencies, failure behavior and
environment status of every active observability store. The common profile is `observability-stateful-v1`.

| Store | Role | Deployment | HA / replication | PREPROD retention | PROD retention | PROD RPO / RTO |
|---|---|---|---|---|---|---|
| VictoriaMetrics | SRE metrics | Fleet-managed cluster | 3 vmstorage, replication factor 2 | 14d | 90d | 6h / 2h |
| VictoriaLogs | infrastructure logs | Fleet-managed cluster | 3 sharded vlstorage; no hidden replication | 14d | 30d | 6h / 2h |
| ClickHouse | application traces/logs | Fleet-managed StatefulSets | 1 shard x 3 replicas + 3 Keeper | 7d | 30d | 6h / 4h |
| MongoDB Community | HyperDX metadata only | MongoDB Community Operator | 3-member replica set, majority writes | HyperDX lifecycle | HyperDX lifecycle | 6h / 2h |
| OpenSearch Security | SIEM/security | OpenSearch Operator | 3 cluster-manager/data nodes, 1 index replica | 14d | 30d hot; 365d snapshots | 1h / 4h |

All persistent members use `localpv-observability`: static RWO XFS LocalPV backed by `localpv-a`/`localpv-b`,
with LUKS2 encryption below the filesystem, `WaitForFirstConsumer`, `Retain`, strict same-engine replica
anti-affinity and XFS project quotas. Distinct PV paths may share a backing NVMe; a PV/path may never be reused.
PVC capacity is derived from measured ingest, retention and replication evidence rather than a guessed fixed size.

SeaweedFS S3 is the only object authority for these backups. PREPROD uses its JIT site object store. PROD
clusters are independent per site and must not form stretched database quorums; `prod-a` backup objects are
kept in the opposite PROD site failure domain and vice versa. Replication is never accepted as backup.
Backup jobs are desired state reconciled by Rancher Fleet; Tekton does not become a backup scheduler.

The five stores are `deferred` in MGMT and `required` in PREPROD/PROD. Storage endpoints are private-only.
OpenBao + External Secrets supply credentials at runtime; secrets are forbidden from Git.

MongoDB is reachable only by HyperDX and backup/restore identities. Ecommerce services are forbidden from using
it and no business data may enter it. OpenSearch Security accepts only the security/SIEM pipeline; general
application and infrastructure logs remain forbidden there.

VictoriaLogs cluster storage is explicitly sharded rather than replicated. Loss of a `vlstorage` member makes
queries fail closed until the missing partitions are restored; the contract does not pretend that sharding is
HA replication.
