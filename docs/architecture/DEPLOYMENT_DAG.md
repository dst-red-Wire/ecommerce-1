# DEPLOYMENT DAG V2 — EXACT

Status: `EXACT`

The deployment graph is dependency-driven. Parallelism is allowed only inside a wave after the wave's prerequisites are healthy.

## Wave 0 — Permanent MGMT prerequisites

Must exist before PREPROD `CREATE`:

- Git/Gitea sources reachable;
- Harbor registry and required OCI artifacts available by immutable digest;
- Terraform state backend reachable;
- OpenBao bootstrap path available;
- version locks/checksums available;
- Ansible collections and RKE2 air-gap artifacts prepared;
- Fleet bundles/charts available;
- deterministic synthetic dataset version identified.

## Wave 1 — Physical/virtual infrastructure

`provider hosts -> Proxmox VE -> network/VLAN/bond -> VM templates -> VM clones -> Rocky bootstrap`

Gate W1: all hosts/VMs match inventory, anti-affinity and network plan.

## Wave 2 — RKE2 cluster

1. `cp-01` initializes cluster.
2. `cp-02` + `cp-03` join in parallel.
3. wait for healthy 3/3 control-plane quorum.
4. `worker-01..03` join in parallel.

Gate W2: Kubernetes API, etcd quorum, node readiness, time sync and baseline host hardening healthy.

## Wave 3 — Network/security foundation

Parallel where dependencies permit:

- Cilium + Hubble;
- Cilium LB IPAM/BGP prerequisites;
- CoreDNS baseline;
- Kyverno policies;
- Pod Security labels/policies;
- Tetragon;
- SPIRE server/agents.

Gate W3: default-deny policy test, SPIFFE issuance, Cilium health and policy admission pass.

## Wave 4 — GitOps/secrets/mesh control

- Rancher Fleet agent/bundles;
- OpenBao Kubernetes auth/bootstrap completion;
- ESO;
- Istio control plane;
- Istio mTLS STRICT validation.

Gate W4: GitOps reconciliation healthy, secret injection smoke passes, mesh identity/mTLS passes.

## Wave 5 — Delivery/registry/observability

Parallel groups:

A. Harbor integrations/robot accounts/signature verification hooks.
B. Tekton pipelines/tasks.
C. OTel Collector, Prometheus, Alertmanager, Grafana.
D. Fluent Bit -> Data Prepper -> OpenSearch Logs + Wazuh integrations.

Gate W5: pipeline dry-run, registry pull-by-digest, telemetry/log/security event flow pass.

## Wave 6 — Stateful platform

May run in parallel after storage/network prerequisites:

- CNPG/PostgreSQL;
- Strimzi Kafka KRaft;
- RabbitMQ;
- Redis Cluster;
- OpenSearch;
- SeaweedFS S3;
- Apicurio Registry.

Gate W6 requires health, anti-affinity, storage binding, operator readiness and backup/restore prerequisites.

## Wave 7 — IAM and Edge/API

- Keycloak + IAM database;
- public certificate automation;
- DNS records/sub-zone validation;
- HAProxy;
- Caddy + Coraza;
- ATS;
- Kong;
- Istio Gateway routes.

Gate W7: `www`, `api`, `cdn`, `auth`, `admin` synthetic resolution/routing paths pass without exposing internal stateful endpoints.

## Wave 8 — Golden service / application slices

- Product first when validating M2 pattern.
- Then M5 slice services by dependency group.
- Storefront/Admin only after their backend contract dependencies are healthy.

Gate W8: service readiness, contracts, migrations, telemetry and smoke tests pass.

## Wave 9 — Qualification

Order:

1. smoke/health/config;
2. security/policy/contracts;
3. integration;
4. BDD/E2E;
5. performance;
6. chaos/DR.

Blocking failure stops downstream expensive/destructive stages.

## Destruction DAG

Destruction reverses dependency order but evidence gates come first:

`validation result -> release evidence OK -> archive OK -> revoke temporary credentials -> delete application/platform resources -> delete VMs -> delete provider hosts/network allocations -> delete temporary DNS -> verify provider/control APIs -> VERIFY ZERO RESOURCE`.

No destroy step may delete required forensic evidence while resilience governance is active.

## Codex implementation requirement

Represent this DAG as code/data, not only prose. Each node must have:

- dependencies;
- health condition;
- timeout;
- retry semantics;
- failure behavior;
- evidence output reference;
- rollback/destroy hook where applicable.
