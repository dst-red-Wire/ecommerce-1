# Architecture Baseline V2 — E-COMMERCE

Status: `LOCKED FOR BUILD`

This document is the canonical execution baseline for repository implementation. It consolidates validated architecture decisions and explicit supersessions.

## 1. Business topology

17 backend services:

`catalog, product, inventory, cart, pricing, tax, order, payment, shipping, tracking, returns, billing, fraud-risk, search, review, user-profile, notification`.

No `checkout` service. `order` owns checkout orchestration and immutable order snapshot.

Two Next.js frontends: `storefront` and `admin`.

## 2. Protocol ownership

- Public APIs: REST/JSON, OpenAPI 3.1.
- Internal synchronous: gRPC, Protobuf, Buf.
- Durable domain events: Kafka, Strimzi KRaft, Protobuf, Apicurio.
- Operational jobs: RabbitMQ Quorum Queues.
- CDC is targeted and never substitutes domain events.

## 3. Platform baseline

- Hypervisor: Proxmox VE 9 where applicable.
- Kubernetes: RKE2.
- Node OS: Rocky Linux 9.x.
- CNI: Cilium + Hubble.
- Service mesh: Istio with mTLS STRICT.
- Workload identity: SPIFFE/SPIRE.
- Human IAM: Keycloak.
- Secrets: OpenBao + ESO.
- Admission/security: Pod Security restricted, Kyverno, Tetragon, default-deny networking.

## 4. Delivery baseline

- Forge/source: Gitea for target self-hosted platform; GitHub repository remains current project source during build.
- CI platform: Tekton.
- OCI registry: Harbor.
- GitOps CD: Rancher Fleet.
- Progressive delivery: Argo Rollouts.
- Supply chain: Trivy + Syft + Cosign + immutable digests.
- `latest` is forbidden.

Woodpecker is tolerated only as a temporary repository bootstrap CI. It must not duplicate the application/platform CI responsibilities owned by Tekton.

## 5. Stateful baseline

- PostgreSQL: CloudNativePG, domain-owned databases, single-writer/home_site model for multi-site writes.
- Kafka: one local cluster per site, MirrorMaker2 inter-site.
- RabbitMQ: one resilient deployment per site.
- Redis: cache/ephemeral state only.
- OpenSearch: rebuildable search/read models.
- SeaweedFS S3: target object store for new PROD deployments, subject to PREPROD qualification gates.
- Harbor remains authoritative for OCI artifacts and MLOps Modelcars.
- Ceph is not a default object-store dependency. RBD/CephFS are admitted only when an explicit block/RWX need remains.

## 6. Edge and DNS

Public API path:

`Internet -> DNS/GSLB -> HAProxy -> Caddy+Coraza -> Kong -> Istio Gateway -> services`

Web/CDN:

- `www -> ATS -> Storefront`
- `cdn -> ATS -> S3/assets`

DNS:

- ClouDNS registrar.
- PowerDNS Hidden Primary MGMT + secondaries Site A/Site B.
- dnsdist.
- DNSSEC.
- ExternalDNS.
- CoreDNS internal.
- Unbound x2/site.
- critical TTL baseline 60 s.
- DNS failover only after fencing/promotion authority is established.

## 7. Observability and security logging

- OpenTelemetry Collector.
- Prometheus + Alertmanager + Grafana.
- Fluent Bit + Data Prepper + OpenSearch Logs.
- Wazuh for security/audit.
- Immutable DFIR archive where required.

## 8. Quality baseline

Execution order:

`unit -> integration -> contracts -> BDD -> smoke/E2E -> performance -> chaos/DR when gated`.

- Go TDD.
- Coverage >=80% global and >=90% for critical code where meaningful.
- race detector and fuzzing.
- testcontainers-go.
- Gherkin + Godog.
- Playwright.
- k6.
- Chaos Mesh.

## 9. PREPROD JIT baseline

Standard lifecycle:

`CREATE -> VALIDATE -> ARCHIVE -> DESTROY COMPLET -> VERIFY ZERO RESOURCE`.

Standard PREPROD:

- 3 JIT bare-metal hosts.
- 3 control-plane VMs + 3 worker VMs.
- temporary PERF workers when required.
- TTL <=24 h for standard campaign.
- risk-based validation DAG.

Certification before first PROD:

1. standard PREPROD campaign;
2. endurance campaign;
3. `PREPROD-CERT PROD-EQUIVALENT` on six final/equivalent hosts;
4. destroy test state and rebuild trusted PROD via IaC/GitOps.

## 10. Resilience invariant

For a compromised reproducible node, VM, container, or workload:

`isolate -> acquire evidence -> destroy -> rebuild via GitOps/IaC`.

PCA continuity, DFIR evidence preservation, and PRI reconstruction cooperate but do not block one another unnecessarily.

## 11. MLOps baseline

- DVC + Git/Gitea + SeaweedFS S3 for dataset versioning/storage.
- MLflow for experiments, metadata, lineage and model lifecycle.
- Harbor for Modelcars OCI.
- deterministic hard gates + champion/challenger non-inferiority + persistent multi-signal drift.
- event-driven bounded retraining; no blind retraining and no automatic model promotion.
- promotions freeze during recovery.

## 12. Explicit supersessions

The following are historical and MUST NOT be introduced as active defaults:

| Superseded target | Active target |
|---|---|
| FluxCD | Rancher Fleet |
| Flagger | Argo Rollouts |
| MinIO Community Edition / Operator | SeaweedFS S3 for new PROD object storage |
| Loki as logging baseline | OpenSearch Logs pipeline |
| Splunk as SIEM baseline | Wazuh + OpenSearch Logs |

References in historical ADRs/issues may remain if clearly marked `SUPERSEDED`.

## 13. Build milestones

- M0 Architecture Sync.
- M1 Monorepo Bootstrap.
- M2 Golden Service `product`.
- M3 PREPROD Infrastructure.
- M4 Platform Baseline.
- M5 Commerce Vertical Slice.
- M6 Remaining 17 services + 2 frontends.
- M7 QA/Security/PERF/Chaos/DR.
- M8 PREPROD certification.
- M9 PROD A/B rollout.

## 14. Execution authority

- ChatGPT: architecture, ADR/policy/control design, collision review, acceptance criteria, repository governance documents.
- Codex: repository implementation, refactoring, IaC, Kubernetes, CI/CD, tests and PR-ready diffs.
- Work: persistent browser/document workflows, external vendor evidence and substantial finished non-code deliverables.

A status must be explicit: `DONE`, `READY FOR CODEX`, `READY FOR WORK`, `BLOCKED`, `DEPLOYED`, or `PROVEN`.
