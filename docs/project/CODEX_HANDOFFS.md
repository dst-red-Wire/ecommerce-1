# CODEX HANDOFFS — M1 TO M9

Status: `CHATGPT PREPARED — EXACT CONTRACTS BOUND`

Codex must always read, in order:

1. `AGENTS.md`
2. `docs/architecture/BASELINE_V2.md`
3. `architecture.lock.yaml`
4. `docs/project/MASTER_EXECUTION_PLAN.md`
5. the milestone issue assigned to the work
6. the exact architecture contracts listed below
7. relevant ADRs/domain docs

## Mandatory exact architecture contracts

- `docs/architecture/EXACT_TOPOLOGY_V2.md`
- `docs/architecture/PREPROD_TOPOLOGY_V2.md`
- `docs/architecture/PROD_TOPOLOGY_V2.md`
- `docs/architecture/NETWORK_IPAM_CONTRACT.md`
- `docs/architecture/STORAGE_TOPOLOGY_V2.md`
- `docs/architecture/SERVICE_OWNERSHIP_MATRIX.md`
- `docs/architecture/DATA_OWNERSHIP_MATRIX.md`
- `docs/architecture/EVENT_CONTRACT_MATRIX.md`
- `docs/architecture/SECURITY_TRUST_ZONES.md`
- `docs/architecture/DEPLOYMENT_DAG.md`
- `docs/architecture/AIOPS_TOPOLOGY_V1.md`
- `docs/architecture/MLOPS_TOPOLOGY_V1.md`
- `config/infrastructure/preprod-inventory.yaml`
- `config/infrastructure/prod-inventory.yaml`
- `config/infrastructure/network-plan.yaml`
- `config/infrastructure/storage-plan.yaml`
- `config/infrastructure/deployment-waves.yaml`
- `config/contracts/service-ownership.yaml`
- `config/contracts/event-contracts.yaml`
- `config/contracts/dependency-map.yaml`

Codex must never infer or redesign architecture when these sources are explicit. If implementation exposes a contradiction, stop and report `BLOCKED_ARCHITECTURE` instead of silently choosing a new architecture.

## Global Codex prompt

You are implementing the E-COMMERCE platform from a locked architecture baseline and exact topology contracts. Work only inside the scope of the assigned milestone/issue. Before changing files, inventory the current repository and reuse existing structure. Do not create duplicate ownership, duplicate helpers, duplicate pipelines or duplicate source-of-truth files. Keep diffs small and reviewable. All reusable shell logic belongs in shared POSIX `sh` helpers under `scripts/`; do not repeat logic across scripts. Do not commit secrets, credentials, generated evidence, state files or runtime artifacts. Never use `latest`. Preserve rollback/rebuild paths. Run the repository's required validation commands and report exact PASS/FAIL/SKIP results. A milestone is not complete because files exist; it is complete only when its acceptance criteria are demonstrated.

When exact config exists, consume it as data rather than rewriting the same constants in Terraform, Ansible, Helm, scripts or documentation. Add automated consistency checks instead of copy/paste.

## M1 prompt — Monorepo Bootstrap

Tracker: `#13`.

Goal: create the minimal repository skeleton and automation entrypoints needed for later milestones without implementing deep business logic.

Required result:
- exactly 17 backend service directories and two frontends;
- no checkout service;
- contracts, platform, observability, tests and tools areas;
- `go.work`, ownership/contribution/security root files;
- Fleet/Tekton paths, never Flux/Flagger;
- no MinIO CE/Loki/Splunk active defaults;
- no image using `latest`;
- shared repository scripts factored, POSIX compatible;
- preserve `config/infrastructure/*` and `config/contracts/*` as single config sources;
- `make ci` green.

Deliver one PR tied to #13. Include tree summary, commands run, results and SKIPs.

## M2 prompt — Golden Service Product

Tracker: `#14`.

Goal: make Product the single proven service template for transport, persistence, events, telemetry, security, containerization and delivery.

Use `SERVICE_OWNERSHIP_MATRIX.md`, `DATA_OWNERSHIP_MATRIX.md`, `EVENT_CONTRACT_MATRIX.md`, `dependency-map.yaml` and `SECURITY_TRUST_ZONES.md` as hard boundaries. Implement only Product deeply. REST and gRPC call the same application use-cases. Use pgx/sqlc, versioned migrations, transactional outbox, franz-go Kafka, Protobuf contracts, idempotence, OTel and structured logs. Provide unit, integration and contract tests. Provide non-root container, immutable dependencies, Fleet deployable configuration and Tekton CI stages for lint/test/build/scan/SBOM/sign/push. No other service may receive duplicated Product business logic.

Deliver one or a small sequence of tightly-scoped PRs tied to #14.

## M3 prompt — PREPROD Infrastructure

Tracker: `#16`.

Goal: implement reproducible JIT infrastructure as code from `PREPROD_TOPOLOGY_V2.md`, `NETWORK_IPAM_CONTRACT.md`, `STORAGE_TOPOLOGY_V2.md`, `preprod-inventory.yaml`, `network-plan.yaml` and `storage-plan.yaml`.

Do not re-decide placement, VM sizing, VLANs, CIDRs, public-IP role slots, anti-affinity or storage-device ownership. Consume the canonical YAML and validate it.

Implement:
1. Terraform/OpenTofu provider modules and environment composition;
2. inventory/IPAM/storage loaders reused by Terraform/Ansible;
3. Proxmox host/bootstrap configuration hooks;
4. VM creation with anti-affinity/layout assertions;
5. Rocky cloud-init/bootstrap and Ansible hardening;
6. RKE2 bootstrap and air-gap/version-lock hooks;
7. lifecycle TTL/watchdog;
8. archive/destroy/verify-zero automation;
9. static tests and dry-run validation where real infrastructure is unavailable;
10. config consistency tests for duplicate IP, CIDR overlap, invalid placement and device collisions.

Do not hardcode credentials. Do not claim real provider provisioning when credentials/environment are absent. Return `READY FOR REAL PROVISIONING` only after all offline/static validation passes.

## M4 prompt — Platform Baseline

Tracker: `#17`.

Goal: install the minimum complete platform needed to run and prove application slices, following `DEPLOYMENT_DAG.md`, `deployment-waves.yaml`, `STORAGE_TOPOLOGY_V2.md`, `storage-plan.yaml` and `SECURITY_TRUST_ZONES.md`.

Order:
`RKE2 -> Cilium/Hubble -> Fleet -> Kyverno/Pod Security -> SPIRE -> Istio -> OpenBao/ESO -> Harbor -> Tekton -> observability/security logging -> stateful platform`.

Stateful baseline:
- CNPG/PostgreSQL;
- Strimzi Kafka KRaft + MirrorMaker2 hooks;
- RabbitMQ Quorum Queues;
- Redis Cluster;
- OpenSearch;
- SeaweedFS S3;
- Apicurio Registry where contract workflow requires it.

Requirements:
- default-deny network posture;
- no `latest`;
- pinned charts/images/versions via lock/config files;
- Pod Security restricted where applicable;
- PDB/anti-affinity/topologySpread for critical components;
- health/readiness, dashboards/alerts, backup/restore prerequisites;
- GitOps desired state through Fleet;
- no manual PROD mutation pattern;
- tests for policy, rendering, storage binding and dependency ordering.

## M5 prompt — Commerce Vertical Slice

Tracker: `#18`.

Goal: prove a real user-facing commerce path through the actual platform without redesigning ownership.

Implement in four bounded slices:

A. `Storefront -> Catalog/Product/Search/Pricing/Inventory`
B. `Cart -> Order -> Tax -> Fraud/Risk -> Payment`
C. `Shipping -> Tracking -> Returns -> Billing -> Notification`
D. `Review + User Profile`

For each slice:
- contracts first, derived from `SERVICE_OWNERSHIP_MATRIX.md`, `EVENT_CONTRACT_MATRIX.md` and `dependency-map.yaml`;
- enforce `DATA_OWNERSHIP_MATRIX.md` and no cross-database reads;
- add outbox/idempotence where required;
- BDD Given/When/Then for critical behavior;
- Playwright E2E for user journeys;
- telemetry and failure-path tests;
- rollback/migration notes.

Do not create new services unless ChatGPT architecture governance explicitly approves them.

## M6 prompt — Full Application

Tracker: `#19`.

Goal: complete all validated business capabilities and admin workflows while preserving exact service/data/event ownership.

Include:
- FR/EN;
- EUR;
- guest checkout;
- RBAC/scopes and privileged passkey requirements;
- Stripe PaymentIntents/Payment Element flow, authorization/capture separation;
- immutable Order snapshot;
- returns/refunds;
- billing/credit notes/e-invoicing adapter boundary;
- shipping/tracking;
- reviews;
- fraud manual-review path;
- privacy/data-minimization obligations.

All domains must have tests, contracts, migration path, observability and ownership documentation. Changes to ownership matrices require ChatGPT review first.

## M7 prompt — Qualification

Tracker: `#20`.

Goal: turn the implemented system into a release candidate with evidence.

Execute/generate automation for:
- unit, race, fuzz, coverage;
- integration/Testcontainers;
- OpenAPI/gRPC/Kafka contract compatibility;
- BDD;
- Playwright browser/protocol matrix;
- SAST/dependency/container/IaC/security-policy checks;
- Trivy/Syft/Cosign supply-chain gates;
- k6 performance;
- Chaos Mesh and DR tests behind fail-closed environment gates;
- restore/rebuild checks;
- evidence index referencing external artifacts rather than committing runtime evidence.

A FAIL cannot be converted to PASS by documentation. Open corrective issues.

## M8 prompt — PREPROD Certification

Tracker: `#21`.

Goal: automate and execute, where credentials/hardware permit, the three validated campaigns using the same signed digest/release manifest/configuration and the exact physical topology from `PROD_TOPOLOGY_V2.md`/`prod-inventory.yaml`.

1. Standard <=24h: general qualification.
2. Endurance: 72 useful hours of stable load.
3. PROD-EQUIVALENT: exactly six final/equivalent physical hosts, three/site, with 3 CP + 5 workers/site and symmetric site-loss/host-loss certification.

After each temporary campaign: archive evidence -> destroy -> verify zero resource.

For final certification: destroy test state and rebuild trusted PROD via IaC/GitOps. Never promote test state directly into production.

Return machine-readable campaign result plus human summary. `FAIL` or `INCOMPLETE` blocks M9.

## M9 prompt — PROD A/B Rollout

Tracker: `#22`.

Goal: deploy trusted production A/B from approved IaC/GitOps and execute controlled release using `PROD_TOPOLOGY_V2.md`, `prod-inventory.yaml`, `network-plan.yaml`, `storage-plan.yaml` and release-governance rules.

Requirements:
- exact signed release manifest/digests from certification;
- three physical failure domains/site;
- 3 CP + 5 workers/site;
- fencing/home_site authority;
- DNS/GSLB failover only after fencing/promotion authority;
- progressive delivery through Argo Rollouts;
- canary/one-site-first according to release governance;
- rollback/quarantine tested;
- observability and business KPI checks live;
- no manual normal-state mutation;
- release ledger/evidence updated.

Codex executes repository and environment automation. It does not independently authorize GO-LIVE.
