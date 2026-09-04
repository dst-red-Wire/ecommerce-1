# CODEX HANDOFFS — M1 TO M9

Status: `CHATGPT PREPARED`

Codex must always read, in order:

1. `AGENTS.md`
2. `docs/architecture/BASELINE_V2.md`
3. `architecture.lock.yaml`
4. `docs/project/MASTER_EXECUTION_PLAN.md`
5. the milestone issue assigned to the work
6. relevant ADRs and domain docs

Codex must never infer or redesign architecture when the above sources are explicit. If implementation exposes a contradiction, stop and report it as a blocker instead of silently choosing a new architecture.

## Global Codex prompt

You are implementing the E-COMMERCE platform from a locked architecture baseline. Work only inside the scope of the assigned milestone/issue. Before changing files, inventory the current repository and reuse existing structure. Do not create duplicate ownership, duplicate helpers, duplicate pipelines or duplicate source-of-truth files. Keep diffs small and reviewable. All reusable shell logic belongs in shared POSIX `sh` helpers under `scripts/`; do not repeat logic across scripts. Do not commit secrets, credentials, generated evidence, state files or runtime artifacts. Never use `latest`. Preserve rollback/rebuild paths. Run the repository's required validation commands and report exact PASS/FAIL/SKIP results. A milestone is not complete because files exist; it is complete only when its acceptance criteria are demonstrated.

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
- `make ci` green.

Deliver one PR tied to #13. Include tree summary, commands run, results and SKIPs.

## M2 prompt — Golden Service Product

Tracker: `#14`.

Goal: make Product the single proven service template for transport, persistence, events, telemetry, security, containerization and delivery.

Implement only Product deeply. REST and gRPC call the same application use-cases. Use pgx/sqlc, versioned migrations, transactional outbox, franz-go Kafka, Protobuf contracts, idempotence, OTel and structured logs. Provide unit, integration and contract tests. Provide non-root container, immutable dependencies, Fleet deployable configuration and Tekton CI stages for lint/test/build/scan/SBOM/sign/push. No other service may receive duplicated Product business logic.

Deliver one or a small sequence of tightly-scoped PRs tied to #14.

## M3 prompt — PREPROD Infrastructure

Goal: implement reproducible JIT infrastructure as code for the validated PREPROD topology.

Inputs:
- 3 phoenixNAP AMS JIT bare-metal hosts, TTL <=24h;
- Proxmox VE 9;
- Rocky Linux 9.x RKE2 VMs;
- 3 CP + 3 Workers standard, +2 PERF workers only for performance burst;
- VLANs 401 MGMT, 402 K8S-NODES, 403 STORAGE, 404 REPLICATION, 405 BACKUP, 406 EDGE-DMZ;
- LACP 2x25Gb/s trunk where provider/hardware supports the validated design;
- auxiliary VM roles: 2 Edge, 2 DNS, 2 Squid, 2 GW with strict anti-affinity;
- raw NVMe passthrough as defined by the platform storage plan;
- CREATE -> VALIDATE -> ARCHIVE -> DESTROY -> VERIFY ZERO RESOURCE.

Implement:
1. Terraform/OpenTofu provider modules and environment composition;
2. machine-readable IPAM/inventory data reused by Terraform/Ansible;
3. Proxmox host/bootstrap configuration hooks;
4. VM creation with anti-affinity/layout assertions;
5. Rocky cloud-init/bootstrap and Ansible hardening;
6. RKE2 bootstrap and air-gap/version-lock hooks;
7. lifecycle TTL/watchdog;
8. archive/destroy/verify-zero automation;
9. static tests and dry-run validation where real infrastructure is unavailable.

Do not hardcode credentials. Do not claim real provider provisioning when credentials/environment are absent. Return `READY FOR REAL PROVISIONING` only after all offline/static validation passes.

## M4 prompt — Platform Baseline

Goal: install the minimum complete platform needed to run and prove application slices.

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
- tests for policy, rendering and dependency ordering.

## M5 prompt — Commerce Vertical Slice

Goal: prove a real user-facing commerce path through the actual platform.

Implement in four bounded slices:

A. `Storefront -> Catalog/Product/Search/Pricing/Inventory`
B. `Cart -> Order -> Tax -> Fraud/Risk -> Payment`
C. `Shipping -> Tracking -> Returns -> Billing -> Notification`
D. `Review + User Profile`

For each slice:
- define/update OpenAPI, Protobuf and Kafka contracts first;
- enforce domain data ownership;
- no cross-database reads;
- add outbox/idempotence where required;
- BDD Given/When/Then for critical behavior;
- Playwright E2E for user journeys;
- telemetry and failure-path tests;
- rollback/migration notes.

Do not create new services unless ChatGPT architecture governance explicitly approves them.

## M6 prompt — Full Application

Goal: complete all validated business capabilities and admin workflows while preserving the proven golden patterns.

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

All domains must have tests, contracts, migration path, observability and ownership documentation.

## M7 prompt — Qualification

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

Goal: automate and execute, where credentials/hardware permit, the three validated campaigns using the same signed digest/release manifest/configuration.

1. Standard <=24h: general qualification.
2. Endurance: 72 useful hours of stable load.
3. PROD-EQUIVALENT: six final/equivalent hosts, symmetric site-loss/host-loss certification.

After each temporary campaign: archive evidence -> destroy -> verify zero resource.

For the final certification: destroy test state and rebuild trusted PROD via IaC/GitOps. Never promote test state directly into production.

Return machine-readable campaign result plus human summary. `FAIL` or `INCOMPLETE` blocks M9.

## M9 prompt — PROD A/B Rollout

Goal: deploy trusted production A/B from approved IaC/GitOps and execute controlled release.

Requirements:
- exact signed release manifest/digests from certification;
- site A/B topology and fencing/home_site authority;
- DNS/GSLB failover only after fencing/promotion authority;
- progressive delivery through Argo Rollouts;
- canary/one-site-first according to release governance;
- rollback/quarantine tested;
- observability and business KPI checks live;
- no manual normal-state mutation;
- release ledger/evidence updated.

Codex executes repository and environment automation. It does not independently authorize GO-LIVE.