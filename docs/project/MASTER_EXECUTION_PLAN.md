# MASTER EXECUTION PLAN — E-COMMERCE

Status: `CHATGPT PM BASELINE`

This document is the delivery source of truth for project sequencing. It does not replace architecture ADRs, `docs/architecture/BASELINE_V2.md`, `architecture.lock.yaml`, release governance or resilience governance.

## 1. Operating model

The project is managed as three coordinated execution surfaces with one owner per work item.

- **ChatGPT = Project Manager / Business Manager / Architecture & Governance lead**: scope, milestones, dependencies, decisions, collision review, acceptance criteria, business readiness, risk management, issue/handoff preparation and review of evidence.
- **Codex = engineering execution**: repository changes, code, IaC, Kubernetes, CI/CD, tests, refactors, commands, validation and PR-ready changes.
- **Work = long-running business/research/deliverable execution**: vendor due diligence, browser workflows, evidence collection, finished reports, spreadsheets, launch packs and non-code documentation.

Rule: no task is assigned simultaneously to all three. ChatGPT decides and prepares; Codex implements technical repository work; Work produces persistent research/business/evidence deliverables.

## 2. Status vocabulary

Only these statuses are allowed:

- `DONE`: planning/artifact/task completed.
- `READY FOR CODEX`: engineering task is unblocked and has complete inputs.
- `READY FOR WORK`: Work task is unblocked and has complete inputs.
- `BLOCKED`: missing dependency, credential, environment, decision or proof.
- `DEPLOYED`: running in an environment, not yet proven.
- `PROVEN`: acceptance criteria and required evidence passed.

`IMPLEMENTED` or `DEPLOYED` never implies `PROVEN`.

## 3. Milestone program

| Milestone | Primary owner | Objective | Entry gate | Exit gate | Current status |
|---|---|---|---|---|---|
| M0 Architecture Sync | ChatGPT | lock canonical V2 baseline and remove architecture collisions | validated project decisions | baseline, lock, agent rules and merged sync PR | DONE |
| M1 Monorepo Bootstrap | Codex | create minimal maintainable monorepo skeleton | M0 merged | exactly 17 services + 2 frontends represented, repo checks green | READY FOR CODEX |
| M2 Golden Service Product | Codex | prove one production-grade Go service pattern | M1 PROVEN | Product REST/gRPC/PostgreSQL/Outbox/Kafka/tests/container/Fleet/Tekton pattern PROVEN | BLOCKED by M1 |
| M3 PREPROD Infrastructure | Codex | provision reproducible JIT infrastructure foundation | M1 and infrastructure specification | Terraform/Ansible/Proxmox/Rocky/RKE2 baseline reproducible, destroyable, zero-resource verified | BLOCKED by M1/spec merge |
| M4 Platform Baseline | Codex | deploy security, delivery, observability and stateful platform baseline | M3 PROVEN | platform services healthy, declarative, observable, secured, restore prerequisites present | BLOCKED by M3 |
| M5 Commerce Vertical Slice | Codex | deliver first end-to-end commerce path | M2 + M4 PROVEN | Storefront through domain/data/event paths passes contracts, BDD, E2E and baseline performance | BLOCKED by M2/M4 |
| M6 Full Application | Codex | complete 17 services + Storefront + Admin | M5 PROVEN | all scoped business capabilities implemented with contracts/tests/ownership | BLOCKED by M5 |
| M7 Qualification | Codex | run full QA/security/supply-chain/perf/chaos/DR gates | M6 feature complete and platform stable | qualification evidence complete; no unresolved release blocker | BLOCKED by M6 |
| M8 PREPROD Certification | Codex execution + Work reporting; release governance authority | execute three PREPROD campaigns and certify material equivalence | M7 PROVEN | standard + endurance + PROD-equivalent PASS; evidence archived; test state destroyed; READY_FOR_PROD | BLOCKED by M7 |
| M9 PROD A/B Rollout | Codex execution; release governance authority; Work launch pack | build trusted PROD A/B and progressive rollout | M8 READY_FOR_PROD | controlled rollout, rollback proven, monitoring/business operations ready, release evidence complete | BLOCKED by M8 |

## 4. Critical path

`M0 -> M1 -> M2`

In parallel after M1, M3 may proceed when its specification is merged.

Then:

`M3 -> M4`

M5 requires both the golden service pattern and platform baseline:

`M2 + M4 -> M5 -> M6 -> M7 -> M8 -> M9`

No PROD infrastructure opening to customer traffic is authorized before M8 returns `READY_FOR_PROD`.

## 5. Parallel work that must not block the critical path

### Work stream W1 — Vendor & commercial due diligence

Can run in parallel with M1-M4.

Scope: phoenixNAP, Hetzner, ClouDNS, Stripe, Qonto and any already-approved provider dependency that materially affects deployment.

Output: current offers/capabilities, constraints, support/SLA information, pricing evidence where available, region/network limits, contractual/operational risks and source references.

### Work stream W2 — Business/compliance readiness

Can run in parallel with M2-M6.

Scope: B2C mono-vendeur FR+UE, EUR, FR/EN, guest checkout, GDPR/privacy obligations, customer support flow, returns/refunds, invoicing/e-invoicing readiness, terms and launch obligations. Work does not invent legal conclusions; it assembles a review-ready readiness dossier and flags items requiring qualified legal/accounting review.

### Work stream W3 — PREPROD evidence pack

Starts when M7 evidence exists.

Output: campaign evidence index, test matrix, exceptions, unresolved failures, traceability to release manifest/digest/configuration and executive PASS/FAIL summary. Evidence is referenced, not copied into Git when it is runtime/audit material.

### Work stream W4 — PROD launch pack

Starts during M8 after certification evidence is stable.

Output: launch checklist, operational contacts/ownership, rollback communication pack, customer/support readiness, vendor dependency checklist, business KPIs, incident communications template and executive GO/NO-GO pack.

## 6. Engineering decomposition

### M1 — Bootstrap

Canonical tracker: GitHub issue `#13`.

No deep service implementation. Build structure and checks only.

### M2 — Golden Service

Canonical tracker: GitHub issue `#14`.

Product is the reference pattern. Do not clone product business logic into other services.

### M3 — PREPROD Infrastructure

Required implementation domains:

1. provider inputs and environment variables;
2. IPAM/network inventory consumed by Terraform/Ansible/NetBox-compatible data;
3. bare-metal provisioning assumptions;
4. Proxmox VE 9 configuration;
5. Rocky Linux 9.x VM templates/bootstrap;
6. VM anti-affinity/layout;
7. RKE2 bootstrap;
8. Cilium installation prerequisites;
9. JIT TTL/watchdog;
10. archive -> destroy -> verify-zero automation;
11. non-secret evidence outputs.

Exact runtime versions belong in versioned lock/config files, not in this project plan.

### M4 — Platform Baseline

Delivery order:

`RKE2 -> Cilium/Hubble -> Fleet -> Kyverno/Pod Security -> SPIRE -> Istio -> OpenBao/ESO -> Harbor -> Tekton -> observability/security logging -> data platform`.

Stateful components follow the locked architecture: CNPG/PostgreSQL, Strimzi Kafka KRaft, RabbitMQ Quorum Queues, Redis Cluster, OpenSearch and SeaweedFS S3. Ceph is conditional only for an explicitly approved block/RWX need.

### M5 — Vertical Slice

Implement in bounded slices:

- M5-A discovery: Storefront -> Catalog/Product/Search/Pricing/Inventory.
- M5-B checkout/order: Cart -> Order -> Tax -> Fraud/Risk -> Payment.
- M5-C fulfilment: Shipping -> Tracking -> Returns -> Billing -> Notification.
- M5-D trust/content: Review + User Profile.

M5 is complete only when the user-visible path is exercised through actual contracts, persistence, events and observability in PREPROD.

### M6 — Full Application

Complete all capabilities, admin workflows, localization FR/EN, failure paths, permissions, data minimization, migration paths and service-level documentation. No new microservice may be added without architecture admission review.

### M7 — Qualification

Required gate families:

`unit -> integration -> contract -> BDD -> smoke/E2E -> supply-chain/security -> performance -> chaos/DR`.

The three PREPROD campaigns are specialized qualification stages; later campaigns may reuse immutable evidence only when digest/configuration equivalence is proven, while required entry gates are replayed after reconstruction.

### M8 — Certification

1. PREPROD standard <=24h.
2. Endurance 72 useful hours.
3. PREPROD-CERT PROD-EQUIVALENT using six final/equivalent hosts.
4. Destroy test state.
5. Rebuild trusted PROD via IaC/GitOps.

A `FAIL` or `INCOMPLETE` blocks M9.

### M9 — PROD A/B

Use signed immutable release manifests, controlled rollout, explicit fencing/home-site authority, progressive delivery, rollback/quarantine and release ledger evidence. No normal manual production mutation.

## 7. Business scope that engineering must preserve

- B2C, mono-vendeur.
- France + EU target scope.
- EUR.
- FR + EN.
- guest checkout.
- Stripe payment integration with SCA/3DS where applicable.
- Payment and Billing remain separate domains.
- Qonto PA integration is owned by Billing through an adapter for French e-invoicing readiness.
- immutable Order checkout snapshot.
- fraud review workflow with the validated operational SLA.
- privacy-by-design and data minimization.

Business changes that modify one of these structural assumptions require explicit change control before implementation.

## 8. Project-manager gates

ChatGPT must perform these checks before marking a milestone `READY`:

1. inputs are canonical and versioned;
2. dependencies are complete or explicitly mocked;
3. no unresolved architecture collision;
4. acceptance criteria are testable;
5. rollback/destruction path exists where relevant;
6. evidence destination/format is defined;
7. owner is unique;
8. Work/Codex is not asked to make an architectural decision;
9. no secret or privileged action is embedded in the prompt;
10. downstream milestone prerequisites are identified.

## 9. Change control

When new information appears:

1. classify as business change, architecture change, implementation detail, defect, evidence gap or vendor constraint;
2. architecture/business structural changes go through ChatGPT review first;
3. implementation defects stay with Codex;
4. external facts and vendor constraints may be gathered by Work and returned to ChatGPT for decision;
5. accepted structural changes update the owning ADR/baseline and explicit supersession before Codex proceeds.

## 10. Definition of program completion

The program is not complete when code is merged. Completion requires:

- all M1-M9 exit gates met;
- PROD A/B deployed from reproducible IaC/GitOps;
- release evidence complete;
- restore/failover/rollback evidence current;
- business/compliance launch checklist complete;
- support/incident ownership defined;
- no unresolved P0/P1 blocker;
- operational and business KPIs observable;
- project status `PROVEN`, not merely `DEPLOYED`.
