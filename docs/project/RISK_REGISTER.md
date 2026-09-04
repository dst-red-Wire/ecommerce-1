# PROJECT RISK REGISTER — E-COMMERCE

Status: `ACTIVE`

| ID | Risk | Impact | Likelihood | Owner | Mitigation / control | Trigger for escalation | Current status |
|---|---|---|---|---|---|---|---|
| R-001 | Historical docs reintroduce FluxCD/Flagger/MinIO CE/Loki/Splunk | High | Medium | ChatGPT | BASELINE_V2 + architecture.lock + AGENTS precedence; CI deny checks in M1 | active default appears in new code | CONTROLLED |
| R-002 | Codex asked to choose architecture rather than implement | High | Medium | ChatGPT | milestone issues + CODEX_HANDOFFS + change-control stop rule | Codex reports contradictory/missing structural decision | CONTROLLED |
| R-003 | Provider capability/hardware differs from design | High | Medium | Work + ChatGPT | W1 vendor due diligence; PREPROD certification on final/equivalent hardware | provider cannot supply required network/disk/host profile | OPEN |
| R-004 | Versions/charts incompatible at implementation time | High | Medium | Codex | version lock/BOM during M1-M4; compatibility tests in PREPROD | dependency conflict or unsupported version | OPEN |
| R-005 | PREPROD JIT lifecycle leaves billable/orphan resources | High | Medium | Codex | TTL watchdog + destroy + VERIFY ZERO RESOURCE | any resource remains after campaign | BLOCKING IF TRIGGERED |
| R-006 | Stateful failover creates split-brain | Critical | Low/Medium | resilience/release governance + Codex | home_site + fencing + quorum; DNS switch only after authority | ambiguous writer authority | BLOCKING |
| R-007 | Replication mistaken for backup | Critical | Medium | ChatGPT + Codex | independent/off-site backups, restore tests, DR evidence | no independent restore point | BLOCKING |
| R-008 | Security/compliance work deferred until launch | High | Medium | ChatGPT + Work + Codex | W2 in parallel, M7 security gates, privacy-by-design | unresolved launch-critical legal/privacy/payment obligation | BLOCKING FOR M9 |
| R-009 | Product service template copied into domain logic incorrectly | Medium | Medium | Codex | Golden service reuses infrastructure conventions only; domain ownership tests/review | shared package contains domain business rules | OPEN |
| R-010 | Excessive platform complexity delays delivery | High | Medium | ChatGPT | component-admission rule; no new component without measurable need | proposal adds overlapping platform component | CONTROLLED |
| R-011 | Test evidence exists but is not traceable to exact release/config | High | Medium | Codex + Work | signed release manifest/digest/config; evidence index | evidence missing commit/digest/config identity | BLOCKING FOR M8 |
| R-012 | Endurance/perf tests use load generators inside system under test | Medium | Low | Codex | external load generators; campaign spec | generator consumes certified cluster capacity | BLOCKING FOR CERT |
| R-013 | MLOps/AIOps autonomy can modify protected state | Critical | Low | AIOps/release/resilience governance | kill switches, authority levels, forbidden autonomous operations | autonomous writer/failover/DNS/IAM/secrets mutation attempted | BLOCKING |
| R-014 | Cost grows before business proof due to multi-site/hardware footprint | High | Medium | Business manager / ChatGPT | JIT PREPROD, cost evidence, staged procurement, capacity gates | recurring infra spend exceeds approved envelope | OPEN — requires budget envelope |
| R-015 | No explicit financial/business launch KPIs | Medium | Medium | Business manager / ChatGPT | define KPI pack before M9 using actual product objectives | M8 starts without business success metrics | OPEN |
| R-016 | Support/fraud/refund operations not staffed for launch | High | Medium | Work + business owner | W2/W5 operational readiness, escalation matrix | no owner or SLA for customer-impact queue | OPEN |
| R-017 | PROD hardware certification invalidated by BOM/topology/load change | High | Medium | release governance | re-certification trigger documented | hardware/topology/capacity profile changes | CONTROLLED |
| R-018 | CI bootstrap Woodpecker becomes permanent duplicate of Tekton | Medium | Medium | Codex | M1 removes overlap and documents transition | same app build gates run independently in both systems | OPEN |
| R-019 | Data retention/logging violates minimization or forensic needs | High | Medium | ChatGPT + Work + Codex | classification/retention policy, W2 review, DFIR immutable tier | unclassified log/data set or conflicting retention | OPEN |
| R-020 | Production launch blocked by missing credentials/contracts/accounts | High | Medium | Work + business owner | W1 account/contract readiness checklist before M8 | required provider account/API access not ready | OPEN |

## Escalation rule

Any `Critical` risk or any risk marked `BLOCKING` stops automatic milestone promotion. ChatGPT must classify the issue, route the owner and update the milestone status before work resumes.

## Review cadence

- at every milestone exit;
- before each PREPROD campaign;
- before M9 GO/NO-GO;
- after any P0/P1 incident or material vendor/architecture change.