# TECHNICAL READINESS

Status: `READY — NO SPECIFICATION BLOCKER IDENTIFIED`

```text
Decisions
   ↓
Architecture Baseline
   ↓
EXACT TOPOLOGY
   ↓
Network/IPAM contract
   ↓
Storage contract
   ↓
Service/Data/Event ownership
   ↓
Deployment DAG
   ↓
Codex handoff
```

| Layer | Authoritative source | Status |
|---|---|---|
| Decisions | ADRs + specialized governance Skills | LOCKED |
| Architecture Baseline | `docs/architecture/BASELINE_V2.md`, `architecture.lock.yaml` | LOCKED |
| Exact topology | `docs/architecture/EXACT_TOPOLOGY_V2.md`, `PREPROD_TOPOLOGY_V2.md`, `PROD_TOPOLOGY_V2.md`, AIOps/MLOps topology files | EXACT |
| Network/IPAM | `docs/architecture/NETWORK_IPAM_CONTRACT.md`, `config/infrastructure/network-plan.yaml` | EXACT |
| Storage | `docs/architecture/STORAGE_TOPOLOGY_V2.md`, `config/infrastructure/storage-plan.yaml` | EXACT |
| Service ownership | `docs/architecture/SERVICE_OWNERSHIP_MATRIX.md`, `config/contracts/service-ownership.yaml` | EXACT |
| Data ownership | `docs/architecture/DATA_OWNERSHIP_MATRIX.md` | EXACT |
| Event ownership | `docs/architecture/EVENT_CONTRACT_MATRIX.md`, `config/contracts/event-contracts.yaml` | EXACT |
| Service dependencies | `config/contracts/dependency-map.yaml` | EXACT |
| Security boundaries | `docs/architecture/SECURITY_TRUST_ZONES.md` | EXACT |
| Deployment order | `docs/architecture/DEPLOYMENT_DAG.md`, `config/infrastructure/deployment-waves.yaml` | EXACT |
| Codex execution | `docs/project/CODEX_HANDOFFS.md`, issues `#13`, `#14`, `#16-#22` | READY/DEPENDENCY-GATED |
| Work execution | `docs/project/WORK_HANDOFFS.md`, issues `#23-#25` | READY/DEPENDENCY-GATED |

## Allowed blockers after this gate

Only these blocker classes are valid:

- `BLOCKED_EXTERNAL`: credentials, provider account, hardware availability, DNS/domain authority, external API access.
- `BLOCKED_BUDGET`: unapproved or insufficient spend envelope.
- `BLOCKED_CONTRACT`: provider/commercial contract missing or incompatible.
- `BLOCKED_HUMAN_REVIEW`: legal, privacy, accounting or mandatory human approval.
- `BLOCKED_ENGINEERING`: implementation, version compatibility, test, performance or defect failure.
- `BLOCKED_EVIDENCE`: required proof not produced or invalid.
- `BLOCKED_ARCHITECTURE`: only for a newly discovered contradiction or genuinely new structural requirement; never for missing description of the current baseline.

## Codex rule

Codex consumes canonical YAML/contracts as data. It must not duplicate constants in Terraform, Ansible, Helm, scripts or docs. If provider/runtime facts make an exact contract impossible, Codex stops and returns the precise conflict instead of selecting another topology.

## Work rule

Work verifies current external reality against the exact contracts. It does not redesign topology. Provider mismatch is returned as a dated constraint with source and affected contract.

## Readiness verdict

- M1: `READY FOR CODEX`.
- M2: dependency-gated by M1, no specification blocker.
- M3: dependency-gated by M1 and real provider access for deployment, no specification blocker.
- M4-M9: dependency-gated by preceding milestones/evidence, no known specification blocker.
- W1/W2: `READY FOR WORK`.
- W3-W5: evidence/dependency-gated, no specification blocker.

Any future blocker must name one of the blocker classes above and point to the failing dependency, test, provider fact or contract.