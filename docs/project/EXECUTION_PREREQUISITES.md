# EXECUTION PREREQUISITES & BLOCKER CHECKLIST

Status: `ACTIVE`

Purpose: identify inputs that ChatGPT cannot manufacture and that would otherwise block Codex or Work late in the program.

## A. Inputs ChatGPT has prepared

- canonical architecture baseline V2;
- machine-readable architecture lock;
- repository agent rules;
- M0 sync merged;
- milestone program M1-M9;
- Codex handoffs M1-M9;
- Work handoffs W1-W6;
- business readiness gates;
- risk register;
- GitHub milestone trackers #13, #14, #16-#22;
- Work trackers #23-#25;
- PREPROD/PROD certification sequencing and evidence expectations.

## B. Human/account/provider inputs that cannot be invented

| Input | Needed for | Owner/source | Blocking point |
|---|---|---|---|
| phoenixNAP account/API credentials and real resource quota/availability | real M3 provisioning | business owner/provider | M3 DEPLOYED |
| Hetzner account, final orderable PROD hardware/BOM and network allocation | M8 cert/M9 | business owner/provider | M8/M9 |
| ClouDNS registrar/DNS account, MFA/locks and zone authority | DNS real tests/PROD | business owner | M7/M9 |
| Stripe test then production account/config/webhook secrets | payment integration/launch | business owner/Stripe | M6/M9 |
| Qonto PA access/contract/integration credentials where required | billing/e-invoicing | business owner/Qonto | M6/M9 |
| domain names/public DNS delegation | external PREPROD/PROD paths | business owner | external E2E/M9 |
| hardware security keys for privileged identities | privileged IAM proof | business owner/operators | M7/M9 |
| approved budget/cost envelope | provider provisioning/PROD | business owner | real M3 and M9 |
| legal/privacy/accounting sign-off items | commercial launch | qualified humans | M9 |
| customer support/fraud/refund operational owners | operational launch | business owner | M9 |
| initial real catalog/content/media and carrier choices | production commerce | business/product owner | M6/M9 |

These values must never be committed to Git when sensitive. Codex must consume credentials only through the approved secret/bootstrap path.

## C. Version/BOM inputs Codex must resolve and lock

ChatGPT selects architectural products; Codex resolves implementation-compatible current versions in a versioned lock/BOM after compatibility checks.

Required before M4 real deployment:
- RKE2;
- Rocky image/template revision;
- Cilium/Hubble;
- Rancher/Fleet;
- Argo Rollouts;
- Tekton;
- Harbor;
- Istio;
- SPIRE;
- OpenBao/ESO;
- Kyverno/Tetragon;
- CNPG;
- Strimzi/Kafka;
- RabbitMQ operator;
- Redis deployment method;
- OpenSearch;
- SeaweedFS;
- Prometheus/Alertmanager/Grafana/OTel/Wazuh/log pipeline;
- application build/runtime base images;
- Terraform/OpenTofu providers/modules and Ansible collections.

Rule: resolve compatibility as code/config and test it; do not add a new component merely to solve version friction without architecture review.

## D. Data/testing prerequisites

Before M5/M7:
- reproducible synthetic-data generator with fixed seeds and documented distributions;
- no real customer PII in PREPROD;
- synthetic product/SKU/inventory/order/payment/fraud/shipping/review datasets;
- sentinel data for restore/integrity checks;
- external load generators for performance/certification;
- test identities with least privilege;
- mock/sandbox provider endpoints when real integrations are unavailable.

## E. Evidence prerequisites

Every evidence item used for promotion must identify:
- release ID;
- Git commit;
- OCI digest(s);
- configuration/version lock identity;
- environment/campaign;
- timestamp UTC;
- test/control ID;
- result;
- artifact/log/metric reference;
- corrective issue on failure.

Evidence is stored in CI/audit/object evidence systems as appropriate, not as generated bulk artifacts in Git.

## F. Cost governance

Before spending on real infrastructure:
1. Work records current provider price evidence where available.
2. Business owner sets/approves an envelope; ChatGPT records the gate, not a fabricated budget.
3. PREPROD remains JIT and TTL-bounded.
4. PERF workers exist only for required campaigns.
5. Cost changes that alter architecture trigger component/capacity review.
6. M9 cannot start with an unknown recurring PROD cost commitment.

## G. Blocker handling

When Codex or Work reports missing input:
- credential/account/provider access -> `BLOCKED_EXTERNAL` and route to business owner/Work;
- unclear architecture -> `BLOCKED_ARCHITECTURE` and route to ChatGPT;
- failing implementation/test -> `BLOCKED_ENGINEERING` and keep with Codex;
- legal/accounting approval -> `BLOCKED_HUMAN_REVIEW`;
- evidence gap -> `BLOCKED_EVIDENCE` and route to the producer of that evidence.

Never solve a blocker by silently weakening an acceptance gate.