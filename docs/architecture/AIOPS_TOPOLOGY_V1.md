# AIOps topology V1

Status: `EXACT`

## Zones

| Zone | Components | Authority |
|---|---|---|
| MGMT `aiops-system` | HolmesGPT, RAG retrievers, Go verifier, signed runbook catalog, incident PostgreSQL, RabbitMQ task queue, SeaweedFS evidence, OpenBao/Cosign, kill switches | permanent control plane |
| GPU JIT | KServe, vLLM, embedding model, reranker, signed Modelcars | inference only; no source of truth |
| PREPROD/PROD executors | Robusta/Tekton executors, collectors, read-only evidence adapters | least privilege execution surface |

## Workflow

`signal -> evidence -> diagnostic -> runbook -> policy -> approval -> execution -> post-check -> audit`

## Sources

- Prometheus metrics
- OpenTelemetry traces/metrics
- Wazuh security signals
- OpenSearch Logs
- Kubernetes events
- Fleet desired/observed state

All retrieved data is untrusted input. C4, secrets, payment data and credentials are excluded from models and embeddings.

## Control plane

- PostgreSQL: incidents, states, locks, leases, approvals, fencing tokens, kill-switch state.
- RabbitMQ Quorum Queue: task transport only.
- SeaweedFS S3 Object Lock: immutable sealed evidence.
- OpenSearch RAG: rebuildable projection, distinct from logs and business OpenSearch.
- runbook catalog: Git, tested, signed, deployed by Fleet.
- Go verifier: deterministic policy/contract authority.

## Autonomy

- L1: read-only; compromise/DFIR/destructive or irreversible operations.
- L2: human approval for writers, PITR, failover, DNS/network/IAM/secrets and durable sensitive changes.
- L3: only explicitly qualified stateless reversible actions and approved reconstructible non-authoritative state.
- initial stateful L3: OpenSearch projection rebuild and explicitly reconstructible Redis caches only.

## Security

- WireGuard + SPIFFE/mTLS between MGMT, target environments and GPU JIT.
- Cilium default-deny.
- separate SPIFFE identities for evidence query, runbook publisher, executor and model runtime.
- model cannot emit shell, kubectl or arbitrary manifests.
- model output is limited to `runbook_id + version + typed parameters + evidence references`.
- kill switches exist per runbook, service, site and globally.

## Crash safety

State transitions:

`PREPARED -> STARTED -> EFFECT_OBSERVED -> VERIFIED`

Execution uses lease heartbeat, monotonic fencing token, idempotency key `incident_id + action_id`, bounded retry and `RECOVERY_PENDING` on uncertainty.

## Release

AIOps immutable release pins orchestrator, verifier, MCP schemas, runbooks, prompts, model, embedding model, reranker and RAG snapshot digests.

Promotion:

`PREPROD qualification -> shadow -> read-only canary -> L3 canary single site/single target -> second site -> champion`

No model signs, merges, approves or promotes itself.
