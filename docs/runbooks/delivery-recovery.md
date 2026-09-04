# Delivery recovery and rollback

## Digest rollback

Identify the last approved `repository@sha256:digest` and its signed
`PromotionProof`. Create a reviewed PR that changes only the affected service
overlay digest back to that value. Flux performs the rollback. Never rebuild a
historical release, retag it as rollback, or apply the Deployment directly.

## Failed or stale promotion

- If remote `main` differs from `expected-main-sha`, discard the ephemeral
  workspace and rerun against the new SHA.
- If the deterministic proposal branch already carries the same tree and
  idempotence key, reuse it.
- If it differs, stop and investigate; do not force push or retry a stale
  commit.
- If the proof is expired, missing, or unverifiable, status is `NOT PROVEN` and
  no Git proposal is allowed.

## Retention and observability

Retain PipelineRun metadata, structured logs, scan reports, SBOM, Chains
provenance, PromotionProof, gate receipts and PR audit links for the approved
policy period. Export run duration, task failures, queue time, Chains signing
latency, proof verification failures, promotion conflicts, Flux reconciliation
latency and drift alerts. Correlate them by source commit, image digest,
PipelineRun UID and idempotence key; never log credentials or proof private
material.

Runtime retention, metrics, alerts and recovery exercises remain `NOT PROVEN`.
