# MLOps topology V1

Status: `EXACT`

## Lifecycle

`dataset -> experiment -> candidate -> deterministic gates -> security/provenance -> champion/challenger -> probabilistic evaluation -> drift baseline -> signed OCI artifact -> GitOps PR -> shadow -> canary -> promotion`

## Data and metadata

- lakeFS: sole dataset-version authority; its dedicated CNPG metadata references objects in SeaweedFS S3.
- MLflow: dedicated CNPG metadata; experiments, metrics, lineage, run/dataset/model relationships and champion/challenger.
- SeaweedFS S3: dataset/object backend with dedicated buckets by environment/finality.
- Harbor: authoritative OCI registry for Modelcars and signed RAG snapshots.

## Artefact identity

A promotable ML release pins at minimum:

- source revision
- lakeFS dataset commit/digest
- training/evaluation code revision
- parameters
- base model revision
- tokenizer/config
- quantization
- runtime config
- embedding model digest when used
- reranker digest when used
- RAG snapshot digest when used
- chunking policy version
- evaluation digest
- SBOM/provenance/signature

## Evaluation

Order:

1. deterministic hard gates;
2. security/provenance gates;
3. champion/challenger non-inferiority;
4. probabilistic quality evaluation;
5. drift baseline registration.

Critical invariants use tolerance zero. Drift is multi-signal and persistent; there is no single universal threshold.

## Promotion

- Tekton orchestrates import/build/evaluation.
- Syft/Trivy produce SBOM/scan evidence.
- Cosign signs with OpenBao-backed authority.
- Harbor stores immutable Modelcars by digest.
- Fleet carries desired state.
- Argo Rollouts manages progressive exposure where applicable.
- double approval is required where governed by release/AIOps policy.
- no automatic model promotion: a human approval is required before the GitOps PR can be merged and promoted.

## Drift and retraining

Evidently OSS runs as a Tekton batch, never as a permanent launch service. Its Prometheus-compatible metrics are scraped by vmagent into VictoriaMetrics; detailed governed evidence never includes raw datasets in metrics or logs.

`drift -> qualification (dedupe, quotas, evidence) -> analysis -> approval if retraining is justified -> training -> full qualification -> challenger/champion -> GitOps PR -> shadow -> canary -> promotion`

Drift never directly triggers training, promotion or deployment. Retraining is bounded; no model self-promotion is permitted.

## Recovery

Retention classes R0-R5 apply by artefact/data class.

Required recovery assets:

- CNPG backups for separate lakeFS and MLflow metadata;
- independent SeaweedFS S3 backup for datasets/evaluation artefacts;
- Harbor recovery for OCI artefacts;
- tested restore procedures;
- promotion freeze during recovery.

## Runtime

- no Internet download at inference runtime;
- deploy by immutable digest only;
- KServe/vLLM GPU JIT has no source-of-truth or promotion authority;
- rollback selects a previously approved immutable release bundle.
- recovery order is IAM/OpenBao -> GitOps/Harbor -> CNPG -> S3 -> lakeFS/MLflow -> integrity/lineage verification -> runtimes; resilience governance remains authoritative for RTO/RPO.
- GPU JIT is for qualification or inference only; after a temporary campaign archive evidence, destroy resources and prove `GPU_ZERO_RESOURCE=true`.
