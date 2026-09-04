# MLOps topology V1

Status: `EXACT`

## Lifecycle

`dataset -> experiment -> candidate -> deterministic gates -> champion/challenger -> signed OCI artifact -> GitOps promotion -> deployment -> drift monitoring -> rollback/retrain trigger`

## Data and metadata

- Dataset versioning: DVC + Git/Gitea + SeaweedFS S3.
- MLflow: experiments, metadata, lineage, run/dataset/model relationships and digests.
- SeaweedFS S3: dataset/object backend with dedicated buckets by environment/finality.
- Harbor: authoritative OCI registry for Modelcars and signed RAG snapshots.

## Artefact identity

A promotable ML release pins at minimum:

- source revision
- dataset digest/version
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
- evaluation result digest
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
- no model self-promotion.

## Retraining

- event-driven and bounded;
- scheduled re-evaluation is allowed;
- no blind retraining;
- no automatic promotion;
- retraining output always re-enters full candidate evaluation.

## Recovery

Retention classes R0-R5 apply by artefact/data class.

Required recovery assets:

- PostgreSQL backup for MLflow metadata;
- independent object backup for datasets/evaluation artefacts;
- Harbor recovery for OCI artefacts;
- tested restore procedures;
- promotion freeze during recovery.

## Runtime

- no Internet download at inference runtime;
- deploy by immutable digest only;
- KServe/vLLM GPU JIT has no source-of-truth or promotion authority;
- rollback selects a previously approved immutable release bundle.
