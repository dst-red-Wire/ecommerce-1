# Execution performance

The repository optimizes cycle time by avoiding unnecessary work before optimizing individual commands.

The execution order is fixed by these controls:

1. `scripts/ci-affected.rb` computes affected components from changed paths and canonical dependency/contract metadata.
2. Exact PASS evidence may be reused only from the direct parent when the strict delta does not affect a gate. Content caches never authorize a PASS.
3. Tekton keeps the authoritative CI DAG: the global-gate branch and affected-component matrix start after classification, and the finalizer joins them.
4. Frontend tasks use Turborepo content-addressed caching, PNPM uses its local store with `--prefer-offline`, and Go uses its native build/test cache. Tekton component TaskRuns share only the concurrency-safe Go build/module cache under the PipelineRun workspace; verdict evidence remains separate. BuildKit cache is activated only when an OCI image-build workflow actually exists; no synthetic cache control plane is added early.
5. `make perf-audit` reads deterministic evidence and writes `.context/performance/<sha>.json` with execution/reuse counts, cache hit ratio, a Tekton critical-path estimate, parallelization headroom, Amdahl priorities and optional full-vs-incremental comparison.
6. Tekton TaskRuns execute their mutable gate work in per-TaskRun ephemeral checkouts while writing only small gate records back to the shared PipelineRun evidence directory. This preserves fan-out without concurrent writes to one worktree.
7. Parallelism remains bounded by the management-plane runner and Kubernetes resource budget. Do not hardcode a concurrency number before runtime measurements prove the CPU/RAM/I/O budget.

The audit is advisory performance evidence. Tekton remains CI authority, deterministic gates remain fail-closed, and the audit cannot promote cached artifacts into PASS evidence.
