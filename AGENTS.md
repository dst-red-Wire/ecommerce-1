# Repository agent guide

## Scope

These rules apply to the whole repository.

## Authoritative architecture

Before changing code or structure, read:

1. `docs/architecture/BASELINE_V2.md`
2. `architecture.lock.yaml`
3. relevant ADRs and domain documentation

Validated architecture is not to be redesigned during implementation unless an explicit contradiction is found and routed back to architecture governance.

## Repository rules

- Do not recreate, rename or move top-level architecture arbitrarily.
- Do not create a new domain when an existing owner can hold the responsibility.
- Keep shared libraries minimal; do not centralize domain logic.
- Every backend service owns its `go.mod`, migrations, tests and container build.
- REST and gRPC transports call the same application use cases.
- No service reads another service's database directly.

## Active platform choices

- CI: Tekton.
- GitOps CD: Rancher Fleet.
- Progressive delivery: Argo Rollouts.
- Registry: Harbor.
- Object storage target: SeaweedFS S3.
- Logging/security: Fluent Bit + Data Prepper + OpenSearch Logs + Wazuh.

Do not introduce these superseded defaults into new implementation:

- FluxCD
- Flagger
- MinIO Community Edition / MinIO Operator
- Loki as the logging baseline
- Splunk as the SIEM baseline

Historical references may remain only when explicitly labelled superseded.

## Development

- Keep CI entry points in `scripts/` runnable both locally and in containers.
- Write portable POSIX `sh` for repository shell helpers unless a task explicitly requires another runtime.
- Factor common shell behavior into reusable functions; do not copy helpers between scripts.
- A missing optional project area must be reported as `SKIP`, not treated as a failure.
- Never print secrets, credentials, kubeconfigs, Terraform state, private keys or local environment files.
- Never commit generated reports, caches, binaries, archives or scanner output unless the repository explicitly defines them as source artifacts.
- Never use mutable image tags such as `latest`; pin versions and use digests for promoted artifacts.
- Run `make ci` before submitting CI-related changes.

## Change discipline

Each implementation PR must state:

- owning domain;
- scope and files changed;
- relevant contract/ADR;
- tests added or changed;
- rollback path;
- expected evidence.

Prefer small reviewable PRs over monolithic changes.

## Build sequence

Do not implement the 17 services in parallel from empty scaffolding. Follow:

`M1 bootstrap -> M2 golden product service -> M3 PREPROD infra -> M4 platform -> M5 vertical slice -> M6 remaining application -> M7 qualification -> M8 certification -> M9 PROD`.

The `product` service is the first golden backend implementation and must validate the shared engineering conventions before they are replicated.
## Token-efficient agent context

Do not dump the repository, full CI logs, or broad architecture documentation into an agent prompt by default.

Before implementation, use `make context TASK="<bounded task>"`. The generated `.context/codex-context.md` is the preferred handoff: it routes changes through repository contracts and enforces a bounded byte budget.

Use `make diff-context` for review-oriented work and `make failure-context GATE=<gate>` for deterministic failures. Give the agent the reduced artifact plus the exact failing file/test, not the raw full log.

Context escalation is automatic: L0 for local implementation, L1 for domain/contract work, and L2 for architecture/control-plane work. Do not manually escalate to broader context unless the reduced pack is insufficient or an exact contract requires it.

## Automated delivery

Use `make deliver TITLE="..."` for routine feature-branch handoff. It may run local gates, commit, push without force, generate bounded diff context, and create or refresh a GitHub pull request. It must never merge, auto-approve, bypass branch protection, or act as release authority.
