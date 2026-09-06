# Agent-efficiency and Ansible-first execution model

The repository remains the source of truth. Tekton is the sole CI authority; Rancher Fleet remains GitOps/CD authority. Ansible owns repeatable state reconciliation for the developer workstation and local toolchain. Bazel, Nx and Turborepo remain local accelerators only.

## Fast path before AI

`contracts -> affected classifier -> native deterministic gates -> bounded context -> Codex only for unresolved reasoning -> exact-SHA evidence -> delivery`

Run `make verify-change BASE=origin/main` before delegating a failure. Use `make failure-context COMPONENT=service:product` for an affected component and `make context TASK="..."` only after local tools have reduced the problem.

## Automation ownership

- Ansible: packages, verified Node/Corepack/Go/sqlc/context tooling, Docker readiness, Git-local reconciliation, hooks, repeatable bootstrap and generation/reconciliation workflows.
- `scripts/repoctl.py`: fast stateless repository orchestration, affected-only dispatch, evidence, validation, delivery and diagnostics.
- Ruby/Python/Go helpers: specialized validators, generators and graph/context algorithms when they provide distinct deterministic logic.
- Make/Tekton: stable entrypoints that invoke these owners directly.
- Shell: forbidden in tracked repository sources. Do not add `*.sh`; migrate stateful logic to Ansible and stateless logic to native Python/Ruby/Go/PNPM/Make/Tekton entrypoints.

This split is intentional: starting Ansible for every lint/test would be slower. Ansible handles state; native tools handle stateless checks.

## Accelerator roles

- Bazel: pinned local verification entrypoint; it does not replace Tekton.
- Nx: renders a derived dependency graph from canonical contracts; generated graph state is ignored and non-authoritative.
- Turborepo: schedules/caches frontend tasks inside the existing PNPM workspace.

## Generated contracts

`make api-generate` produces versioned Go and TypeScript transport bindings from `config/contracts/public-api-contracts.yaml`. Before generation, `repoctl` deterministically bundles only the registry-declared `common_components` document into each service specification, rewrites those local `$ref`s to internal refs, rejects any undeclared/remote external reference, and runs Go generation from the owning service module so `oapi-codegen` resolves the correct `go.mod`. Canonical source contracts remain split and unchanged. Contract gates regenerate bindings when OpenAPI changes, so exact-SHA verification detects codegen drift. `make api-mock SERVICE=product` starts Prism from the same contract, and `BASE=... make contracts` performs compatibility checks.

## Evidence and delivery

`make verify-change` writes bounded JSON evidence. Committed verification binds evidence to the exact SHA; pre-push reuses a matching PASS rather than replaying the same gates. `make deliver` builds PR validation from that evidence and never approves or merges.

## Hook/runtime optimization

The pre-commit configuration has one affected-only worktree gate and one exact-SHA pre-push gate. Repository-owned `make publish` skips only the duplicate worktree hook because it immediately runs the stronger exact-SHA gate before push. Hot-path service/frontend checks first validate pinned local state and start Ansible only when reconciliation is actually required.
