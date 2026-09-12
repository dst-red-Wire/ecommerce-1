# ADR-0001 — Migration du runtime frontend Next.js vers Go + templ + HTMX

Status: ACCEPTED

## Context

Storefront and Admin currently use Next.js/React/Node.js. This is a migration, not a completed bootstrap. No CPU or memory gain is considered proven without PREPROD benchmarks.

## Decision

Keep `frontend/apps/storefront` and `frontend/apps/admin`. Both are distinct deployable applications in the single Go module `frontend/go.mod`, included by the root `go.work`.

The target production frontend runtime is Go + templ + HTMX. HTMX and CSS are vendored static assets embedded into the Go applications. Node.js tooling is prohibited from the active repository.

## Consequences

Shared frontend code is introduced only when justified. The legacy Next.js implementation is removed; rollback is performed by reverting this migration commit.

Positive effects expected: a single Go dependency graph for both frontends, a simpler target runtime and reuse of the repository Go toolchain. These remain hypotheses until measured.

Costs and risks: application migration, replacement of React-specific components and deterministic server-side rendering. Rollback keeps the qualified legacy implementation available until the Go target passes the required gates.

Alternatives rejected: keep Next.js as the production target; or create one Go module per frontend, which would duplicate dependency management without a validated isolation requirement.
