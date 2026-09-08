# ADR-0001 — Migration du runtime frontend Next.js vers Go + templ + HTMX

Status: ACCEPTED

## Context

Storefront and Admin currently use Next.js/React/Node.js. This is a migration, not a completed bootstrap. No CPU or memory gain is considered proven without PREPROD benchmarks.

## Decision

Keep `frontend/apps/storefront` and `frontend/apps/admin`. Both are distinct deployable applications in the single Go module `frontend/go.mod`, included by the root `go.work`.

The target production frontend runtime is Go + templ + HTMX. Node.js may remain temporarily for Playwright, CSS/build tooling, tests and migration compatibility; it is no longer the target production runtime.

## Consequences

Shared frontend code is introduced only when justified. The existing Next.js implementation remains until migration, PREPROD qualification and production deployment are proven.

Positive effects expected: a single Go dependency graph for both frontends, a simpler target runtime and reuse of the repository Go toolchain. These remain hypotheses until measured.

Costs and risks: application migration, replacement of React-specific components and temporary dual tooling. Rollback keeps the qualified legacy implementation available until the Go target passes the required gates.

Alternatives rejected: keep Next.js as the production target; or create one Go module per frontend, which would duplicate dependency management without a validated isolation requirement.
