# Flux staging-to-integration convergence

## Invariants

Protected `main` is the sole desired-state branch for integration,
preproduction and production. The currently running staging bootstrap may
still reference `infra/tekton-flux`; this repository pass does not mutate it.
Never fast-forward or push feature-branch history into `main` as a migration.

## Reviewed convergence

1. Merge only the reviewed, targeted GitOps changes through a normal PR into
   `main`.
2. Record the merged `main` commit and render
   `gitops/clusters/integration` locally.
3. Read the existing staging Flux `GitRepository` and `Kustomization`, their
   inventory, health and prune settings. This is a read-only checkpoint.
4. During a separately authorized runtime window, bootstrap the integration
   path from the recorded `main` commit. This is the first operation allowed to
   mutate Flux and is outside this pass.
5. Prove reconciliation, health, inventory ownership and rollback from Git.
6. Enable/retain `prune: true` only after confirming that the new inventory does
   not claim legacy staging resources unintentionally.
7. Remove the obsolete `ecommerce-staging` source/Kustomization only in a
   separate reviewed cleanup, after the integration inventory is healthy.

Flux self-manages its `GitRepository` and `Kustomization` after bootstrap.
Rollback means reverting the reviewed desired-state commit or restoring the
previous digest in Git; do not use direct workload `kubectl apply`.

Current runtime convergence status: `NOT PROVEN`.
