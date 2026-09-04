# GitOps environments

Flux is the only deployment reconciler. Tekton builds and validates artifacts,
then proposes explicit Git changes containing immutable OCI digests.

- `clusters/integration`: permanent Hetzner CCX33, Docker Engine and three-node
  Kind cluster. This is the former `staging` environment.
- `clusters/preproduction`: ephemeral, multi-VM kubeadm cluster. Definitions are
  committed but no cloud resources are created by this repository change.
- `clusters/production`: real HA cluster, reconciled from approved Git changes.
- `infrastructure`: reusable cluster components.
- `legacy`: historical local-only assets, excluded from remote environments.

Application bases live under `apps/<service>/base`; service-owned overlays live
under `apps/<service>/overlays/<environment>`. Their base image name must be the
canonical GHCR repository without a mutable tag. Each service overlay sets
`digest: sha256:...`; cluster Kustomizations include those overlays as
resources and never carry a detached top-level `images: []` placeholder.

All three Flux sources declare protected `main` as authoritative desired state.
The existing staging bootstrap still tracks `infra/tekton-flux` at runtime; no
implicit fast-forward is allowed. The explicit convergence and old-staging
cleanup procedure is documented in `docs/runbooks/flux-integration-migration.md`.
