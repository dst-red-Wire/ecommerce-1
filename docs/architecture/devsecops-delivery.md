# DevSecOps delivery architecture

## Responsibility split

```text
Developer -> GitHub -> Tekton -> GHCR -> Git digest update -> Flux
```

- GitHub is the Git source of truth and review boundary.
- Tekton owns tests, source scanning, one OCI build, image scanning and SBOM.
- BuildKit pushes to GHCR and returns the registry-produced digest through the
  `IMAGE_DIGEST` result. Tekton never invents a digest.
- Tekton Chains ignores TaskRun storage and signs the completed, deeply
  inspected `build-and-publish` PipelineRun. A build TaskRun is never an
  approval boundary.
- The promotion pipeline changes Git only. Flux alone deploys and reconciles.

The image convention is lowercase:

```text
ghcr.io/dst-red-wire/ecommerce-1/<service>
```

Tags identify source builds for humans, but Kubernetes deployments use only:

```text
ghcr.io/dst-red-wire/ecommerce-1/<service>@sha256:<registry-digest>
```

## Build and promotion

The `build-and-publish` Pipeline accepts only a full commit SHA. Clone writes a
Git archive to a separate `source-snapshot` workspace. Tests and source scans
receive only a read-only checkout; BuildKit receives only the archived
snapshot, verifies its SHA-256, extracts it in a preparation step, and mounts
the resulting context read-only. The raw build and final evidence Tasks expose
only deliberately untyped results. `IMAGE_URL`/`IMAGE_DIGEST` exist solely as
completed Pipeline results so an early TaskRun cannot look like final approval.
The unsigned `DeliveryEvidence` remains explicitly `NOT_PROVEN`.

After Chains has signed the completed PipelineRun, a separately trusted final
attestor may issue `promotion-proof.json` plus its Sigstore bundle. This
environment-specific `PromotionProof` binds repository, commit, source
snapshot, service, digest, the consumed DeliveryEvidence hash, exact scan set,
SBOM reference/hash, PipelineRun UID, Chains provenance reference, issuer/key
identity and bounded expiration. The proof, bundle, and DeliveryEvidence are
copied once into an immutable task-local snapshot; Cosign, JSON Schema and
business parsing all consume those same bytes. The promotion Pipeline has no
digest parameter.

The `promote-image` Pipeline permits only these edges:

```text
build -> integration
integration -> preproduction
preproduction -> production
```

The signed proof closes the only permitted edges. Integration uses `build` as
its source; preproduction uses `integration`; production uses `preproduction`.
The machine-readable mapping is
`contracts/supply-chain/promotion-policy.json`.
The update Task starts from the current remote `main` SHA, compares it with the
caller-provided optimistic-lock SHA, changes exactly one service overlay and
creates a deterministic proposal branch. It never rebuilds and never pushes
`main`.

Protected `main` and pull-request approval remain GitHub responsibilities. The
proposal branch is `promotion/<environment>/<service>/<digest-prefix>`. A
concurrent identical proposal is idempotent; a changed `main` or colliding
branch fails closed without retry or force push. Until a GitHub App restricted
to proposal branches and the PR integration are provisioned, promotion
PipelineRuns must not be started.

The generic Dockerfile builder uses rootless BuildKit. Its user namespace still
uses `--oci-worker-no-process-sandbox` and needs an unconfined
seccomp/AppArmor exception while remaining non-root and non-privileged. The Run
contract requires label `ecommerce.dev/workload=ci-build`, taint
`ecommerce.dev/ci-build=true:NoSchedule`, explicit resources and the isolated
`tekton-ci` namespace. No run-submitter RoleBinding exists. The Kyverno policy
remains `Audit` and must become `Enforce` only after a dedicated CI worker and
the narrow Pod Security exception are runtime-tested. The first real build is a
blocking validation, not assumed readiness.

## Why no Gitea, Harbor or registry:2

The historical local bootstrap keeps Gitea and `registry:2` for isolated local
experiments. They are not referenced by remote environments. GitHub already
provides the authoritative Git service and GHCR provides the required OCI
registry, access control and digest pulls. Adding Gitea or Harbor to the current
single-server integration environment would add state, backups, credentials and
operations without improving the validated delivery path.
