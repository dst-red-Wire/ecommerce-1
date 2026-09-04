# Tekton delivery runbook

## Hard prerequisites

Do not create a PipelineRun until all of the following are true:

- the application service, `go.mod`, tests and Dockerfile exist;
- the target starts with `ghcr.io/dst-red-wire/ecommerce-1/`;
- `ghcr-push` exists out of band and is attached only to
  `tekton-image-push`;
- the PipelineRun exactly implements the checked-in Run contract, including
  per-task ServiceAccounts;
- source and evidence workspaces have bounded persistent storage;
- the rootless BuildKit exception is confined to a dedicated, labelled and
  tainted CI worker;
- the Kyverno Run contract is in `Enforce` and the run-submitter binding was
  separately reviewed;
- Chains completed-PipelineRun provenance, its signer and independent
  verification are healthy.

Use the Git commit SHA as `source-revision` and a non-`latest` human tag such as
`sha-<short-commit>` as `image-tag`. Pipeline completion returns an unsigned
`DeliveryEvidence` with status `NOT_PROVEN`; it is not promotable by itself. A
trusted final attestor must verify the completed Chains provenance and issue an
environment-specific signed `PromotionProof`.

## Integration update

Run `promote-image` with `environment=integration`, the current remote `main`
SHA and read-only evidence/trust workspaces. There is intentionally no digest,
target branch or source revision parameter. Bind the `github-git-write` Secret
as the `git-auth` workspace only for `propose-git-change`. The signed proof must
declare `sourceEnvironment=build` and the exact service integration overlay.

## Preproduction and production

For preproduction, the signed proof uses `sourceEnvironment=integration`. For
production, it uses `sourceEnvironment=preproduction`. The verifier rejects any
other signed edge and derives the same digest from the proof.

The Git Task fetches remote `main`, enforces optimistic locking, changes one
existing overlay whose image is referenced by the service base, and pushes a
deterministic `promotion/...` proposal branch. An external GitHub integration
creates the PR; this pass creates none. Flux observes only the merged approved
Git state. Tekton must never call `kubectl apply` against an application
environment.
