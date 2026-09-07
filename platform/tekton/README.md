# Tekton CI authority

`platform/tekton` is the sole repository CI control plane for ecommerce-1. Repository-local Make targets and `scripts/ci-*` files remain the deterministic implementation primitives; Tekton invokes them and owns remote CI execution.

## Pipeline classes

- `global`: architecture/governance, API contracts, secret scan and shell automation.
- `frontend`: Storefront or Admin, parameterized by scope and using the PNPM workspace.
- `go-service`: one autonomous `services/<service>` Go module at a time.
- `platform`: Terraform or Ansible validation without performing apply/mutation.

Changed paths are classified with `scripts/ci-affected.rb` (`make affected BASE=<sha> HEAD=<sha>`). The classifier uses the canonical ownership/API contracts and fails closed for unknown service or OpenAPI paths. CI-control changes fan out to every component class.

`ecommerce-affected` is the authoritative affected-only orchestration pipeline. It always executes the global guards, consumes the classifier result, and fans out only component gates that require execution. Exact direct-parent PASS evidence may suppress an unaffected expensive component gate only after signature/provenance verification. The Matrix/array-result fan-out requires Tekton `enable-api-fields=beta`; management-plane admission must keep that feature enabled before this pipeline is certified.

Remote PASS evidence is published as a signed OCI artifact in Harbor according to `config/contracts/ci-evidence.yaml`. Missing or unverifiable evidence is an optimization miss and forces execution; it is never converted into PASS. The finalizer publishes `tekton/ecommerce-affected` against the exact reviewed SHA when Gitea status credentials are present.

## Runtime contract

Each Pipeline receives a `source` workspace containing the exact commit SHA being reviewed. Runner images are supplied as Pipeline parameters because their immutable Harbor digests belong to the management-plane runtime configuration, not to an unverified public tag in these manifests. Admission policy must require `@sha256:` runner references before the Tekton control plane is certified.

CI may build, test, scan, attest and publish immutable artifacts. It must not deploy workloads directly. Promotion remains `Tekton -> Harbor digest -> reviewed GitOps update -> Fleet -> cluster`, with Argo Rollouts used only for rollout strategy.

## Forge trigger path

The target trigger path is direct and has no intermediate CI engine:

```text
Gitea push / PR
  -> Gitea webhook
  -> Tekton EventListener / TriggerBinding / TriggerTemplate
  -> Tekton PipelineRun
```

Gitea is the forge authority for source, pull requests, review metadata and webhook delivery. Tekton is the only CI execution authority. Gitea Actions may be used only for bounded forge administration that does not run build, test, lint, scan, SBOM, signing, publishing, deployment or GitOps promotion. Gitea Actions must not be used as a wrapper whose purpose is to launch Tekton; the webhook calls Tekton Triggers directly.

Webhook delivery must be authenticated before a `PipelineRun` is created. Gitea publishes `X-Gitea-Signature` and a GitHub-compatible `X-Hub-Signature-256`, both HMAC-SHA256 over the raw request body. The webhook secret belongs in OpenBao and reaches the receiver through ESO; it must never be committed. The concrete interceptor/service-account/ingress resources live under `platform/tekton/triggers/` once the management-plane runtime prerequisites are present.
