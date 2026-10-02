# Tekton CI authority

`platform/tekton` is the sole repository CI control plane for ecommerce-1. Repository-local Make targets and `scripts/ci-*` files remain the deterministic implementation primitives; Tekton invokes them and owns remote CI execution.

## Pipeline classes

- `global`: architecture/governance, API contracts, secret scan and shell automation.
- `frontend`: Storefront or Admin, parameterized by scope and using the PNPM workspace.
- `go-service`: one autonomous `services/<service>` Go module at a time.
- `platform`: OpenTofu or Ansible validation without performing apply/mutation.
- `product-release`: M2 golden path from exact-SHA Product gates to multi-architecture OCI build, Harbor push, Trivy, Syft, and Cosign signature/attestation. It never deploys or mutates Fleet state.

Changed paths are classified with `scripts/ci-affected.rb` (`make affected BASE=<sha> HEAD=<sha>`). The classifier uses the canonical ownership/API contracts and fails closed for unknown service or OpenAPI paths. CI-control changes fan out to every component class.

`ecommerce-affected` is the intended affected-only orchestration pipeline. It executes the global guards, consumes the classifier result, and fans out component gates. Direct-parent evidence reuse is disabled until a trusted verifier outside the PR workspace can authenticate it. The Matrix/array-result fan-out requires Tekton `enable-api-fields=beta`; management-plane admission must keep that feature enabled before this pipeline is certified.

The affected Pipeline runs PR-controlled scripts without registry, signing, or forge status credentials. Its PipelineRun must use the dedicated `runner-workload` ServiceAccount with token automount disabled and no attached Secrets; Tekton may otherwise inject credentials into every Step via `/tekton/creds`. No trigger or admission policy currently proves this binding, so runner authority stays inactive. It forces a full gate plan and writes local evidence only. Remote signed evidence publication and the `tekton/ecommerce-affected` status are blocked until an independently approved controller outside the PR workspace verifies gate results and publishes them. `make tekton-proof` fails with `BLOCKED_POLICY` while that publisher is absent; local records are not merge authority.

## Runtime contract

The authoritative `ecommerce-affected` Pipeline owns population of its `source` workspace. Its first Task initializes an empty workspace, rejects repository URLs with embedded credentials, fetches the immutable base/head commit SHAs supplied by the authenticated trigger, and checks out the head detached before classification. The Task check runs after PipelineRun creation; a future authenticated trigger or admission policy must compare the URL with trusted repository coordinates and reject unsafe values before storing a PipelineRun. That pre-creation guard is absent and blocks activation. `repoctl tekton-plan` then fails closed unless the requested head resolves to the clean checked-out `HEAD`. Runner images are supplied as Pipeline parameters because their immutable Harbor digests belong to the management-plane runtime configuration, not to an unverified public tag in these manifests. Admission policy must require `@sha256:` runner references before the Tekton control plane is certified.

CI may build, test, scan, attest and publish immutable artifacts. It must not deploy workloads directly. Promotion remains `Tekton -> Harbor digest -> reviewed GitOps update -> Fleet -> cluster`, with Argo Rollouts used only for rollout strategy.

The Product release pipeline accepts all execution images as runtime parameters; M4 admission must reject any value that is not an immutable `@sha256:` Harbor reference. Registry and signing credentials are secret names only and must be materialized from OpenBao through ESO. The signature Task has no PR source workspace: it regenerates its SBOM from the immutable image digest in a private emptyDir before signing. M2 proves this pipeline statically. A real Harbor push, Trivy scan of the published digest, SBOM attestation, signature, and Fleet reconciliation remain `REMOTE_RUNTIME_NOT_AVAILABLE` until the M4 control plane exists.

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
