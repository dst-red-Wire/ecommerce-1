# Tekton exact runtime proof

This operation closes the distributed execution-evidence proof without turning GitHub,
Gitea, Make, or Ansible into a second CI authority. Tekton remains the executor and the
only component allowed to publish the `tekton/ecommerce-affected` PASS status.

## Safety boundary

`make tekton-proof` is a state-changing management-plane operation. It reconciles the
versioned `platform/tekton` Tasks/Pipelines and creates deterministic parent and child `PipelineRun` objects for the supplied immutable
base/parent/head SHAs. The parent run publishes full signed evidence; the child run must
fetch that evidence from Harbor and reuse it before a clean verifier Pod authenticates
the child evidence again. Run it only after the wiring
change has passed review and the human runtime-activation gate has been granted.

The operation does not create plaintext credentials. Secret material must already reach
Kubernetes through the approved OpenBao -> External Secrets Operator path. The runtime
config contains names/coordinates only and must not contain token, password, private-key,
or Docker-auth values.

## Non-secret runtime config shape

```yaml
kube_context: management-context
namespace: ecommerce-ci
runner_image: harbor.example/project/ci-runner@sha256:<64-hex>
pipeline_service_account: ecommerce-ci-runner
repo_url: https://forge.example/owner/ecommerce-1.git
evidence_repository: harbor.example/project/ci-evidence
evidence_signing_secret: ci-evidence-signing
registry_auth_secret: harbor-registry-auth
status_secret: ci-forge-status
```

The referenced signing Secret must expose the keys `cosign.key`, `cosign.pub`, and
`cosign.password`. The registry Secret must expose `.dockerconfigjson`. The dedicated
status Secret must expose exactly one provider shape already supported by
`repository_delivery.py`: either `GITHUB_REPOSITORY` + `GITHUB_TOKEN`, or
`GITEA_API_URL` + `GITEA_REPOSITORY` + `GITEA_TOKEN`.

## Execution

After review/merge and the explicit human activation gate:

```text
make tekton-proof \\
  RUNTIME_CONFIG=/absolute/path/to/non-secret-runtime.yaml \\
  BASE_SHA=<full-base-sha> \\
  PARENT_SHA=<full-parent-sha> \\
  HEAD_SHA=<full-head-sha>
```

Before any management-plane mutation, the playbook proves the exact two-commit
relationship `BASE_SHA -> PARENT_SHA -> HEAD_SHA` from local Git objects. A mismatch
blocks the operation before Tekton reconciliation or PipelineRun creation.

Recovery is fail-closed and automation-owned. Successful exact parent/child `PipelineRun`
objects are preserved. A terminal failed run is recycled only after its controller label,
full proof SHA, service account, repository, evidence coordinates, and secret-name inputs
match the requested proof exactly. A stale verifier Pod is likewise deleted only after
its automation ownership and exact head SHA are proven, so retries require no manual
resource deletion.

A successful playbook means the exact `PipelineRun` completed successfully. Final proof
still requires reading back the exact forge status and authenticated Harbor evidence for
the same head SHA; absence of either remains BLOCKED rather than PASS.
