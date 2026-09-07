# Gitea -> Tekton trigger boundary

This directory owns the final forge-to-CI trigger integration. The approved flow is:

```text
Gitea push / PR
  -> Gitea webhook
  -> Tekton EventListener
  -> TriggerBinding
  -> TriggerTemplate
  -> PipelineRun
```

No Gitea Actions, Woodpecker, GitHub Actions, Jenkins, GitLab CI or Drone hop belongs between Gitea and Tekton.

Runtime manifests must be added here only when all prerequisites are represented in the repository: Tekton Triggers CRDs, least-privilege EventListener service account/RBAC, the canonical CI runner image by immutable Harbor digest, ingress/network policy, and the webhook secret injected from OpenBao through ESO. Do not commit a placeholder secret or a non-runnable TriggerTemplate merely to make the directory look complete.

The exact prerequisite contract is `config/contracts/tekton-trigger-runtime.yaml`. Namespace selection, the Harbor runner digest, and secret coordinates remain management-plane runtime inputs rather than guessed repository literals. Static contract validation is not runtime proof: EventListener/TriggerBinding/TriggerTemplate manifests remain blocked until every live proof listed by that contract is satisfied.

Source checkout is already owned by `ecommerce-affected`: the Pipeline initializes the workspace and fetches/checks out the immutable base/head SHAs before any gate runs. Trigger resources must pass those authenticated immutable SHAs and the repository clone URL; they must not prepopulate or mutate the source workspace themselves.

The receiver must authenticate Gitea webhook deliveries before creating a PipelineRun. Gitea signs the raw body with HMAC-SHA256 and exposes the digest in `X-Gitea-Signature`; it also emits the GitHub-compatible `X-Hub-Signature-256`. Filter only the canonical `push` and `pull_request` event classes required by `config/contracts/ci-topology.yaml`.
