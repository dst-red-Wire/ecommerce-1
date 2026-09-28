# ecommerce-1 agent guide

These rules apply repository-wide. architecture.lock.yaml — the single canonical architecture authority. Read only the sections and contracts needed for the task.

## Environment and ownership

- On Windows, work in the canonical WSL2 Linux checkout, such as /home/dev/ecommerce-1, never /mnt/c.
- Application runtime: Go, server-rendered HTML, templ and HTMX. Node is developer tooling only.
- Tekton owns CI; Rancher Fleet owns GitOps/CD; Argo Rollouts owns progressive delivery.
- Infrastructure logs: OpenTelemetry Collector -> VictoriaLogs. Application telemetry: Rotel -> ClickHouse -> HyperDX. Security-only logs: Data Prepper -> OpenSearch -> Wazuh.
- Repeatable or stateful workstation and host changes belong to Ansible. Stateless repository orchestration belongs to `scripts/repoctl.py`. Specialized validators may use native tools.
- Parallelize only independent work.
- No tracked *.sh automation. Preserve domain ownership and top-level structure; avoid duplicate authorities, pipelines and helpers.
- Services own their persistence. No direct reads of another service database.
- Pin tool and image versions; never promote mutable latest tags.
- Never expose or commit secrets, credentials, kubeconfigs, Terraform state, private keys, generated evidence, caches, binaries, archives or scanner output unless registered as source.

## Bounded context

- Start from the task, selected paths, relevant tests and smallest applicable contract. Do not preload broad docs, PR history or full logs.
- Hooks prepare .context/codex-context.md at L0/L1/L2 ceilings of 4/8/12 KiB. Read it only when repository context is needed. Manual: make context TASK="<task>" PATHS="<paths>"; PRINT=1 displays the pack.
- Reviews: make diff-context BASE=<last-reviewed-sha>. Failures: make failure-context GATE=<gate> or COMPONENT=<component>.
- Context selection does not narrow canonical gate selection or risk classification.

## Validation and delivery

- Use affected deterministic checks. Reuse strictly valid exact-input/exact-SHA PASS evidence.
- Publish through make deliver TITLE="..."; no force-push, governance bypass or direct-push delivery claim.
- PRs state owner, scope, relevant contract, tests/evidence and rollback. Detailed rules: config/contracts/review-policy.yaml.

## Review authority

ChatGPT alone issues CODE and SECURITY reviews bound to the published exact SHA. Codex must not trigger Codex reviews, emit verdicts or merge-readiness markers. A head change invalidates prior final reviews. Gates support review but cannot replace it; sensitive merges retain the repository-owner boundary.

Use .agents/skills/chatgpt-exact-sha-review/ for exact-SHA reviews and .agents/skills/pr-recovery-guided/ for stale or dirty PR recovery. Read their references only for those workflows.

## Build sequence

M0 architecture sync -> M1 bootstrap -> M2 golden product and M2.5 persistent MGMT; M2.5 -> M3 PREPROD infra -> M4 platform; M2 + M4 -> M5 vertical slice -> M6 application -> M7 qualification -> M8 certification -> M9 PROD.

## On-demand references

- Agent efficiency: docs/engineering/agent-efficiency.md
- Qualification: config/contracts/qualification-execution-policy.yaml
- Review and delivery: config/contracts/review-policy.yaml
- Security scanning: config/contracts/security-scan-policy.yaml
