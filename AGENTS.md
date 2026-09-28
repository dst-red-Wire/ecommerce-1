# ecommerce-1 agent guide

These rules apply to the whole repository. Keep agent context small: this file is a router, not a complete architecture manual.

## Working environment

- On Windows, work only from the canonical WSL2 checkout on the native Linux filesystem, for example /home/dev/ecommerce-1, never /mnt/c.
- Application code is Go with server-rendered HTML, templ, and HTMX. Node-based tooling may exist only as governed developer tooling; do not introduce a Node application runtime.
- Tekton is the CI authority. Rancher Fleet is the GitOps/CD authority. Argo Rollouts owns progressive delivery.

## Read only what the task needs

- architecture.lock.yaml is the architecture authority. Open only the relevant section when the task changes architecture, governance, platform, or a registered contract.
- Start from the user task, touched paths, relevant tests, and the smallest applicable contract. Do not preload broad architecture docs, PR history, full CI logs, or unrelated contracts.
- Codex project hooks prepare .context/codex-context.md with a governed 4/8/12 KiB L0/L1/L2 budget. Read that pack only when repository context is needed.
- Manual fallback: make context TASK="<task>". Use PRINT=1 only when the pack itself must be displayed.
- For review deltas use make diff-context BASE=<last-reviewed-sha>. For failures use make failure-context GATE=<gate> or COMPONENT=<component>.
- archive/legacy-prompts/** is historical-only and excluded from normal agent context. Never use it as current architecture or implementation authority.

## Implementation ownership

- Repeatable or stateful workstation/host changes belong to Ansible.
- Stateless repository orchestration belongs to scripts/repoctl.py; specialized deterministic logic may use Python, Ruby, Go, or a native CLI.
- No tracked shell automation (*.sh).
- Preserve domain ownership and existing top-level structure. Do not create duplicate source-of-truth files, pipelines, helpers, or domain responsibilities.
- Services own their persistence. No service reads another service database directly.
- Use pinned versions/digests; never introduce mutable latest dependencies or promoted artifacts.
- Never print or commit secrets, credentials, kubeconfigs, Terraform state, private keys, generated evidence, caches, binaries, archives, or scanner output unless explicitly registered as source.

## Validation and delivery

- Prefer affected-only deterministic checks. Reuse exact-input/exact-SHA PASS evidence; do not rerun a proven gate merely because time passed.
- Use make deliver TITLE="..." for canonical feature-branch publication. Do not force-push or bypass repository governance. Direct git push is diagnostic/recovery only, not delivery evidence.
- Keep PRs bounded and state owner, scope, relevant contract, tests/evidence, and rollback path.
- Detailed delivery/cleanup rules live in config/contracts/review-policy.yaml; load them only for PR-governance work.

## CODE and SECURITY authority

ChatGPT is the sole AI authority for CODE and SECURITY review. Codex must not trigger, poll, or issue Codex review verdicts or merge-readiness markers.

For exact-SHA review work, use .agents/skills/chatgpt-exact-sha-review/. For stale/dirty PR recovery, use .agents/skills/pr-recovery-guided/. Their SKILL.md files are lightweight routers; read their references/ runbooks only when that workflow is actually active.

A head change invalidates final exact-SHA review evidence. Deterministic gates are evidence, not a substitute for ChatGPT CODE/SECURITY review. Sensitive changes retain the explicit repository-owner merge boundary defined by current policy.

## Detailed references, on demand

- Architecture: architecture.lock.yaml
- Agent/context efficiency: docs/engineering/agent-efficiency.md
- Qualification: config/contracts/qualification-execution-policy.yaml
- Review/delivery: config/contracts/review-policy.yaml
- Security scanning: config/contracts/security-scan-policy.yaml
