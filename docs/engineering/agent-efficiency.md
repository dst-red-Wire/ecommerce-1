# Agent efficiency and Codex token budget

The repository optimizes for deterministic work before model reasoning. Tekton remains CI authority, Fleet remains GitOps/CD authority, and Ansible owns repeatable workstation state.

## Fast path

task -> exact task delta -> affected/native checks -> bounded context -> model only if reasoning remains -> exact evidence -> delivery

Codex must not begin by reading the repository, full PR history, or broad architecture documentation. Project instructions are capped at 4 KiB and AGENTS.md is only a router.

## Automatic Codex context

Trusted Codex workspaces load .codex/config.toml. Its UserPromptSubmit hook prepares .context/codex-context.md and .context/codex-context.json before a prompt without blocking the prompt if the optimization is unavailable.

The hook injects only a small routing summary. The full pack stays on disk and is read only when the task needs repository context.

Governed maximum context sizes:

- L0 local implementation/test: 4 KiB
- L1 domain/API/service contract: 8 KiB
- L2 architecture/security/platform/control plane: 12 KiB

make context TASK="<task>" is the manual equivalent. It prints a one-line summary by default; PRINT=1 explicitly prints the pack.

Default scope is the current working-tree delta. Use SINCE=<sha> only when a committed delta is intentionally required. This prevents old changes on a long-lived feature branch from escalating unrelated later work.

Examples:

    make context TASK="fix product validation"
    make context TASK="review PR correction" SINCE=<last-reviewed-sha>
    make context TASK="inspect staged change" STAGED=1
    make context TASK="show pack" PRINT=1

Canonical documents are pointers by default. Their contents are not copied into the context pack unless an explicit bounded excerpt is requested. Service ownership/dependency/public-API fragments are still routed when a service is identified.

## Review and failure context

make diff-context BASE=<last-reviewed-sha> is capped at 12 KiB and uses a low-context unified diff.

make failure-context GATE=<gate> or COMPONENT=<component> keeps at most 80 causal lines / 12 KiB around deterministic error markers.

ChatGPT review handoffs are capped at 8 KiB. Exact-SHA review cache hits do not trigger another AI review.

## Exact-input Codex cache

Every context manifest records task digest, exact HEAD SHA, relevant-path digest, applicable-contract digest, context-policy version, actual context bytes, and a non-authoritative bytes/4 token estimate.

Together these form the cache key. make codex-budget reports whether an exact previously marked result can be reused. make codex-budget-mark RESULT=.context/<result> marks only an explicit result under .context. Any change to the key invalidates reuse.

This cache never changes CODE/SECURITY authority and never converts stale evidence into current evidence.

## MCP profiles

Repository-managed user profiles are installed by Ansible under ~/.codex/ without overwriting the user's base config.toml:

- ecommerce-minimal: no repository-owned MCP enabled.
- ecommerce-openai: enables only the public OpenAI developer-docs MCP owned by this repository profile.

Run Codex with --profile ecommerce-minimal by default and select the OpenAI profile only for OpenAI/Codex/API documentation work. Unrelated user-global MCP servers remain user-owned and should be disabled in their own profile when not needed.

The project-local Codex configuration caps AGENTS.md ingestion to 4096 bytes, the available-skills catalog to 1200 tokens, and every generic tool/function output retained in history to 4096 tokens. The OpenAI Docs profile allow-lists only `search_openai_docs` and `fetch_openai_doc`, with a 2048-token output budget for each.

## Historical prompts

Old bootstrap/design prompt documents live under archive/legacy-prompts/. They are retained for provenance, excluded from normal context routing, and are not current architecture or implementation authority.

## Ownership

- Ansible: repeatable workstation state and Codex profile installation.
- scripts/repoctl.py: stateless repository orchestration and bounded diagnostics.
- scripts/context-pack.py: task-delta routing and context manifests.
- scripts/codex_budget.py: exact-input result reuse decision.
- .codex/hooks/user_prompt_submit.py: non-authoritative pre-prompt context preparation.
