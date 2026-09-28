# Agent efficiency and Codex token budget

The repository optimizes for deterministic work before model reasoning. Tekton remains CI authority, Fleet remains GitOps/CD authority, and Ansible owns repeatable workstation state.

## Fast path

task -> exact task delta -> affected/native checks -> bounded context -> model only if reasoning remains -> exact evidence -> delivery

Codex must not begin by reading the repository, full PR history, or broad architecture documentation. Project instructions are capped at 4 KiB and AGENTS.md is only a router.

## Automatic Codex context

Trusted Codex workspaces load .codex/config.toml. Its UserPromptSubmit hook prepares .context/codex-context.md and .context/codex-context.json before a prompt without blocking the prompt if the optimization is unavailable.

The hook injects only a small routing summary. The full pack stays on disk and is read only when the task needs repository context. The hook does not claim an avoided model call.

Governed maximum context sizes:

- L0 local implementation/test: 4 KiB
- L1 domain/API/service contract: 8 KiB
- L2 architecture/security/platform/control plane: 12 KiB

make context TASK="<task>" is the manual equivalent. It prints a one-line summary by default; PRINT=1 explicitly prints the pack.

Default scope selects only dirty paths that match the task. Use PATHS=<exact paths> if the task name is ambiguous, STAGED=1 for the index, or SINCE=<sha> for the committed delta through HEAD. Scope selection only controls AI context; canonical gates and risk classification use their own complete inputs.

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

## Pre-invocation Codex budget

`make codex-run TASK="<bounded task>" PATHS="<exact paths>"` prepares a fresh pack, records preflight byte and non-authoritative token estimates, and uses the central budget decision before `codex exec --json`. A default run is not reusable. For a deterministic local read-only answer, pass `CACHEABLE=1 EXPECT="<literal completion criterion>"`. Only a completed answer matching that criterion with no tool, file-change, web, or MCP event is marked reusable. An eligible HIT prints the verified local result with zero Codex calls.

The cache revalidates current HEAD/base, selected paths, index/worktree state, instructions, contracts, pack digest and result digest. It does not grant gate PASS, CODE/SECURITY review, owner authorization, or merge authority. External-state requests, PR status, CVE scans, code edits, and side-effecting operations are not eligible for reuse.

The run's local `.context/codex-budget/metrics/<id>.json` records the effective profile/model/effort, context bytes, HIT/MISS, call count, duration, success, and usage from supported JSONL events. Cached input is part of input tokens and reasoning is part of output tokens. Missing counters remain null. The interactive CLI and VS Code extension cannot be intercepted before their model calls through UserPromptSubmit; their calls are outside this avoided-call measurement.

Direct `make codex-budget` is a diagnostic check against a fresh context manifest. Manual `make codex-budget-mark RESULT=.context/<result> VALIDATED=1 READ_ONLY=1` requires an explicit completed, validated read-only result.

## MCP profiles

Repository-managed user profiles are installed by Ansible under ~/.codex/ without overwriting the user's base config.toml:

- ecommerce-minimal: no repository-owned MCP enabled.
- ecommerce-openai: enables only the public OpenAI developer-docs MCP owned by this repository profile.

Run Codex with --profile ecommerce-minimal by default and select the OpenAI profile only for OpenAI/Codex/API documentation work. Unrelated user-global MCP servers remain user-owned and should be disabled in their own profile when not needed.

The project-local Codex configuration caps AGENTS.md ingestion to 4096 bytes, the available-skills catalog to 1200 tokens, and every generic tool/function output retained in history to 4096 tokens. The OpenAI Docs profile allow-lists only `search_openai_docs` and `fetch_openai_doc`, with a 2048-token output budget for each.

## Historical prompts

Old bootstrap/design prompts were removed from the current tree. Git history retains their original blobs. A local provenance list is stored under .context/legacy-prompts-provenance.tsv on the migration workstation.

## Acceptance measurement protocol

Freeze the sample before computing a reduction: two new small local changes, one new service/contract task, one governance task, one diagnostic failure, one current-PR follow-up, and two repeats of previously completed read-only local tasks. Report new versus repeated tasks and cold versus warm cache separately. The repeat share may be adjusted only from observed normal workflow frequency, never to manufacture HITs.

For each task record equivalent expected outcome, model and effort, required gates, baseline and optimized Codex JSONL usage, retries, failures and success criteria. Sum `input_tokens + output_tokens` across actual invocations; `cached_input_tokens` is a subset of input and `reasoning_output_tokens` is a subset of output. Keep missing values UNKNOWN. Calculate `1 - after / before` only when both sides are complete and comparable. Context-byte reduction, avoided CLI invocations, token reduction and quality are separate results. If the baseline or sample is incomplete, report MESURE_INSUFFISANTE.

## Ownership

- Ansible: repeatable workstation state and Codex profile installation.
- scripts/repoctl.py: stateless repository orchestration and bounded diagnostics.
- scripts/context-pack.py: task-delta routing and context manifests.
- scripts/codex_budget.py: exact-input result reuse decision.
- .codex/hooks/user_prompt_submit.py: non-authoritative pre-prompt context preparation.
