---
name: codex-review-budget
description: Reduce Codex and Work usage by reusing exact-SHA evidence, analyzing only material deltas, and reserving full reviews for final candidate SHAs.
---

# Codex review budget

Apply this skill to pull-request review, review polling, qualification follow-up, or repeated agent analysis.

The user's explicit instructions take precedence over this skill.

## Objective

Preserve review quality while avoiding repeated model work. Deterministic repository tools collect state, run tests, classify impact, and summarize failures. Invoke an AI review only when the material state changed or a final-candidate review is required.

## Mandatory workflow

1. Poll forge state with deterministic tools only. Time passing is never sufficient reason to invoke Codex.
2. Persist a minimal snapshot per PR: head SHA, last reviewed SHA, review decision, check summary, and stable IDs of unresolved findings.
3. When the head SHA changes, analyze `LAST_REVIEWED_SHA..HEAD_SHA`; do not reread the unchanged repository. Use the repository's existing `affected` and `diff-context` commands.
4. Run a full code/security review once for each explicitly selected final-candidate SHA. After a fix, review the delta from the last reviewed SHA unless the change invalidates the full-review assumptions.
5. Reuse exact-SHA qualification and review evidence. Never rerun an already-proven gate for the same inputs unless its evidence is missing, invalid, or the relevant contract changed.
6. Keep mechanical work outside the model: Git operations, status comparison, affected routing, linters, tests, validation, and log extraction are deterministic.
7. Give agents bounded failure summaries, not full logs. Include command, exit code, pass/fail counts when available, failing files/tests, and a short error window. Keep the raw log outside the prompt.
8. Use three reasoning depths: FAST for status/classification, NORMAL for a bounded finding or changed component, DEEP only for architecture, complex incidents, or one final-candidate review.
9. Group unresolved findings by owning component/path and analyze coherent groups together. Do not create one model session per finding by default.
10. Cache review artifacts by `PR/<head-sha>/`. A cache hit for the same review kind and exact SHA suppresses another equivalent model review.

## Repository integration

For `ecommerce-1`, prefer existing commands and contracts:

- `make context TASK="..."` for bounded implementation context.
- `make diff-context BASE=<last-reviewed-sha>` for review deltas.
- `make failure-context GATE=<gate>` or `COMPONENT=<component>` for deterministic failures.
- `make affected BASE=<last-reviewed-sha> HEAD=<head-sha>` before selecting tests.
- `make verify-change BASE=<base> HEAD=<head>` for affected qualification.
- `.context/review-budget/` is ephemeral state and must never be committed.

## Decision contract

Before any repeated review, produce a small decision record with:

- `should_invoke_ai`: boolean
- `reason`: stable reason code
- `depth`: FAST, NORMAL, or DEEP
- `base_sha` and `head_sha`
- `affected_components`
- `unresolved_finding_ids`
- `cached_review_kinds`

If `should_invoke_ai` is false, stop without requesting another model review.

## Escalation

Escalate from differential to full review only when one of these is true: no trustworthy prior review exists for the ancestry, the change modifies review/qualification policy itself, the base changed incompatibly, or the user explicitly selects the SHA as a final candidate.
