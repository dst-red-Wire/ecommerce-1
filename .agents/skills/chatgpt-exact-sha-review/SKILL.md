---
name: chatgpt-exact-sha-review
description: Perform repository CODE and SECURITY reviews with ChatGPT only, bound to the exact published PR head SHA, while reusing deterministic qualification evidence and bounded deltas.
---

# ChatGPT exact-SHA review

Apply this skill to pull-request CODE review, SECURITY review, merge-readiness review, review follow-up, and review of fixes.

The user's explicit instructions take precedence.

## Authority

ChatGPT is the only AI review authority for CODE and SECURITY review in this repository.

Never trigger, request, rerun, poll, or rely on Codex review workflows. Do not post `@codex review`, `@codex security review`, or equivalent triggers. Historical Codex findings may be migrated as ordinary findings, but they do not authorize a new Codex invocation.

## Exact-SHA contract

1. Read the PR's current published head SHA before reviewing.
2. Bind every CODE and SECURITY conclusion to that full SHA.
3. If the head changes, invalidate the prior final review for merge readiness.
4. Review `LAST_REVIEWED_SHA..HEAD_SHA` as the bounded corrective delta when trustworthy ancestry exists.
5. For the selected final candidate, issue final CODE and SECURITY conclusions for the exact current head SHA.
6. Never claim an uncommitted worktree has an exact-SHA final review.

## Deterministic evidence

Prefer repository evidence before model analysis:

- `make affected BASE=<last-reviewed-sha> HEAD=<head-sha>`
- `make diff-context BASE=<last-reviewed-sha>`
- `make failure-context GATE=<gate>` or `COMPONENT=<component>`
- `make verify-change BASE=<base> HEAD=<head>`
- exact-commit evidence under `.context/evidence/<head-sha>.json` when repository policy produces it

Reuse valid evidence for identical inputs. Do not rerun a proven gate merely because time passed.

## CODE review

Review at minimum:

- correctness and edge cases;
- regressions and backwards compatibility;
- canonical architecture and repository contracts;
- state transitions and idempotence;
- error and rollback behavior;
- tests and evidence quality;
- operational and deployment consequences;
- accidental scope expansion.

Classify each finding by severity and identify the owning path/component and concrete failure mode.

## SECURITY review

Review at minimum:

- secret handling and accidental disclosure;
- authentication, authorization, and authority transitions;
- input validation and injection boundaries;
- network exposure and firewall/routing behavior;
- privilege and filesystem permissions;
- supply-chain, artifact, signature, and digest integrity;
- unsafe defaults, fail-open behavior, and rollback bypasses;
- destructive or irreversible operations;
- auditability without leaking sensitive data.

Do not infer safety solely from passing tests.

## Finding lifecycle

For each finding record:

- severity;
- reviewed SHA;
- path/component;
- concrete risk;
- required correction;
- deterministic proof expected.

Resolve a finding only when the fix is present on a published SHA and the supporting evidence has been checked.

## Review result

A final review result must state:

- PR number;
- exact full head SHA;
- CODE review status;
- SECURITY review status;
- qualification/evidence status;
- unresolved blockers, if any.

A prior review on another SHA is historical context only.

## Merge-readiness rule

A candidate is review-ready only when all are true:

- GitHub PR head equals the reviewed SHA;
- exact-SHA qualification required by repository policy passes;
- ChatGPT CODE review is complete for that SHA;
- ChatGPT SECURITY review is complete for that SHA;
- no unresolved blocking finding remains.

Do not use Codex completion, Codex reactions, or Codex review summaries as a merge-readiness condition.
