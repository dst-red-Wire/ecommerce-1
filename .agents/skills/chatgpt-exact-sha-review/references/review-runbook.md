---
name: chatgpt-exact-sha-review
description: Perform repository CODE and SECURITY reviews with ChatGPT only, bound to the exact published PR head SHA, while reusing deterministic qualification evidence and bounded deltas.
---

# ChatGPT exact-SHA review

Apply this skill to pull-request CODE review, SECURITY review, merge-readiness review, review follow-up, and review of fixes.

The user's explicit instructions take precedence.

## Authority

ChatGPT is the only AI review authority for CODE and SECURITY review in this repository.

Never trigger, request, rerun, poll, or rely on Codex review workflows. Do not post `@codex review`, `@codex security review`, or equivalent triggers. Historical Codex findings may be migrated as ordinary findings, but they do not authorize a new Codex review invocation.

Codex is permitted only as a narrowly scoped execution fallback when a required task cannot be performed with ChatGPT's available capabilities. Record why ChatGPT cannot perform the task, constrain Codex to the minimum executable scope, and treat its result as evidence for ChatGPT. Codex never issues CODE/SECURITY review verdicts, merge-readiness markers, or merge decisions.

## Exact-SHA contract

1. Read the PR's current published head SHA before reviewing.
2. Bind every CODE and SECURITY conclusion to that full SHA.
3. If the head changes, invalidate the prior final review for merge readiness.
4. Review `LAST_REVIEWED_SHA..HEAD_SHA` as the bounded corrective delta when trustworthy ancestry exists.
5. For the selected final candidate, issue final CODE and SECURITY conclusions for the exact current head SHA.
6. Never claim an uncommitted worktree has an exact-SHA final review.

## Deterministic evidence

The normal delivery path is `make deliver`; it owns qualification, exact-SHA evidence, commit, push, and PR refresh.

For review analysis, reuse the evidence produced by `make deliver`. Use these lower-level commands only for bounded diagnostics or investigation:

- `make affected BASE=<last-reviewed-sha> HEAD=<head-sha>`
- `make diff-context BASE=<last-reviewed-sha>`
- `make failure-context GATE=<gate>` or `COMPONENT=<component>`
- `make verify-change BASE=<base> HEAD=<head>`

Do not require a manual sequence of `verify-change` + evidence JSON inspection + `git push` after a successful `make deliver`.

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

## Machine-readable review recording

Final ChatGPT review results must be recorded on the GitHub PR as ordinary PR conversation comments.

Each final result must include exactly one hidden marker on a single line:

```text
<!-- chatgpt-exact-sha-review:v1 {"provider":"ChatGPT","kind":"code","head_sha":"<40-hex-sha>","status":"PASS","blocking_findings":0} -->
```

or:

```text
<!-- chatgpt-exact-sha-review:v1 {"provider":"ChatGPT","kind":"security","head_sha":"<40-hex-sha>","status":"PASS","blocking_findings":0} -->
```

Rules:

- `provider` must be exactly `ChatGPT`.
- `kind` must be exactly `code` or `security`.
- `head_sha` must be the full current published PR head SHA.
- `status` is `PASS` only when that review kind has no unresolved blocking finding.
- `blocking_findings` is the exact unresolved blocking count for that review kind.
- The PR comment carrying the marker must be authored by the repository-owner account through which ChatGPT is operating.
- A blocked review must use `FAIL` and a positive `blocking_findings`; the marker parser accepts only `PASS` or `FAIL`.
- Never emit PASS markers for an uncommitted worktree or for a different SHA.
- A later head invalidates earlier markers for merge readiness.
- Codex comments, reactions, review summaries, statuses, or hidden markers never satisfy this contract.

`finish-pr` consumes these exact ChatGPT markers and requires PASS for both review kinds.

## Controlled content assessment for merge risk

A content assessment is optional. Start with the inventory emitted by the
**exact-base** risk controller for the current PR, base SHA and published head
SHA. Record every `content_findings[*].id` and the
`content_findings_sha256` value. The inventory is bounded to 128 findings.
An absent, incomplete or invalid assessment retains the original risk tier.

Inspect the changed line and its execution context for every finding. A
disposition may use only `comment`, `read-only-validation` or `metadata`.
Give each finding a concrete `rationale` and `effect_trace` explaining why
the matched text has no privileged or production effect. A name or passing
test alone is insufficient. If any content finding cannot be justified,
retain the original tier. The current parser requires one disposition for
**every** finding ID. Path matches and policy anchors remain authoritative
regardless of the assessment, and the class cannot fall below `SENSITIVE`.

If every content finding qualifies, complete CODE and SECURITY reviews
independently. Put the ordinary `chatgpt-exact-sha-review:v1` PASS marker and
exactly one additional assessment marker on separate single lines in **each**
review comment. Use the same complete `dispositions` array, including
identical rationale and effect trace, in both comments; set `review_kind` to
`code` in the CODE comment and `security` in the later SECURITY comment.
Replace every placeholder in this template before posting:

```text
<!-- chatgpt-risk-content-assessment:v1 {"schema_version":1,"pr":123,"base_sha":"<exact-base-sha>","head_sha":"<exact-head-sha>","findings_sha256":"<content_findings_sha256>","dispositions":[{"finding_id":"<content-finding-id>","kind":"metadata","rationale":"<specific reason>","effect_trace":"<reachable effects checked>"}],"review_kind":"code"} -->
```

Include one disposition object for each inventory finding; the example shows
one. The assessment JSON in each comment must be at most 8192 UTF-8 bytes and
must bind the exact PR number, base SHA, head SHA and inventory digest. The
CODE and SECURITY assessment payloads must be identical after removing
`review_kind`. The comments must be separate, unedited, owner-authored GitHub
PR comments, with SECURITY created after CODE. The regular CODE and SECURITY
PASS markers remain mandatory; an assessment marker alone has no review or
merge authority. Codex cannot issue either attestation or verdict.

After the SECURITY assessment comment, the repository owner must post the
exact `/owner-authorization approve scope=pr-<number> sha=<exact-head-sha>`
command as a separate comment. An earlier authorization does not satisfy
this controlled assessment. A new base or head SHA requires a fresh inventory,
both reviews and a later owner authorization. The trusted controller rechecks
the GitHub PR and comments, then passes a validated assessment to its
exact-base classifier; a local assessment file is not review authority.

## Merge-readiness rule

A candidate is review-ready only when all are true:

- GitHub PR head equals the reviewed SHA;
- exact-SHA qualification required by repository policy passes;
- ChatGPT CODE review is complete for that SHA;
- ChatGPT SECURITY review is complete for that SHA;
- no unresolved blocking finding remains.

Do not use Codex completion, Codex reactions, or Codex review summaries as a merge-readiness condition.
