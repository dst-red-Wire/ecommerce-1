# ChatGPT exact-SHA review budget

This repository applies `.agents/skills/chatgpt-exact-sha-review/SKILL.md` through the deterministic controller `scripts/review_budget.py`.

## Goal

Reduce repeated ChatGPT CODE/SECURITY analysis without weakening exact-SHA review or qualification. The controller itself never invokes a model. It decides whether an AI review is justified and keeps ephemeral state under `.context/review-budget/`.

## Central delivery loop

After a PR is published, external automation must provision a distinct clean checkout at the PR's exact GitHub `baseRefOid`, then invoke its wrapper against the clean exact-head checkout:

```text
python3 <exact-base-checkout>/scripts/repository_delivery.py trusted-pr-transition \
  --target-root <exact-head-checkout> --pr <number>
```

The trusted wrapper verifies both SHA bindings, repository identity, ancestry, and cleanliness before it runs the exact-base `repoctl.py`. Neither the PR-head Makefile nor PR-head `repoctl.py` is a delivery authority. `make pr-loop PR=<number> TRUSTED_ROOT=<exact-base-checkout>` is only a local adapter to the same base-owned wrapper; external automation must invoke the wrapper directly. The controller derives its state from the current GitHub PR, current exact head SHA, merge-authoritative qualification evidence, owner-authored ChatGPT markers, deterministic repository-owned risk classification, any required exact owner authorization, and current merge controls. It performs only the next authorized transition and does not persist a second delivery state.

Valid qualification and review proofs for the current SHA are reused. A head change makes every qualification, CODE, SECURITY, and owner-authorization proof for the earlier SHA historical, abandons the in-flight transition, and restarts at qualification. Missing CODE or SECURITY emits `state=CHATGPT_REVIEW_REQUIRED` with `review_kind=CODE|SECURITY`, the PR number, exact head SHA, expected marker, and the actual bounded `chatgpt_review_handoff()` payload. That payload contains the exact-head delta, sorted changed files, prior validated verdict, byte count, and SHA-256 digest and never exceeds the 8 KiB central handoff budget; inability to build it blocks the event. The result carries an exact-base `rerun.argv`; the external automatic consumer invokes ChatGPT for exactly that PR/SHA and reruns that same trusted wrapper after a valid marker. The controller itself never invokes a model or creates a verdict. SECURITY is impossible before an exact-SHA CODE PASS with zero blocking findings.

After exact-SHA qualification, CODE, and SECURITY all pass, the base-owned non-LLM policy resolves capabilities and changed paths. Its executable controller is also materialized from the exact PR base SHA and run with Python isolation, so a PR-head replacement cannot classify itself; a missing bootstrap controller or invalid result is `SENSITIVE`. `LOW_RISK` records owner authorization as `NOT_REQUIRED_BY_POLICY`, reaches `MERGE_READY`, and delegates automatically to `finish-pr`. `SENSITIVE` emits `OWNER_AUTH_REQUIRED` with the exact command the repository owner must explicitly approve; the caller reruns `pr-loop` after authorization and then delegates to `finish-pr`. `NOT_REQUIRED_BY_POLICY` is not `AUTO_AUTHORIZED` and never creates a synthetic owner decision.

After all exact-SHA authorities pass, `pr-loop` re-reads GitHub, checks unresolved conversations, branch protection, required checks, and commit provenance, then delegates merge exclusively to `finish-pr`. Post-merge synchronization and canonical `branch-cleanup` are reported separately so cleanup failure cannot be hidden by a successful merge.

Add `--dry-run` and `--json` to the exact-base wrapper command for a read-only versioned machine result. Direct PR-head `repoctl.py pr-loop` and `finish-pr` calls fail closed.

The automatic consumer must treat GitHub, marker, capability, path, diff, or classifier ambiguity as blocking or sensitive. It must never infer a review from local state, trigger SECURITY before CODE, reuse a marker or classification from another SHA, let an LLM classify risk, or synthesize owner authorization.

Comment precedence uses immutable GitHub creation time and comment ID. Editing an older comment cannot make it the latest verdict because `updated_at` is ignored. Owner authorization and revocation require the entire trimmed comment to be the exact command, so documentation, quotations, and fenced examples carry no authority. After `finish-pr`, GitHub is always re-read before assigning the merge result; a non-zero process exit with an exact-head merged PR is a successful merge, while an unavailable re-read yields an unknown result and blocks cleanup until verification.

## The 10 enforced rules

1. Polling is deterministic; elapsed time alone never triggers AI.
2. Minimal PR state is persisted locally.
3. Head changes are reviewed as a delta from the last reviewed SHA.
4. Full DEEP review is reserved for an explicitly selected final candidate.
5. Exact-SHA evidence and review results are reused.
6. Git/status/tests/routing/log extraction remain deterministic.
7. Failure context is bounded before entering an agent prompt.
8. FAST/NORMAL/DEEP depth is selected from the type of change.
9. Findings are grouped by coherent owner/path instead of one session per finding.
10. Review cache key is `PR/head-sha/review-kind`.

## Snapshot format

Create a JSON snapshot outside Git-tracked source, for example `.context/review-budget/current.json`:

```json
{
  "base_sha": "<base-sha>",
  "head_sha": "<head-sha>",
  "last_reviewed_sha": "<last-reviewed-sha-or-empty>",
  "unresolved_finding_ids": ["R1", "R2"],
  "checks": {"qualification": "PASS"},
  "reviews": {"code": "RUNNING", "security": "RUNNING"}
}
```

## Decide whether ChatGPT review should run

```text
python3 scripts/review_budget.py decide --pr 123 --snapshot .context/review-budget/current.json --review-kind combined
```

The output is a compact decision record. If `should_invoke_ai` is false, do not launch another equivalent review.

For a selected final candidate SHA:

```text
python3 scripts/review_budget.py decide --pr 123 --snapshot .context/review-budget/current.json --review-kind security --final-candidate
```

A final candidate uses DEEP only when that exact SHA/review-kind is not already cached.

## Record verified exact-SHA review evidence

```text
python3 scripts/review_budget.py cache --pr 123 --head-sha <sha> --review-kind security --source verified-review
```

A later decision for the same PR/SHA/review-kind returns `exact_sha_cache_hit` and suppresses another equivalent model review.

## Delta and affected routing

When a new head is detected, the decision record includes the deterministic commands to prepare bounded review context. The canonical repository commands remain:

```text
make affected BASE=<last-reviewed-sha> HEAD=<head-sha>
make diff-context BASE=<last-reviewed-sha>
make verify-change BASE=<base-sha> HEAD=<head-sha>
```

Use `make failure-context GATE=<gate>` or `COMPONENT=<component>` for failures instead of sending raw logs.

## Bounded raw-log fallback

When a raw log must be summarized before handoff:

```text
python3 scripts/review_budget.py summarize-log --log /path/to/failure.log
```

Limits are versioned in `config/contracts/review-budget.json`.

## Reproducibility

The behavior is defined by three tracked artifacts: the skill, the JSON contract, and the deterministic Python controller. Runtime state/cache is intentionally untracked under `.context/review-budget/`, so a clean checkout reproduces policy while each environment keeps only its own temporary PR observations.
