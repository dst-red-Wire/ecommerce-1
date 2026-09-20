# ChatGPT exact-SHA review budget

This repository applies `.agents/skills/chatgpt-exact-sha-review/SKILL.md` through the deterministic controller `scripts/review_budget.py`.

## Goal

Reduce repeated ChatGPT CODE/SECURITY analysis without weakening exact-SHA review or qualification. The controller itself never invokes a model. It decides whether an AI review is justified and keeps ephemeral state under `.context/review-budget/`.

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
