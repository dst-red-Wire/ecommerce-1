---
name: pr-recovery-guided
description: Route stale/dirty pull-request recovery through a safe one-step-at-a-time workflow.
---

# PR recovery router

Use this skill for stale PRs/worktrees, dirty recovery, porting old work to current main, qualification preparation, or safe retirement.

## Non-negotiable invariants

- Give one executable operator action at a time and inspect its result before the next state-changing action.
- Never force-push.
- Never delete dirty work before tracked/untracked content is archived and SHA-256 verified.
- Never equate CLOSED with ABSORBED or assume a stale branch is useless.
- Preserve current main and unrelated active worktrees.
- Port materially stale work onto a fresh current-main branch instead of blindly merging obsolete history.
- Do not overwrite current authority files from an old branch without reconciliation.
- Final CODE/SECURITY review belongs to ChatGPT and only to a published exact SHA.
- Use make deliver for canonical publication once the recovered work is ready.

## Progressive disclosure

First collect only PR number/state, branch/head SHA, current main SHA, ahead/behind relation, worktree cleanliness, and unresolved blocking findings.

Read references/recovery-runbook.md only when the recovery actually enters backup, cleanup, porting, qualification, publication, or thread-resolution steps.
