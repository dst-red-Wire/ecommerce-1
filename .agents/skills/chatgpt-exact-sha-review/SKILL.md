---
name: chatgpt-exact-sha-review
description: Route exact-SHA CODE/SECURITY review work to the bounded ChatGPT review workflow.
---

# Exact-SHA review router

Use this skill only for pull-request CODE review, SECURITY review, review follow-up, or merge-readiness review.

## Non-negotiable invariants

- ChatGPT is the sole AI CODE/SECURITY review authority.
- Never trigger, poll, request, or rely on Codex review workflows.
- Bind every conclusion to the current published full PR head SHA.
- A head change invalidates the prior final review for merge readiness.
- Reuse valid deterministic evidence and review only the bounded corrective delta when ancestry is trustworthy.
- Deterministic gates are evidence; they never replace ChatGPT review.
- Codex may execute a narrowly scoped fallback only when ChatGPT lacks the required execution capability; its output remains evidence, never a verdict.
- Never issue a final exact-SHA review for an uncommitted worktree.

## Progressive disclosure

Start with the PR metadata, current exact head SHA, bounded changed paths/diff, unresolved findings, and exact-SHA qualification evidence. Do not load PR history or broad repository documentation by default.

Read references/review-runbook.md only when an actual CODE/SECURITY review or finding lifecycle operation needs the detailed checklist, evidence format, or result-marker contract.
