---
name: pr-recovery-guided
description: Recover, clean, port, qualify, review, and retire stale ecommerce-1 pull-request work safely. Drives the operator one executable instruction at a time, waits for the result, and never batches destructive or state-changing steps.
---

# PR recovery guided

Use this skill when cleaning old pull requests/worktrees, recovering useful uncommitted work, porting a stale PR onto current `main`, qualifying it, or preparing exact-SHA CODE/SECURITY review.

The user's explicit instructions take precedence.

This skill complements `chatgpt-exact-sha-review`: that skill owns exact-SHA CODE and SECURITY review; this skill controls the safe operational sequence.

## Interaction contract

1. Give exactly **one executable instruction at a time**.
2. After giving the instruction, stop and wait for the user's output.
3. Do not provide the next command until the previous result is known.
4. One instruction may contain a small command block only when every command belongs to the same atomic check or action.
5. Never combine backup, destructive cleanup, publication, review, and merge in one instruction.
6. When a command fails, diagnose that failure first; do not continue the planned sequence.
7. Prefer direct action through available GitHub tools when authorized, but still report only the next operator action when local WSL execution is required.

## Safety invariants

- Never force-push.
- Never delete a dirty worktree before its tracked and untracked content is archived and SHA-256 verified.
- Never assume a closed PR's work is useless; inspect whether current `main` already absorbed it or whether review findings contain reusable requirements.
- Never resurrect a very stale branch by blindly merging it into current `main`.
- Never overwrite a canonical contract or generated projection from an obsolete branch without checking current repository authority.
- Never mix an unrelated `main` regression fix into the recovered PR when it can be fixed separately.
- Never request a final CODE/SECURITY review for an uncommitted worktree. Final review is bound to the exact published SHA.
- Never resolve old GitHub review threads merely because a local test exists; resolve only after the new exact SHA contains the fix and the evidence supports it.
- Preserve `main` and any still-open critical-path PR worktree unless the user explicitly targets them.

## Phase 1 — Identify state

Collect only the minimum state needed for the next decision:

- PR number and state.
- branch and exact head SHA.
- current `main` SHA.
- ahead/behind relationship.
- worktree path and dirty/clean state.
- unresolved review thread IDs/severities.

If the worktree is dirty, the next instruction must be backup-related, not cleanup-related.

## Phase 2 — Rescue before cleanup

For dirty worktrees:

1. Save original HEAD, branch, and `git status --short`.
2. Save tracked changes with `git diff --binary`.
3. Archive non-ignored untracked files.
4. Generate SHA-256 manifests.
5. Require `sha256sum -c` PASS before any reset, clean, worktree removal, or branch deletion.

Ignore Windows `:Zone.Identifier` files as cleanup noise unless the user explicitly needs them.

## Phase 3 — Remove obsolete worktrees safely

A worktree can be removed immediately only when all are true:

- it is not a protected/current worktree;
- it is clean;
- its HEAD is already an ancestor of current `main`.

Otherwise classify it as `AUDIT` or `DIRTY`, preserve it, and inspect before removal.

After removal, run `git worktree prune` and `git fetch --prune`.

## Phase 4 — Port a stale PR to current main

When the PR is materially behind current `main`:

1. Preserve the stale worktree.
2. Build a patch containing the stale PR commits plus local tracked changes.
3. Keep untracked content in a separate verified archive.
4. Create a fresh worktree/branch from `origin/main`.
5. Apply the tracked patch with `git apply --3way`.
6. Restore untracked files only after checking path collisions.
7. Do not reuse obsolete authority files blindly; reconcile against current `architecture.lock.yaml` and current canonical contracts.

If governed files are newly introduced under `docs/architecture/`, `config/contracts/`, `config/infrastructure/`, or other registered authority sets, verify that the current root authority registers them exactly once.

## Phase 5 — Qualify and publish with one canonical command

The normal path is a single command:

`make deliver TITLE="..." MSG="..." BASE=main`

`make deliver` owns the complete happy path:

1. qualify the affected change;
2. validate and cache exact-SHA evidence;
3. commit when needed;
4. push without force;
5. create or refresh the pull request.

Do not split the normal workflow into `verify-change` + manual evidence JSON inspection + manual `git push`.

Use focused tests, `make verify-change`, evidence-file inspection, or `git push` only as bounded diagnostic/recovery tools when `make deliver` fails or when explicitly required to investigate a defect.

If a failure is unrelated to the recovered PR and already exists on current `main`, isolate it into a separate branch/PR. Do not contaminate the recovered PR scope.

Use `make failure-context GATE=<gate>` when available rather than pasting large raw logs.

## Phase 6 — Delivery evidence contract

A successful `make deliver` must establish:

- an exact published HEAD SHA;
- PASS qualification for the required affected gates;
- exact-SHA evidence under repository policy;
- a GitHub PR whose head equals that SHA.

Do not require the operator to manually open or parse `.context/evidence/*.json` after a successful `make deliver`; ChatGPT may inspect repository evidence directly when review needs it.

## Phase 7 — Final candidate

After successful `make deliver`:

- capture the exact published HEAD SHA;
- verify the GitHub PR head matches that SHA;
- keep the worktree clean;
- proceed to ChatGPT exact-SHA CODE and SECURITY review.

Do not publish from the stale historical branch when a current-main replacement branch exists.

## Phase 8 — Audit old findings

For every unresolved historical review thread:

1. record thread ID, severity, path, and requirement;
2. map it to the exact correction in the current candidate;
3. map it to deterministic test/evidence;
4. mark it `COVERED`, `PARTIAL`, or `OPEN`.

Do not resolve GitHub threads until the correction exists on the exact published candidate SHA.

## Phase 9 — CODE and SECURITY review

For a final candidate SHA:

1. verify the PR current head equals the intended SHA;
2. use ChatGPT to perform CODE review for that exact SHA;
3. use ChatGPT to perform SECURITY review for that exact SHA;
4. never trigger, request, rerun, poll, or depend on Codex review workflows;
5. reuse valid deterministic evidence and review only the material delta after fixes;
6. if the head SHA changes, treat the prior final review as historical and review the new exact SHA;
7. resolve findings only after the fix exists on a published SHA and its evidence is verified;
8. require no unresolved blocking finding before merge.
9. record final CODE and SECURITY results with the `chatgpt-exact-sha-review:v1` markers required by `review-policy.yaml`;
10. treat Codex comments, reactions, summaries, and review completion as non-authoritative historical input only.

Use `chatgpt-exact-sha-review` as the review authority and duplication-control contract.

## Phase 10 — Merge and cleanup

Merge only after required qualification/review conditions are satisfied.

After merge:

1. update local `main` by fast-forward;
2. verify the work has landed;
3. delete obsolete remote/local branches when safe;
4. remove temporary worktrees only after checking they are clean;
5. preserve verified rescue archives until the user explicitly decides they are no longer needed.

## Response style

Operational responses should be terse.

Preferred pattern:

`Étape N — <goal>`

Then one command block.

Then one sentence stating exactly what output to return.

Do not include future-step command blocks in the same response.
