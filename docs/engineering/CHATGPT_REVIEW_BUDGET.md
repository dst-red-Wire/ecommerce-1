# ChatGPT exact-SHA review budget

This repository applies `.agents/skills/chatgpt-exact-sha-review/SKILL.md` through the deterministic controller `scripts/review_budget.py`.

## Goal

Reduce repeated ChatGPT CODE/SECURITY analysis without weakening exact-SHA review or qualification. The controller itself never invokes a model. It decides whether an AI review is justified and keeps ephemeral state under `.context/review-budget/`.

## Central delivery loop

After a PR is published, provision a distinct checkout at the PR's exact GitHub REST `.base.sha`. Verify that checkout's full HEAD equals `.base.sha` and that it is clean before using it as `TRUSTED_ROOT`. Pass the clean exact-head checkout only as `TARGET_ROOT` data. The base-owned wrapper is the safe controller entrypoint:

```text
python3 -I <verified-exact-base-checkout>/scripts/repository_delivery.py trusted-pr-transition \
  --target-root <exact-head-checkout> --pr <number> --json
```

The trusted wrapper verifies both SHA bindings, repository identity, ancestry, and cleanliness before it runs the exact-base `repoctl.py`. For owner-privileged review, marker, UAC, and merge automation, do not run PR-head Makefile or Python entrypoints such as `make pr-loop`, `make review-dispatch-status`, or `make pr-monitor`. Those entrypoints can run PR-head code before the exact-base wrapper starts. `make deliver` remains the separate official PR publication path. Run privileged dispatch, marker publication, UAC publication, and monitoring only from a separately verified clean exact-base checkout or an independently approved, pinned runner. Do not pass marker, UAC, or merge credentials to qualification subprocesses that may execute PR-head code; block privileged continuation if that isolation is unavailable. The controller derives its state from the current GitHub PR, current exact head SHA, merge-authoritative qualification evidence, owner-authored ChatGPT markers, deterministic repository-owned risk classification, any required exact owner authorization, and current merge controls. It performs only the next authorized transition and does not persist a second delivery state.

### Dynamic exact-head recovery

After the monitor and adapter have been promoted into the verified base, one running monitor handles later PR HEADs without an operator preparing each commit by hand. On startup, restart, and every GitHub HEAD change, it reads the open, non-draft PR's repository, base branch and SHA, head branch and full SHA from GitHub. If the clean target checkout is behind, it fetches that exact SHA and fast-forwards the target branch only after revalidating the same binding. A dirty, divergent, renamed, closed, draft, or otherwise stale target blocks; it is never reset or force-updated.

The independent trusted clone also needs the exact PR commit object for base-owned affected routing such as `scripts/ci-affected.rb`. The trusted `pr_review_dispatch_transition.transition()` performs this object fetch after GitHub preflight and before invoking the wrapper, so both direct base-owned `pr-loop` and monitor-driven transitions use the same path. It fetches only the GitHub-bound full head SHA into the trusted clone's object database, verifies the fetched commit is exactly that SHA, and re-reads GitHub before using it. The fetch uses `--no-write-fetch-head` and leaves `FETCH_HEAD` and branch refs unchanged; it must not checkout, reset, pull, or move the trusted clone's HEAD away from the verified base SHA, and no fetched PR source is executed by the privileged adapter. Dry-run skips the fetch and remains read-only; when the exact object is absent, it reports the missing prerequisite instead of claiming PASS. An object still missing after a failed fetch, changed binding, or changed trusted HEAD is fail-closed: no new review submission, marker, UAC, or merge follows from the old campaign.

Monitor state and outbox records are recovery hints, not authority. On bootstrap and restart, the monitor detects and fast-forwards a stale clean target even if its saved checkpoint already names the new GitHub SHA; the trusted transition repeats the object and binding checks before the wrapper runs. Existing submissions resume by ID; a new SHA starts fresh qualification, CODE, SECURITY, and any required UAC. The user does not need to synchronize either checkout or announce a completed review.

Valid qualification and review proofs for the current SHA are reused. A head change makes every qualification, CODE, SECURITY, and owner-authorization proof for the earlier SHA historical, abandons the in-flight transition, and restarts at qualification. Missing CODE or SECURITY emits `state=CHATGPT_REVIEW_REQUIRED` with `review_kind=CODE|SECURITY`, the PR number, exact head SHA, expected marker, and the actual bounded `chatgpt_review_handoff()` payload. That payload contains the exact-head delta, sorted changed files, prior validated verdict, byte count, and SHA-256 digest and never exceeds the 8 KiB central handoff budget; inability to build it blocks the event. The result carries an exact-base `rerun.argv`; the external automatic consumer invokes ChatGPT for exactly that PR/SHA and reruns that same trusted wrapper after a valid marker. The controller itself never invokes a model or creates a verdict. SECURITY is impossible before an exact-SHA CODE PASS with zero blocking findings.

Once promoted into the trusted exact-base checkout, `scripts/pr_review_dispatch_transition.py` is the adapter for that machine result. Its interpreter and every imported module must resolve inside the verified trusted checkout; the adapter treats `TARGET_ROOT` as data and never imports or executes its Python modules. Qualification gates that may execute PR-head code need a separate credential-isolation boundary. The adapter independently resolves exactly one open, non-draft, same-repository PR for the target branch, base, and full head SHA, and checks that binding again before dispatch. `scripts/chatgpt_review_dispatcher.py` validates the unmodified handoff bytes, their digest, the event schema, and the binding. It records only a reconstructible, content-addressed request under `.context/review-dispatch/`; the request is never review authority. A repeated request is idempotent, and a changed head supersedes the old request. The configured transport receives only the controller's bounded canonical handoff. After a crash, an existing submission is polled by ID instead of resubmitted. A bound real PASS result with zero blocking findings may cause publication of the exact owner-authored PASS marker; a bound FAIL with positive blocking findings may publish a FAIL marker and blocks SECURITY. Both verdicts are recognized only after a fresh GitHub owner-proof read; transport results and outbox remain non-authoritative. Only an unedited, latest exact-SHA GitHub marker accepted by the trusted controller establishes CODE or SECURITY PASS. A missing or disabled transport remains `BLOCKED_EXTERNAL_REVIEW_TRANSPORT`; no PASS is inferred.

During a trusted transition, the base parser reads static toolchain inputs through bounded regular-file descriptors without following symlinks in any path component. The captured bytes and regular-file mode must match the Git blob at the wrapper's exact target HEAD (or exact base for base-owned inputs). The fixed Windows `.ps1`/`.bat`/`.cmd` CRLF checkout projections are compared and parsed as canonical LF bytes, matching `.gitattributes`; JSON, YAML and Python remain byte-for-byte checks. Git clean filters are never executed. Parsing consumes those same bytes, including Ansible projections and the AST of gate sources; it never reopens a checked path or executes a target gate source to inspect it. Local working-tree validation still accepts edits to regular files.

The normal dispatch path requires the controller's structured v1 handoff, including its tree and qualification digest. It uses the same controller response that completed qualification: the fresh qualification witness is process-local, so a second process cannot stabilize it by claiming reuse. The next controller invocation occurs after a verified review marker.

PR #172 has an explicit, temporary transport exception because its pre-v1 base cannot emit that schema. Invoke the adapter from the verified exact-base checkout only, with the independently verified full base and published head SHAs:

```text
python3 -I <verified-exact-base-checkout>/scripts/pr_review_dispatch_transition.py \
  --trusted-root <verified-exact-base-checkout> --target-root <exact-head-checkout> \
  --pr 172 --json \
  --legacy-bootstrap-binding ced96d663c1dca1c885d450104f344c10431738d:<published-head-sha>
```

The equivalent adapter argument is `--legacy-bootstrap-binding <base-sha>:<head-sha>`. The exception is fixed to repository `dst-red-Wire/ecommerce-1`, PR #172, branch `feat/controller-compat-bootstrap`, and the base shown above. Both SHAs must match the current GitHub binding and clean local checkout; changed bindings are rejected. It applies only when the base response contains neither a structured handoff nor a compatibility digest. A present but invalid v1 payload always blocks.

This invocation dispatches the base controller's canonical legacy payload, with `handoff_protocol=legacy-bootstrap` and the exact exception binding recorded in the result and outbox. It does not manufacture a v1 proof. Saved outbox data cannot opt in a later invocation. Qualification, CODE before SECURITY, owner authorization, and merge requirements still belong to the exact-base controller. Without the explicit exception, legacy output is rejected. Both a rejected protocol and unavailable external transport return exit code 1; a valid dry run returns 0, and absence of transport does not change a qualification PASS.

Once the adapter and its dependencies have been promoted into the verified exact-base checkout, read the non-authoritative outbox through that checkout:

```text
python3 -I <verified-exact-base-checkout>/scripts/pr_review_dispatch_transition.py \
  --target-root <exact-head-checkout> --pr <number> --status --kind CODE --json
```

Once the hardened Makefile is itself part of the verified base, the equivalent invocation is `make -C <verified-exact-base-checkout> review-dispatch-status PR=<number> KIND=CODE TRUSTED_ROOT=<verified-exact-base-checkout> TARGET_ROOT=<exact-head-checkout>`. Use `--kind SECURITY` in the direct command or `KIND=SECURITY` in Make for the other review. Status has `verdict_authority=false` and never creates a request. The privileged transition likewise starts from the verified base adapter with `--trusted-root <verified-exact-base-checkout> --target-root <exact-head-checkout> --pr <number> --json`, or, after Makefile promotion, `make -C <verified-exact-base-checkout> pr-loop PR=<number> TRUSTED_ROOT=<verified-exact-base-checkout> TARGET_ROOT=<exact-head-checkout> JSON=1`. After a valid CODE marker appears, it re-reads GitHub, executes the exact-base controller's `rerun.argv`, and allows SECURITY dispatch only after that controller recognizes CODE PASS. The SECURITY marker triggers the same automatic trusted rerun, which verifies both markers. If the controller returns `OWNER_AUTH_REQUIRED` and this exact PR/SHA has explicit owner consent, the owner identity publishes only the exact UAC command; a valid UAC triggers another trusted rerun. Without that consent, it waits at the owner boundary. The controller alone checks merge requirements and delegates merge to `finish-pr`. The user does not have to inform Codex that a ChatGPT review is finished: GitHub markers are rediscovered and verified automatically. If external review remains QUEUED or RUNNING, the invocation exits in a waiting state; a trusted poller resumes on a changed transport state or GitHub proof, never on elapsed time alone.

After exact-SHA qualification, CODE, and SECURITY all pass, the base-owned non-LLM policy resolves capabilities and changed paths. Its executable controller is also materialized from the exact PR base SHA and run with Python isolation, so a PR-head replacement cannot classify itself; a missing bootstrap controller or invalid result is `SENSITIVE`. `LOW_RISK` records owner authorization as `NOT_REQUIRED_BY_POLICY`, reaches `MERGE_READY`, and delegates automatically to `finish-pr`. `SENSITIVE` emits `OWNER_AUTH_REQUIRED` with the exact command the repository owner must explicitly approve for that PR/SHA; when that consent is supplied, the consumer publishes the command and invokes the trusted rerun. `NOT_REQUIRED_BY_POLICY` is not `AUTO_AUTHORIZED` and never creates a synthetic owner decision.

After all exact-SHA authorities pass, `pr-loop` re-reads GitHub, checks unresolved conversations, branch protection, required checks, and commit provenance, then delegates merge exclusively to `finish-pr`. Post-merge synchronization and canonical `branch-cleanup` are reported separately so cleanup failure cannot be hidden by a successful merge.

Add `--dry-run` and `--json` to the exact-base wrapper command for a read-only versioned machine result. Direct PR-head `repoctl.py pr-loop` and `finish-pr` calls fail closed.

The automatic consumer must treat GitHub, marker, capability, path, diff, or classifier ambiguity as blocking or sensitive. It must never infer a review from local state, trigger SECURITY before CODE, reuse a marker or classification from another SHA, let an LLM classify risk, or synthesize owner authorization.

Comment precedence uses immutable GitHub creation time and comment ID. Editing an older comment cannot make it the latest verdict because `updated_at` is ignored. Owner authorization and revocation require the entire trimmed comment to be the exact command, so documentation, quotations, and fenced examples carry no authority. After `finish-pr`, GitHub is always re-read before assigning the merge result; a non-zero process exit with an exact-head merged PR is a successful merge, while an unavailable re-read yields an unknown result and blocks cleanup until verification.

## Transport configuration and recovery

Set `CHATGPT_REVIEW_TRANSPORT=command-v1` to select the repository-owned command adapter explicitly. Set `CHATGPT_REVIEW_TRANSPORT_COMMAND` to an absolute path to the installed ChatGPT review worker and `CHATGPT_REVIEW_TRANSPORT_SHA256` to the 64-character SHA-256 of that executable. The adapter rejects a missing, disabled, non-executable, or digest-mismatched worker. `CHATGPT_REVIEW_TRANSPORT=disabled` disables dispatch explicitly; an unset selection is unavailable. Neither state falls back to another backend. Rotate the pinned executable and its digest together; configure credentials in the worker's runtime secret store, never in Git, outbox records, logs, or test fixtures. An absent credential or worker blocks real review.

A privileged monitor may run only after its code and dependencies are promoted to the verified exact-base checkout and its CLI accepts an explicit `TARGET_ROOT`. It must use the PR checkout only for exact-head data and must invoke the trusted adapter from the same verified base. Its required deployment shape is:

```text
python3 -I <verified-exact-base-checkout>/scripts/pr_monitor.py \
  --owner dst-red-Wire --repo ecommerce-1 --pr <number> \
  --trusted-root <verified-exact-base-checkout> --target-root <exact-head-checkout>
```

This is a required interface, not a command to run against a base version that lacks `--target-root`. Once the hardened Makefile and monitor are both in the verified base, use `make -C <verified-exact-base-checkout> pr-monitor OWNER=dst-red-Wire REPO=ecommerce-1 PR=<number> TRUSTED_ROOT=<verified-exact-base-checkout> TARGET_ROOT=<exact-head-checkout>`. Do not run `make pr-monitor` from the PR checkout with owner credentials. Polling an existing submission uses its saved `submission_id`; an unchanged timer cannot submit a new review. A new GitHub HEAD, CODE marker, SECURITY marker, or UAC proof can start the next trusted transition.

An owner who explicitly authorizes UAC for one exact campaign may pass `--owner-authorization-binding <PR>:<FULL_HEAD_SHA>` to a promoted trusted adapter or monitor. Omit it otherwise. A new HEAD requires new consent, qualification, and reviews.

For PR #185, the exact base `29859406d056debcaab2c8fc7a353a00de987971` does not contain this new transport, marker publisher, UAC publisher, or monitor interface. Its PR HEAD cannot promote itself into owner authority. The dynamic trusted-clone object fetch and bootstrap/restart recovery described above are not available from that base. The base-owned wrapper above can report qualification and the exact review request, but automated CODE/SECURITY/UAC publication remains `BLOCKED_AUTHORITY` until an independently approved runner with the complete flow is installed or the flow reaches a later trusted base. Do not work around this by executing PR-head Makefile targets or Python with owner credentials.

The worker reads one JSON object from stdin and writes one bounded JSON object to stdout. The request uses `schema_version=1` and `operation=submit|status|fetch_result`. `submit` receives the validated canonical review request and its `idempotency_key`; `status` and `fetch_result` receive the returned `submission_id`. Replies use these exact fields:

| Operation | Reply fields |
| --- | --- |
| `submit` | `submission_id` |
| `status` | `submission_id`, `state` (`QUEUED`, `RUNNING`, `COMPLETED`, or `FAILED`) |
| `fetch_result` | `submission_id`, `identity`, `provider`, `repository`, `kind`, `pr`, `head_sha`, `status`, `blocking_findings`, `output` |

`identity` is the original dispatch identity; `provider` is `ChatGPT`; `kind` is `code` or `security`. PASS requires zero blocking findings, FAIL requires a positive count, and `output` is a nonempty UTF-8 review summary of at most 8 KiB. The adapter also caps the whole worker reply and each invocation at 30 seconds.
 The worker must enforce that key across its own crash boundary, since a crash between external submit and local persistence can otherwise duplicate a review. The adapter does not expose worker stderr, raw review output, or credential values in its outbox and logs. The worker must expose blocking findings to maintainers through its own access-controlled result channel keyed by submission ID; the GitHub marker records only the exact verdict and blocking count. Network errors, timeouts, malformed or oversized results, and ambiguous identities block without generating a marker.

Each campaign binds repository, PR, base, base SHA, head branch, head SHA, review kind, and handoff SHA-256. The content-addressed `dispatch_identity` is stable for an identical request and changes with a new handoff digest. The controller's handoff is capped at 8 KiB and carries changed files, finding paths and delta, prior validated verdict, qualification digest, and exact head; polling does not request another full review. After a restart, the outbox resumes `status(submission_id)`; completed results are fetched and validated against the campaign. A changed HEAD supersedes qualification, CODE, SECURITY, and UAC for the old SHA. Before marker or UAC publication and before any trusted rerun, GitHub must still show the same open, non-draft PR and exact binding. An already valid owner marker or UAC is reused without reposting. UAC publication is off by default and requires an explicit `PR:FULL_HEAD_SHA` authorization binding supplied to the invocation; this limits consent to one campaign and preserves the owner's boundary.

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
