# Verified delivery chain

`architecture.lock.yaml` registers the machine contracts. Each contract owns one
decision surface; a downstream record may consume upstream proof but cannot issue
the verdict of the gate that controls it.

```text
MILESTONE
  v
MILESTONE TRACKER ISSUE
  v
CONTRACT
  v
WORK PACKAGE
  v
WORK-ITEM ISSUE
  v
CODEX DEV
  v
PR
  v
PREFLIGHT
  v
QUALIFICATION
  v
EXACT-SHA EVIDENCE BUNDLE
  v
CHATGPT CODE
  v
CHATGPT SECURITY
  v
RISK CLASSIFICATION
  v
OWNER AUTHORIZATION, if required
  v
MERGE REQUIREMENTS
  v
finish-pr
  v
POST-MERGE VERIFY
  v
WORK-ITEM ISSUE CLOSE
  v
MILESTONE TRACKER RE-EVALUATION
  v
ROADMAP SYNC
  v
MILESTONE STATUS DERIVED
```

## Authorities

| Decision | Machine authority |
| --- | --- |
| Milestone contract, tracker relation and derived status | `config/contracts/roadmap-policy.yaml` |
| Bounded objective, paths, dependencies and acceptance | `config/contracts/work-package-policy.yaml` |
| Tracker, work-item, defect and follow-up lifecycle | `config/contracts/issue-lifecycle-policy.yaml` |
| Capabilities, preflight, runtime execution and qualification | `config/contracts/qualification-execution-policy.yaml` |
| Recovery, integrity and provenance properties | `config/contracts/execution-properties-policy.yaml` |
| Exact-SHA qualification and bundle format | `config/contracts/ci-evidence.yaml` |
| CODE, SECURITY, risk, owner boundary, merge and post-merge | `config/contracts/review-policy.yaml` |
| External review dispatch transport | `config/contracts/chatgpt-review-dispatch-policy.yaml` |

The architecture lock is the root registry; this page is explanatory and grants no
execution or review authority.

## Scope before development

A merge-authoritative work item needs a valid work package bound to its milestone,
canonical tracker and work-item issue. It states a bounded objective, allowed and
forbidden paths, dependencies, applicable contracts, tests, gate and runtime proofs,
and exit criteria. A PR links to its principal work-item issue. A label or a closed
issue records workflow state, never technical proof. The M2.5 tracker is issue #32.

The work package selects required capabilities. Preflight verifies the exact source,
base, branch, clean worktree, host capacity, runtime backend, toolchain, identities,
network and permissions relevant to those capabilities before expensive work or
machine mutation. Missing capacity is `BLOCKED_RUNTIME`; an executed gate that
fails is `FAIL`. Neither can be converted to `PASS`.

## Proof at one exact HEAD

Qualification must be bound to the exact base SHA, head SHA, tree SHA, qualification
identity and toolchain digest. The bundle inventory lives at
`.context/evidence/<head_sha>/manifest.json`. Its `manifest.sha256` sidecar
identifies the canonical JSON bytes. Each referenced artifact, runtime record, gate
record and review record has a SHA-256 digest. Replacing a proof byte or using another
HEAD or tree invalidates the bundle. Superseded manifests remain in
`.context/evidence/<head_sha>/history/`. The files under `.context` remain
untracked evidence, not Git architecture authority.

A bundle proves integrity and linkage; it does not create qualification, runtime,
CODE, SECURITY or owner PASS. A static gate does not prove runtime. A disposable
RKE2 lab result does not prove the persistent M2.5 management plane is deployed.

## Review, risk and merge

ChatGPT issues CODE and SECURITY verdicts independently for the published exact
HEAD. The external dispatcher only requests and transports reviews. CODE PASS does
not imply SECURITY PASS. A blocking finding returns to development in the PR. A fix
creates a new HEAD and supersedes qualification, both reviews and owner authorization
for the prior HEAD. A follow-up issue is permitted only for explicitly nonblocking,
out-of-scope work with a recorded governance decision and PR relation.

Risk is derived from the exact changed paths, changed content and the repository
policy. The ordered classes are `LOW_RISK`, `SENSITIVE`, `PRIVILEGED`, and
`PRODUCTION`. The class determines owner authorization, review depth, and the
runtime and recovery requirements before mutation. Unknown or partial analysis
fails closed. Owner authorization, when required, binds the PR scope and exact HEAD;
the controller cannot issue it.

Before `finish-pr`, the PR must still be open and ready, base and HEAD current,
qualification and required runtime/recovery proofs valid, CODE and SECURITY PASS
for that HEAD, no unresolved blocking finding or thread, risk classified, required
owner authorization present, and merge requirements satisfied. An unresolved thread marked outdated by GitHub stops blocking only after a new
exact-head CODE and SECURITY PASS. Unresolved current threads remain blocking.

## After merge

GitHub's `MERGED` state alone does not complete a work item. Post-merge verification
checks the merge commit and signature, main ancestry, intended merged tree, absence
of unexpected mutation, required branch cleanup, clean worktree and roadmap sync.
It writes an exact merge-SHA record under `.context/evidence/post-merge/`.
The work-item issue closes only after that verification, the historical qualified
HEAD's declared gates, tests, contracts and QCE capabilities pass, and the exact
bundle witness still matches. Closure is idempotent and read back from GitHub. The
tracker and roadmap are then re-evaluated; status is derived from the required proof
graph. A closed tracker, lab readiness or static qualification cannot produce
`DEPLOYED` or `PROVEN`.

For risky mutations, capture the prior state, mutate, verify the result, restore on
failure or when required, and verify the restored state. Capture, restore and restore
verification are separate evidence fields. A cleanup command exiting zero is not
restore proof.

## Commands and current runtime authority

Use the canonical checkout, a feature branch and a work package under
config/work-packages/<milestone>/<id>.yaml. make deliver TITLE="..."
qualifies and publishes the exact signed commit, then creates or updates its
GitHub PR with the structured primary work-item marker. repoctl pr-loop
derives the next transition from fresh GitHub and exact-head evidence. The
work-package, preflight, evidence-bundle, milestone-plan and
post-merge-verify commands expose focused, machine-readable checks.

The runtime proof registry currently recognizes only the M2.5 disposable RKE2
lab record validated by its producer. A JSON PASS for another milestone,
persistent deployment, or recovery cannot authorize a merge. Recovery-required
work remains blocked until capture, restore and restored-state validation have
a registered producer. Runtime evidence is kept outside Git and is linked to
the exact source and bundle by digest.


### Roadmap proof consumption and follow-up

Roadmap post-merge references are accepted only through the canonical signed-proof
reader with a fresh GitHub PR snapshot, the authorized detached signer, retained
qualification and bundle, exact Git identities and current main ancestry. Stored
PASS fields provide no authority. Persistent deployment remains incomplete until a
registered producer can verify its runtime identity and persistent state. The M2.5
lab producer continues to report `NOT_DEPLOYED`.

The post-merge verifier checks policy-owned roadmap document rendering with
`roadmap_sync.py check --document-only`, avoiding recursive proof derivation. This
mode neither writes a projection nor establishes milestone status; the full roadmap
check still evaluates the proof graph separately.

A document drift may create one deterministic `automation/roadmap-sync/<main-sha>`
branch. Its only generated change is `docs/project/MASTER_EXECUTION_PLAN.md`, covered
by the M7 delivery-chain package and work-item #170. The canonical selector must
resolve exactly one package before branch creation and again for the generated
diff. Read-only preflight runs before generation, and normal `deliver` preflight
checks the final committed source before qualification and publication. Publication
returns `ROADMAP_FOLLOWUP_PENDING` (exit 3); completion waits for its reviewed merge.
Interrupted delivery retains its named branch for idempotent resumption, restores
main when the worktree is safe, and never creates a second follow-up for the same
main. Unexpected changes are preserved and block recovery rather than discarded.


When follow-up publication is reached from a trusted merge transition, a separate
producer restarts from the newly signed current main. It loads the verifier from
that immutable Git commit, checks the complete checkout against Git blobs and
rechecks the local and remote main binding before importing publication code.
Only the child drops the original merge context; the original transition keeps
its base authority, and the publication child cannot issue a merge verdict. A
previous open roadmap follow-up also prevents duplicate publication if main moves.


### Recovery and external review handoff

The trusted controller retains a detached-signed pre-merge witness before calling
the forge merge operation. It binds the PR, base, head, tree, qualification identity,
qualification bytes and evidence-bundle digest. A missing post-merge record can be
rebuilt only from this authenticated witness and fresh GitHub/Git facts. Existing
invalid or partial records are never silently overwritten. Parsed JSON, signatures
and digests consume the same bounded regular-file snapshot.

Historical proof readers can run from a clean feature checkout without executing
that checkout's roadmap implementation. The initial post-merge writer still
requires current main and the canonical document check. A successful merge and
proof return `VERIFIED` / `CLOSE_WORK_ITEM`; only independently verified issue closure
and roadmap re-evaluation can reach `DONE`.

When external ChatGPT transport is absent, qualification remains `PASS` and the
CLI preserves `CHATGPT_REVIEW_REQUIRED` with `CHATGPT_CODE_REVIEW`, then
`CHATGPT_SECURITY_REVIEW` after authenticated CODE evidence. The non-authoritative
outbox reports unavailable transport separately. No local ChatGPT client or synthetic
review verdict is required; the exact-base controller remains the only verifier.
