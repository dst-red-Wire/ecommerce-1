# Repository agent guide

## Scope

These rules apply to the whole repository.

## Authoritative architecture

Before changing code or structure, read:

1. `architecture.lock.yaml` — the single canonical architecture authority
2. `docs/architecture/EXACT_TOPOLOGY_V5.md` — a derived index subordinate to the lock
3. relevant ADRs and domain documentation

Validated architecture is not to be redesigned during implementation unless an explicit contradiction is found and routed back to architecture governance.

## Windows workspace rule

- On Windows, perform every repository operation from WSL2 with the entire checkout on its native Linux filesystem (for example `/home/dev/ecommerce-1`).
- Do not run repository Git, GPG, Ansible, build, test, or automation commands from a Windows-mounted path such as `/mnt/c`.
- The canonical machine rule is `architecture.lock.yaml#repository_governance.windows_workspace`.

## Repository rules

- Do not recreate, rename or move top-level architecture arbitrarily.
- Do not create a new domain when an existing owner can hold the responsibility.
- Keep shared libraries minimal; do not centralize domain logic.
- Every backend service owns its `go.mod`, migrations, tests and container build.
- REST and gRPC transports call the same application use cases.
- No service reads another service's database directly.
- `cart`, `checkout`, `order`, `payment` and `fulfillment` are separate autonomous domains; do not collapse their lifecycle or persistence ownership.

## Active platform choices

- CI: Tekton.
- GitOps CD: Rancher Fleet.
- Progressive delivery: Argo Rollouts.
- Registry: Harbor.
- Object storage target: SeaweedFS S3.
- Telemetry collection: OpenTelemetry Collector.
- Metrics: vmagent + VictoriaMetrics; Prometheus is protocol/format compatibility only, not the primary TSDB/server authority.
- Infrastructure logs: OpenTelemetry Collector -> VictoriaLogs.
- Application telemetry/logs: Rotel -> ClickHouse -> HyperDX.
- Security-only pipeline: Data Prepper + OpenSearch + Wazuh.
- HyperDX metadata store: `mongodb-oss-self-hosted`.

Do not introduce these superseded defaults into new implementation:

- Superseded: FluxCD
- Superseded: Flagger
- Superseded: MinIO Community Edition / MinIO Operator
- Superseded: Loki as the logging baseline
- Superseded: Fluent Bit as the general logging pipeline
- Superseded: Splunk as the SIEM baseline

Historical references may remain only when explicitly labelled superseded.

## Development

- Repeatable or stateful workstation and host changes belong to Ansible.
- Stateless repository orchestration belongs to `scripts/repoctl.py`.
- Specialized deterministic validation belongs to Python, Ruby, Go, or a native CLI.
- CI belongs to Tekton; GitHub/Gitea are forge and review transports, not CI authorities.
- Do not add repository Shell automation: no tracked `*.sh` files are permitted.
- A missing optional project area must be reported as `SKIP`, not treated as a failure.
- Never print secrets, credentials, kubeconfigs, Terraform state, private keys or local environment files.
- Never commit generated reports, caches, binaries, archives or scanner output unless the repository explicitly defines them as source artifacts.
- Never use mutable image tags such as `latest`; pin versions and use digests for promoted artifacts.
- Run `make ci` before submitting CI-related changes.

## Change discipline

Each implementation PR must state:

- owning domain;
- scope and files changed;
- relevant contract/ADR;
- tests added or changed;
- rollback path;
- expected evidence.

Prefer small reviewable PRs over monolithic changes.

## Build sequence

Do not implement the 19 services in parallel from empty scaffolding. Follow:

`M0 architecture sync -> M1 bootstrap -> (M2 golden product service and M2.5 persistent MGMT bootstrap); M2.5 -> M3 PREPROD infra -> M4 platform; M2 + M4 -> M5 vertical slice -> M6 remaining application -> M7 qualification -> M8 certification -> M9 PROD`.

The `product` service is the first golden backend implementation and must validate the shared engineering conventions before they are replicated.
## Token-efficient agent context

Do not dump the repository, full CI logs, or broad architecture documentation into an agent prompt by default.

Before implementation, use `make context TASK="<bounded task>"`. The generated `.context/codex-context.md` is the preferred handoff: it routes changes through repository contracts and enforces a bounded byte budget.

Use `make diff-context` for review-oriented work and `make failure-context GATE=<gate>` for deterministic failures. Give the agent the reduced artifact plus the exact failing file/test, not the raw full log.

Context escalation is automatic: L0 for local implementation, L1 for domain/contract work, and L2 for architecture/control-plane work. Do not manually escalate to broader context unless the reduced pack is insufficient or an exact contract requires it.


## CODE and SECURITY review authority

ChatGPT is the repository's sole AI authority for CODE and SECURITY review.

- Do not trigger, request, rerun, poll, or depend on Codex reviews for merge readiness. This includes `@codex review`, `@codex security review`, and equivalent automated Codex review workflows.
- Historical Codex findings may be used as input evidence, but they are not current review authority and must not cause a new Codex invocation.
- Every ChatGPT CODE review and SECURITY review must be bound to the PR's exact published head SHA. Record that full SHA in the review result.
- If the PR head SHA changes, the previous final review is not valid for the new head. Review the bounded delta, re-run relevant deterministic evidence, then issue final CODE and SECURITY conclusions for the new exact SHA.
- CODE review covers correctness, regressions, repository contracts, architecture adherence, tests, operational behavior, and failure handling.
- SECURITY review covers secrets, authentication and authorization, trust boundaries, input validation, network exposure, privilege, supply chain, artifact integrity, unsafe defaults, and destructive behavior.
- Findings must identify severity, path or owning component, concrete risk, and the exact SHA reviewed.
- A finding may be resolved only after the correction exists on a published SHA and supporting deterministic evidence is available.
- Merge readiness requires exact-SHA qualification plus completed ChatGPT CODE and SECURITY review for that same SHA, with no unresolved blocking finding.
- Deterministic gates and tests are evidence for the review; they do not replace ChatGPT CODE or SECURITY review.
- Final ChatGPT review results are recorded on the PR with `chatgpt-exact-sha-review:v1` machine markers for `code` and `security`; both must bind the current full head SHA and be PASS with zero blocking findings.
- `finish-pr` consumes only those ChatGPT markers. Codex comments, reactions, summaries, statuses, and completed reviews are ignored for merge readiness.
- Codex may be used only as a narrowly scoped execution fallback when a required task cannot be performed with ChatGPT's available capabilities. The reason must be explicit, the scope must be minimal, and Codex output is evidence returned to ChatGPT.
- Codex must never become CODE/SECURITY review authority, emit merge-readiness markers, decide merge readiness, or make merge decisions. ChatGPT performs the final exact-SHA CODE/SECURITY review. Deterministic repository policy authorizes automatic delivery only for `LOW_RISK`; the repository owner retains the explicit merge boundary for `SENSITIVE` changes.

## Automated delivery

Use `make deliver TITLE="..."` for routine feature-branch handoff. It may run local gates, commit, push without force, generate bounded diff context, and create or refresh a GitHub pull request. It must never merge, auto-approve, bypass branch protection, or act as release authority.

Canonical branch publication uses only `make deliver TITLE="..."` (optionally `MSG="..."`). Do not use direct `git push` for repository delivery or invoke `repoctl publish`/`publish-change` as user commands; `publish()` is an internal primitive of `repoctl deliver`. A manual `git push` may remain a diagnostic or recovery operation, but it is never canonical delivery evidence. Successful delivery requires exact-SHA qualification, a signed commit, matching local/remote/PR heads and an open PR. A push followed by PR failure is a partial delivery, not PASS; rerun `make deliver` to reconcile it. `bundle-deliver` remains a trusted isolated-delivery workflow, not a competing developer entrypoint.

After publication, external automation provisions a distinct clean checkout at the PR's exact GitHub `baseRefOid` and invokes `<exact-base-checkout>/scripts/repository_delivery.py trusted-pr-transition --target-root <exact-head-checkout> --pr <number>`. The wrapper validates repository identity, ancestry, cleanliness, and both exact SHAs, then runs the exact-base `repoctl.py`; neither the PR-head Makefile nor PR-head delivery code is authoritative. `make pr-loop PR=<number> TRUSTED_ROOT=<exact-base-checkout>` is only a local adapter and must not be the external trust boundary. Missing CODE or SECURITY emits `state=CHATGPT_REVIEW_REQUIRED`, an uppercase `review_kind`, the PR number, the exact head SHA, and the actual bounded payload returned by `scripts/pr_monitor.py#chatgpt_review_handoff` for the automatic external ChatGPT consumer. The event includes payload byte size and SHA-256 digest and fails closed rather than emitting a minimal handoff when canonical payload construction is unavailable. SECURITY may be emitted only after an exact-SHA CODE PASS marker exists. The consumer uses the emitted exact-base `rerun.argv` after each valid marker. After both reviews pass, repository-owned deterministic policy classifies the exact PR base/head and changed capabilities; ChatGPT and Codex never decide merge risk. The executable classifier is materialized from the exact PR base commit and run in isolated Python mode; the PR-head copy is never classification authority, and a missing base controller during bootstrap is `SENSITIVE` and requires the explicit repository-owner boundary. `LOW_RISK` means qualification plus CODE plus SECURITY can proceed automatically through `MERGE_READY` to `finish-pr`. `SENSITIVE` means the same gates lead to `OWNER_AUTH_REQUIRED`, followed by exact-SHA owner authorization and then `finish-pr`. `NOT_REQUIRED_BY_POLICY` is a normative absence of the owner gate and is never `AUTO_AUTHORIZED` or a synthetic approval. Unknown, ambiguous, partial, unclassified, or failed analysis is never low risk. Any head change invalidates the classification and all exact-SHA evidence and restarts at qualification. The controller never fabricates CODE, SECURITY, or owner authority. Pass `--dry-run --json` to the trusted wrapper to inspect state and valid evidence without qualification, comments, merge, or deletion; direct PR-head `pr-loop` and `finish-pr` calls fail closed.

The normative delivery paths are:

```text
LOW_RISK: qualification PASS -> ChatGPT CODE PASS -> ChatGPT SECURITY PASS
          -> owner authorization NOT_REQUIRED_BY_POLICY -> automatic finish-pr

SENSITIVE: qualification PASS -> ChatGPT CODE PASS -> ChatGPT SECURITY PASS
           -> OWNER_AUTH_REQUIRED -> explicit owner authorization -> finish-pr
```

Expected operator output for a low-risk change:

```text
PR #162
HEAD abc...

qualification   PASS
CODE            PASS
SECURITY        PASS
RISK            LOW_RISK
OWNER AUTH      NOT_REQUIRED_BY_POLICY
MODE            AUTO

STATE MERGE_READY
```

Expected operator output for a sensitive change:

```text
PR #163
HEAD def...

qualification   PASS
CODE            PASS
SECURITY        PASS
RISK            SENSITIVE
OWNER AUTH      MISSING
MODE            OWNER_GATED

STATE OWNER_AUTH_REQUIRED
/owner-authorization approve scope=pr-163 sha=def...
```

PR comment authority is ordered only by immutable GitHub `created_at` plus comment ID; `updated_at` is non-authoritative. An owner authorization or revocation counts only when the trimmed comment body is exactly the command, never when embedded in prose, examples, or code fences. A non-zero `finish-pr` exit is not itself a merge verdict: `pr-loop` must re-read GitHub and accept a merge only when the current PR is merged at the initial exact head; if GitHub is unavailable the merge result remains unknown and the loop fails closed.

## Automatic stale-branch cleanup

Use `make branch-cleanup` for repository branch hygiene. `make git-sync` invokes the same cleanup automatically after fetch/prune and fast-forward, and `finish-pr` performs a final sweep after a successful merge.

A local or `origin` branch may be deleted only when the central `repository_delivery.cleanup` policy proves one of these conditions:

- the branch HEAD is already an ancestor of `origin/main`; or
- a GitHub PR into `main` is merged and its recorded head SHA exactly equals the branch's current HEAD; or
- its GitHub PR was closed without merge, but an exact machine-readable absorption proof binds that source PR and source HEAD to one authoritative absorbing PR HEAD, and GitHub plus Git prove that the absorbing PR was subsequently merged into the current `origin/main` lineage.

`CLOSED != ABSORBED`, `MERGED != ABSORPTION_PROOF`, and `SIMILAR_DIFF != ABSORPTION_PROOF`: closed alone is never sufficient. The absorption proof must use the central `pull-request-absorption-proof:v2` schema in the absorbing PR body, bind both repositories and exact 40-character SHA values, and have one active destination. Its bounded content lineage must start at the exact source HEAD, end at the exact absorbing HEAD, and every edge must be independently verified by Git as either commit ancestry or complete tree identity. Contradictory active proofs are ambiguous and fail closed; supersession must explicitly identify the deterministic proof ID and is never inferred from recency.

For absorption-based cleanup, refresh Git refs and GitHub PR evidence immediately before each destructive local or remote ref deletion. The fresh source state, absorbing state, active proof, merge lineage, content lineage, and deterministic proof ID must exactly match the planned authorization; otherwise preserve the ref.

Never delete the default branch, `master`, the current branch, or any branch checked out by an active worktree. If a branch has advanced after its merged PR or its absorption proof, preserve it. Missing or malformed GitHub CLI/API evidence disables the GitHub-dependent criteria; ancestry-based cleanup may still proceed independently. Use `make branch-cleanup DRY_RUN=1` to inspect the exact deletion plan and proof chain without mutating refs.
<!-- BEGIN ANSIBLE-FIRST-DEVELOPER-AUTOMATION -->
## Ansible-first developer automation

Use Ansible as the default owner of repeatable or stateful developer/workstation automation: package installation, toolchain reconciliation, Docker readiness, Git-local reconciliation, host/OS configuration, and repeatable bootstrap/generation workflows.

Do not add repository Shell automation. No tracked `*.sh` file is allowed. Prefer direct Make/Tekton invocation of Ansible, Python, Ruby, Go, PNPM, Terraform, scanners, or other native tools. Stateful/repeatable workflows belong to Ansible; stateless fast checks belong to native tools or `scripts/repoctl.py`.

When touching an existing Shell helper, migrate its stateful workflow to Ansible or its stateless algorithm to the repository controller in the same tranche. Tekton remains the sole CI authority; Ansible is an execution/reconciliation mechanism, not CI/CD.

Optimize for fewer files and lower process overhead: consolidate stateless repository orchestration in `scripts/repoctl.py` and keep specialized Ruby/Python/Go validators/generators only where they add distinct deterministic logic.

Parallelize only independent work. Use Ansible forks for multi-host fan-out, `strategy: free` where host ordering is irrelevant, `serial` for rolling/sensitive changes, `throttle` for heavy tasks, and `async` + `poll: 0` for independent localhost work. Keep dependency chains sequential: toolchain before tests, OpenAPI generation before drift/compatibility checks, sqlc/migrations before DB tests, and generation before consumers.
<!-- END ANSIBLE-FIRST-DEVELOPER-AUTOMATION -->
