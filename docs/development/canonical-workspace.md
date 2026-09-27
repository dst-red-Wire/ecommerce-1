# Canonical development workspace

The only authorized source checkout is `/home/dev/ecommerce-1` in WSL2. Open it with:

```bash
cd /home/dev/ecommerce-1
code .
make workspace-check
```

The policy lives in `architecture.lock.yaml#repository_governance.canonical_workspace`. Every `repoctl.py` command checks that policy before work begins. `python3 scripts/canonical_workspace.py` emits stable JSON evidence with the locked `canonical_root`, `git_head`, `git_branch`, and `worktree_count` fields. Remote evidence is credential-free and covers every configured fetch and push URL.

`local` is the default execution scope and requires the exact canonical path. The lock declares an explicit `repoctl` command allowlist for each scope. Tekton sets `ECOMMERCE_EXECUTION_SCOPE=ci` for its ephemeral checkouts; that scope permits the isolated path and local clone origin, but only the declared gate commands (and only the `check` frontend action). Trusted `bundle-deliver` execution uses the separate `isolated-delivery` scope, which permits only `deliver` and retains canonical remote validation before publication. Unknown commands and policy drift fail closed.

The only normal branch-publication entrypoint is `make deliver TITLE="..."` (optionally `MSG="..."`). It qualifies the exact commit, checks its signature, pushes without force only when needed, and creates or refreshes one GitHub PR whose base and head match the local and remote refs. `repoctl publish` and `publish-change` are not public commands. Direct `git push` may be used for manual diagnostics or recovery, but it does not prove canonical delivery. If the PR step fails after a push, delivery reports `PARTIAL_DELIVERY`; rerunning `make deliver` resumes without a duplicate commit or PR. The trusted `bundle-deliver` path remains the specialized `isolated-delivery` exception.

The governance publication gate inventories tracked and untracked deliverable source across the repository: Python at every lexical scope (including static f-string fragments), Go `exec.Command` arguments, YAML automation (including Tekton and Ansible command/argument vectors), Makefiles, and common script/IaC sources. Shell line continuations are normalized before command matching. Only mutation sites declared in `config/contracts/review-policy.yaml#repository_delivery.publication.mutation_sites` may publish; malformed executable YAML and additional mutations at an allowed Python site fail closed. Helm templates and intentionally invalid YAML test fixtures receive conservative source-text scanning because they cannot be parsed as ordinary YAML.

| Entrypoint | Mutation | Push | PR create/update | Public API | Status |
| --- | --- | --- | --- | --- | --- |
| `make deliver` | Qualified signed commit if dirty | Normal, only if needed | Required | Yes | Canonical |
| `repoctl deliver` | Orchestrates internal primitive | Normal, only if needed | Required | Controller CLI | Invoked by Make or trusted bundle |
| `publish()` | Qualified signed commit if dirty | Normal, only if needed | No | No | Internal to `deliver` |
| `make publish`, `make publish-change`, `repoctl publish`, `repoctl publish-change` | None | No | No | No | Removed/forbidden |
| Manual `git push` | Git ref only | Possible outside controller | No | Git only | Diagnostic/recovery; never canonical proof |
| `bundle-deliver` | Isolated trusted checkout | Via `repoctl deliver` | Required | Specialized | Approved `isolated-delivery` exception |
| Post-merge `branch-cleanup` | Deletes proved stale refs | Lease-protected deletion only | No | Maintenance | Not publication |

Use one physical checkout for ordinary PR work. Fetch and switch branches there; preserve a branch with unique commits until its work is recovered. Do not open the source through `\\wsl.localhost`, `/mnt/c`, or a secondary worktree. VM disks, build caches, ISOs, and qualification artifacts may live outside the checkout.

For a new branch, after preserving any current work:

```bash
git fetch --prune origin
git switch main
git pull --ff-only
git switch -c <branch> origin/main
```

After merging and verifying that the branch has no unique work:

```bash
git switch main
git pull --ff-only
git branch -d <branch>
git fetch --prune origin
```

An optional shell alias is `alias ecommerce='cd /home/dev/ecommerce-1'`; the policy does not depend on it.
