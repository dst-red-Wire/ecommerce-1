# Canonical development workspace

The only authorized source checkout is `/home/dev/ecommerce-1` in WSL2. Open it with:

```bash
cd /home/dev/ecommerce-1
code .
make workspace-check
```

The policy lives in `architecture.lock.yaml#repository_governance.canonical_workspace`. Every `repoctl.py` command checks that policy before work begins. `python3 scripts/canonical_workspace.py` emits stable JSON evidence with the locked `canonical_root`, `git_head`, `git_branch`, and `worktree_count` fields. Remote evidence is credential-free and covers every configured fetch and push URL.

`local` is the default execution scope and requires the exact canonical path. The lock declares an explicit `repoctl` command allowlist for each scope. Tekton sets `ECOMMERCE_EXECUTION_SCOPE=ci` for its ephemeral checkouts; that scope permits the isolated path and local clone origin, but only the declared gate commands (and only the `check` frontend action). Trusted `bundle-deliver` execution uses the separate `isolated-delivery` scope, which permits only `deliver` and retains canonical remote validation before publication. Unknown commands and policy drift fail closed.

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
