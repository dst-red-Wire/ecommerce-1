#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"
[[ -z "$(git status --porcelain)" ]] || { echo 'FAIL git sync: working tree is dirty'; exit 3; }
git fetch --prune --prune-tags origin
branch="$(git branch --show-current)"
[[ -n "$branch" ]] || { echo 'FAIL git sync: detached HEAD'; exit 4; }
if git rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' >/dev/null 2>&1; then
  git pull --ff-only
else
  echo "SKIP pull: branch $branch has no upstream yet."
fi
echo "PASS git sync: $branch"
