#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"
export PATH="$HOME/.local/bin:$PATH"
branch="$(git branch --show-current)"
[[ -n "$branch" ]] || { echo 'FAIL publish: detached HEAD'; exit 3; }
if [[ "$branch" == main || "$branch" == master ]]; then
  branch="automation/workstation-tooling"
  if git show-ref --verify --quiet "refs/heads/$branch"; then
    git switch "$branch"
  else
    git switch -c "$branch"
  fi
fi
./scripts/ensure-docker-daemon.sh
./scripts/ensure-go-toolchain.sh
make workstation-doctor
make governance
make contracts
make lint
make test
make security
make ansible
make terraform
git add -A
if git diff --cached --quiet; then
  echo 'SKIP commit: no repository changes.'
else
  git commit -m "${MSG:-chore(workstation): automate developer workstation}"
fi
git push -u origin HEAD
echo "PASS publish: pushed $(git branch --show-current) without force."
