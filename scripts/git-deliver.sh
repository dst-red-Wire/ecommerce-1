#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

fail(){ printf 'FAIL deliver: %s\n' "$*" >&2; exit 2; }

branch="$(git branch --show-current)"
[[ -n "$branch" ]] || fail 'detached HEAD'
[[ "$branch" != main && "$branch" != master ]] || fail 'refusing to deliver directly from the default branch'

base="${BASE:-main}"
title="${TITLE:-}"
msg="${MSG:-$title}"

if command -v gh >/dev/null 2>&1; then
  GH=(gh)
elif command -v gh.exe >/dev/null 2>&1; then
  GH=(gh.exe)
else
  fail 'GitHub CLI not found. Run make workstation-bootstrap, then retry make deliver.'
fi

"${GH[@]}" auth status >/dev/null 2>&1 || fail 'GitHub CLI is not authenticated. Run gh auth login once, then retry.'

git fetch origin --prune
if ! git show-ref --verify --quiet "refs/remotes/origin/$base"; then
  fail "origin/$base does not exist"
fi

# Fail closed if the branch was started from an outdated base and cannot be reviewed cleanly.
if ! git merge-base --is-ancestor "origin/$base" HEAD; then
  fail "branch is not based on current origin/$base; synchronize it before delivery"
fi

if [[ -n "$(git status --porcelain)" && -z "$msg" ]]; then
  fail 'uncommitted changes detected; provide TITLE="type(scope): summary" or MSG="..."'
fi

# Reuse the repository-owned publication gate; it validates, commits when needed, and pushes without force.
if [[ -n "$msg" ]]; then
  MSG="$msg" ./scripts/git-publish.sh
else
  ./scripts/git-publish.sh
fi

head_sha="$(git rev-parse HEAD)"

# A PR may already exist. Never create duplicates.
existing="$("${GH[@]}" pr list --head "$branch" --base "$base" --state open --json number,url --jq '.[0] | select(.) | "\(.number) \(.url)"' 2>/dev/null || true)"
if [[ -n "$existing" ]]; then
  printf 'PASS deliver: PR already exists: %s\n' "$existing"
  exit 0
fi

if [[ -z "$title" ]]; then
  title="$(git log -1 --pretty=%s)"
fi
[[ -n "$title" ]] || fail 'unable to derive PR title'

mkdir -p .context
body='.context/pr-body.md'
changed='.context/pr-changed-files.txt'
stat='.context/pr-diff-stat.txt'

git diff --name-only "origin/$base...HEAD" > "$changed"
git diff --stat "origin/$base...HEAD" > "$stat"
[[ -s "$changed" ]] || fail "no changes relative to origin/$base"

{
  printf '## Summary\n\n%s\n\n' "$title"
  printf '## Scope\n\n%s\n' "\`\`\`text"
  cat "$changed"
  printf '%s\n\n## Diff stat\n\n%s\n' "\`\`\`" "\`\`\`text"
  cat "$stat"
  printf '%s\n\n## Validation\n\n' "\`\`\`"
  printf -- '- workstation doctor: PASS\n'
  printf -- '- governance: PASS\n'
  printf -- '- lint: PASS\n'
  printf -- '- security: PASS\n'
  printf -- '- ansible: PASS/SKIP according to repository gate\n'
  printf -- '- terraform: PASS/SKIP according to repository gate\n\n'
  printf '## Review evidence\n\n'
  printf -- '- Base: %s%s%s\n' "\`" "$base" "\`"
  printf -- '- Head branch: %s%s%s\n' "\`" "$branch" "\`"
  printf -- '- Head SHA: %s%s%s\n' "\`" "$head_sha" "\`"
  printf -- '- Generated context remains under %s.context/%s and is not committed.\n\n' "\`" "\`"
  printf '## Safety\n\nThis automation creates the pull request only. It does not approve, merge, force-push, bypass branch protection, or mutate infrastructure.\n'
} > "$body"

url="$("${GH[@]}" pr create --base "$base" --head "$branch" --title "$title" --body-file "$body")"
printf 'PASS deliver: created PR %s\n' "$url"
