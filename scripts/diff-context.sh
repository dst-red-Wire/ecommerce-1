#!/usr/bin/env sh
set -eu
ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT"
BASE=${BASE:-origin/main}
OUT=${OUT:-.context/diff.md}
MAX_LINES=${DIFF_CONTEXT_MAX_LINES:-320}
mkdir -p .context
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT HUP INT TERM
{
  echo '# Focused diff context'
  echo "BASE: $BASE"
  echo "HEAD: $(git rev-parse HEAD)"
  echo
  echo '## Status'
  git status --short
  echo
  echo '## Diff stat'
  git diff --stat "$BASE...HEAD" || true
  echo
  echo '## Changed files'
  git diff --name-only "$BASE...HEAD" || true
  echo
  echo '## Diff'
  git diff --no-ext-diff --unified=3 "$BASE...HEAD" || true
} >"$TMP"
head -n "$MAX_LINES" "$TMP" >"$OUT"
if [ "$(wc -l <"$TMP")" -gt "$MAX_LINES" ]; then echo '[TRUNCATED]' >>"$OUT"; fi
cat "$OUT"
