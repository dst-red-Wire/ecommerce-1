#!/usr/bin/env sh
set -eu
ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT"
TASK=${TASK:-${*:-}}
[ -n "$TASK" ] || { echo 'FAIL: provide TASK="..." or pass a task string' >&2; exit 2; }
exec python3 "$ROOT/scripts/context-pack.py" --task "$TASK" --base "${BASE:-origin/main}"
