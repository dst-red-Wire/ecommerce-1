#!/usr/bin/env sh
set -u
ROOT=$(git rev-parse --show-toplevel) || exit 2
cd "$ROOT" || exit 2
GATE=${1:-${GATE:-}}
[ -n "$GATE" ] || { echo 'Usage: scripts/failure-context.sh <governance|lint|test|security|terraform|ansible|ci>' >&2; exit 2; }
case "$GATE" in governance|lint|test|security|terraform|ansible|ci) ;; *) echo "FAIL unsupported gate: $GATE" >&2; exit 2;; esac
mkdir -p .context
LOG=$(mktemp)
trap 'rm -f "$LOG"' EXIT HUP INT TERM
set +e
make "$GATE" >"$LOG" 2>&1
RC=$?
set -e
OUT=.context/failure-${GATE}.md
{
  echo '# Failure context'
  echo "GATE: $GATE"
  echo "STATUS: $([ "$RC" -eq 0 ] && echo PASS || echo FAIL)"
  echo "EXIT_CODE: $RC"
  echo "HEAD: $(git rev-parse HEAD)"
  echo
  echo '## Relevant output'
  if [ "$RC" -eq 0 ]; then
    tail -n 30 "$LOG"
  else
    # Keep only actionable diagnostics plus tight surrounding context. rg is intentional here.
    rg -n -C 2 --no-heading '(FAIL|FAILED|ERROR|Error|error:|fatal:|Traceback|Exception|SC[0-9]{4}|line [0-9]+|make: \*\*\*)' "$LOG" 2>/dev/null | head -n 220 || tail -n 120 "$LOG"
  fi
} >"$OUT"
cat "$OUT"
exit "$RC"
