#!/bin/sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib.sh"

cd "$(repo_root)"

INDEX=docs/dr/runbooks/index.md
[ -f "$INDEX" ] || dr_fail "runbook index not found: $INDEX"

required_sections='Symptoms / trigger
Preconditions
Safety guards
Diagnosis
Restore or failover procedure
Functional validation
Rollback / failback
Metrics to record
Expected evidence
Escalation when RTO is exceeded'

MISSING_FILE=${TMPDIR:-/tmp}/dr-runbook-missing.$$
trap 'rm -f "$MISSING_FILE"' EXIT HUP INT TERM

validate_runbook() {
  file=$1

  [ -f "$file" ] || dr_fail "runbook file not found: $file"
  : >"$MISSING_FILE"

  printf '%s\n' "$required_sections" | while IFS= read -r section; do
    if ! grep -F -q "$section" "$file"; then
      printf '%s\n' "$section"
    fi
  done >"$MISSING_FILE"

  if [ -s "$MISSING_FILE" ]; then
    dr_warn "missing required sections in $file:"
    while IFS= read -r section; do
      dr_warn "- $section"
    done <"$MISSING_FILE"
    dr_fail "runbook validation failed: $file"
  fi

  pass "runbook structure valid: $file"
}

found=0
while IFS='|' read -r _ runbook component tier status _; do
  runbook=$(printf '%s' "$runbook" | sed 's/^ *//;s/ *$//;s/`//g')
  status=$(printf '%s' "$status" | sed 's/^ *//;s/ *$//')

  case "$runbook" in
    *.md) ;;
    *) continue ;;
  esac

  found=1
  file="docs/dr/runbooks/$runbook"

  case "$status" in
    planned)
      if [ -f "$file" ]; then
        validate_runbook "$file"
      else
        skip "planned runbook not written yet: $file"
      fi
      ;;
    draft|tested|gap)
      validate_runbook "$file"
      ;;
    *)
      dr_fail "unsupported runbook status '$status' for $runbook"
      ;;
  esac
done <"$INDEX"

[ "$found" -eq 1 ] || dr_fail "no runbooks found in index: $INDEX"
pass "runbook index validation completed"
