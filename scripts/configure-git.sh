#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"
CONF="$ROOT/config/workstation/git-local.conf"
[[ -f "$CONF" ]] || { echo "FAIL git config: missing $CONF"; exit 2; }
while IFS='=' read -r key value; do
  [[ -z "$key" || "$key" == \#* ]] && continue
  git config --local "$key" "$value"
done < "$CONF"
for key in user.name user.email; do
  git config --get "$key" >/dev/null 2>&1 || { echo "FAIL git identity: $key is not configured; automation will not invent identity."; exit 3; }
done
git remote get-url origin >/dev/null 2>&1 || { echo 'FAIL git remote: origin is missing'; exit 4; }
echo 'PASS git repository defaults configured.'
