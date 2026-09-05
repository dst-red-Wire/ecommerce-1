#!/bin/sh
set -eu
# shellcheck source=./scripts/lib.sh
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

mode=${1:-}
case "$mode" in
  --check)
    require python3
    python3 scripts/toolchain-doctor.py --scope full --format text --strict
    ;;
  --apply)
    [ "$(id -u)" -ne 0 ] || fail "bootstrap must run as the regular WSL user, not root"
    require python3
    require pipx
    python3 - <<'PY' | while IFS='|' read -r package command; do
import json
from pathlib import Path

lock = json.loads(Path("config/toolchain/toolchain.lock.json").read_text())
for tool in lock["tools"]:
    if tool["installer"] == "pipx":
        print(f"{tool['package']}|{tool['command']}")
PY
      if command -v "$command" >/dev/null 2>&1; then
        info "$command already present; enforcing pinned pipx package $package"
      else
        info "installing pinned pipx package $package"
      fi
      pipx install --force "$package"
    done
    python3 - <<'PY' | while IFS='|' read -r venv package; do
import json
from pathlib import Path

lock = json.loads(Path("config/toolchain/toolchain.lock.json").read_text())
for injection in lock["pipx_injections"]:
    print(f"{injection['venv']}|{injection['package']}")
PY
      info "injecting pinned $package into the $venv pipx environment"
      pipx inject --force "$venv" "$package"
    done
    python3 scripts/toolchain-doctor.py --scope full --format text --strict
    ;;
  *)
    fail "usage: $0 --check|--apply"
    ;;
esac
