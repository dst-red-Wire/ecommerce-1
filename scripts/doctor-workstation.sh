#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"
rc=0
pass(){ printf 'PASS %-24s %s\n' "$1" "$2"; }
fail(){ printf 'FAIL %-24s %s\n' "$1" "$2"; rc=1; }
skip(){ printf 'SKIP %-24s %s\n' "$1" "$2"; }
for cmd in git make python3 pipx pre-commit ansible ansible-lint molecule terraform tflint trivy checkov gitleaks ggshield semgrep syft cosign rg fd yq ast-grep kubeconform conftest opa kubectl helm kustomize docker; do
  if command -v "$cmd" >/dev/null 2>&1; then pass "$cmd" "$(command -v "$cmd")"; else fail "$cmd" missing; fi
done
if grep -qi microsoft /proc/version 2>/dev/null; then pass wsl2 'Microsoft kernel detected'; else fail wsl2 'not running inside WSL2'; fi
if command -v powershell.exe >/dev/null 2>&1; then pass powershell.exe available; else fail powershell.exe missing; fi
if command -v winget.exe >/dev/null 2>&1; then pass winget.exe "$(winget.exe --version 2>/dev/null | tr -d '\r')"; else fail winget.exe missing; fi
if docker info >/dev/null 2>&1; then pass docker-daemon reachable; else fail docker-daemon unreachable; fi
wslconfig_found=0
for candidate in /mnt/c/Users/*/.wslconfig; do
  if [[ -f "$candidate" ]]; then
    wslconfig_found=1
    break
  fi
done
if (( wslconfig_found )); then
  skip wslconfig 'present (Windows script owns exact reconciliation)'
else
  skip wslconfig 'checked by Windows reconciliation'
fi
exit "$rc"
