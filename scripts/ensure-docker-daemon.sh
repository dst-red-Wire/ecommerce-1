#!/usr/bin/env bash
set -Eeuo pipefail

# Ensure the Docker daemon required by repository validation is reachable.
# On WSL2, automatically start Docker Desktop through its supported Windows CLI
# when available, with a bounded wait. No installation or configuration occurs.

DOCKER_CLI="${DOCKER_CLI:-docker}"
DOCKER_DESKTOP_CLI="${DOCKER_DESKTOP_CLI:-}"
DOCKER_WAIT_ATTEMPTS="${DOCKER_WAIT_ATTEMPTS:-30}"
DOCKER_WAIT_SECONDS="${DOCKER_WAIT_SECONDS:-2}"
DOCKER_DISABLE_POWERSHELL_FALLBACK="${DOCKER_DISABLE_POWERSHELL_FALLBACK:-0}"

fail() { printf 'FAIL docker-ready: %s\n' "$*" >&2; exit 1; }
pass() { printf 'PASS docker-ready: %s\n' "$*"; }

if "$DOCKER_CLI" info >/dev/null 2>&1; then
  pass 'daemon already reachable'
  exit 0
fi

started=0
if [ -z "$DOCKER_DESKTOP_CLI" ]; then
  if command -v docker.exe >/dev/null 2>&1; then
    DOCKER_DESKTOP_CLI="$(command -v docker.exe)"
  elif [ -x '/mnt/c/Program Files/Docker/Docker/resources/bin/docker.exe' ]; then
    DOCKER_DESKTOP_CLI='/mnt/c/Program Files/Docker/Docker/resources/bin/docker.exe'
  fi
fi

if [ -n "$DOCKER_DESKTOP_CLI" ]; then
  if "$DOCKER_DESKTOP_CLI" desktop start >/dev/null 2>&1; then
    started=1
  fi
fi

# Older Docker Desktop releases may not expose `docker desktop start`. Fall back
# to starting the official Desktop executable only; do not alter settings.
if [ "$started" -eq 0 ] && [ "$DOCKER_DISABLE_POWERSHELL_FALLBACK" != 1 ] && command -v powershell.exe >/dev/null 2>&1; then
  # PowerShell variables must expand in PowerShell, not in Bash.
  # shellcheck disable=SC2016
  if powershell.exe -NoLogo -NoProfile -NonInteractive -Command \
    '$p = Join-Path $Env:ProgramFiles "Docker\\Docker\\Docker Desktop.exe"; if (Test-Path $p) { Start-Process -FilePath $p; exit 0 } else { exit 1 }' \
    >/dev/null 2>&1; then
    started=1
  fi
fi

[ "$started" -eq 1 ] || fail 'daemon unreachable and Docker Desktop could not be started automatically'

case "$DOCKER_WAIT_ATTEMPTS" in (*[!0-9]*|'') fail 'DOCKER_WAIT_ATTEMPTS must be a positive integer';; esac
case "$DOCKER_WAIT_SECONDS" in (*[!0-9]*|'') fail 'DOCKER_WAIT_SECONDS must be a non-negative integer';; esac
[ "$DOCKER_WAIT_ATTEMPTS" -gt 0 ] || fail 'DOCKER_WAIT_ATTEMPTS must be greater than zero'

attempt=1
while [ "$attempt" -le "$DOCKER_WAIT_ATTEMPTS" ]; do
  if "$DOCKER_CLI" info >/dev/null 2>&1; then
    pass "daemon reachable after automatic start (attempt $attempt/$DOCKER_WAIT_ATTEMPTS)"
    exit 0
  fi
  if [ "$attempt" -lt "$DOCKER_WAIT_ATTEMPTS" ]; then
    sleep "$DOCKER_WAIT_SECONDS"
  fi
  attempt=$((attempt + 1))
done

fail "daemon still unreachable after $DOCKER_WAIT_ATTEMPTS attempts"
