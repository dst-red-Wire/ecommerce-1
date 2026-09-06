#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"
[[ -r /etc/os-release ]] || { echo 'FAIL OS: /etc/os-release missing'; exit 2; }
# shellcheck disable=SC1091
. /etc/os-release
[[ "${ID:-}" == ubuntu ]] || { echo "FAIL OS: expected Ubuntu WSL2, got ${ID:-unknown}"; exit 2; }
grep -qi microsoft /proc/version || { echo 'FAIL WSL2: Microsoft kernel not detected'; exit 2; }
# shellcheck disable=SC1091
. "$ROOT/config/toolchain/versions.env"

sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl git jq make pipx python3-venv shellcheck
export PATH="$HOME/.local/bin:$PATH"
pipx ensurepath >/dev/null 2>&1 || true
pipx_install(){
  local spec="$1" name="$2"
  # pipx 1.4.x does not provide a stable --short listing interface. Probe the
  # managed venv directly so reruns reconcile instead of trying to reinstall.
  if pipx runpip "$name" pip --version >/dev/null 2>&1; then
    pipx runpip "$name" install --disable-pip-version-check --upgrade "$spec"
  else
    pipx install --pip-args='--disable-pip-version-check' "$spec"
  fi
}
pipx_install "pre-commit==${PRE_COMMIT_VERSION}" pre-commit
pipx_install "molecule==${MOLECULE_VERSION}" molecule
pipx inject --force molecule "molecule-plugins[docker]==${MOLECULE_DOCKER_VERSION}" "pytest-testinfra==${TESTINFRA_VERSION}"
pipx_install "ansible-runner==${ANSIBLE_RUNNER_VERSION}" ansible-runner
pipx_install "ansible-builder==${ANSIBLE_BUILDER_VERSION}" ansible-builder
pipx_install "ansible-navigator==${ANSIBLE_NAVIGATOR_VERSION}" ansible-navigator
pipx_install "ggshield==${GGSHIELD_VERSION}" ggshield
pipx_install "checkov==${CHECKOV_VERSION}" checkov
pipx_install "semgrep==${SEMGREP_VERSION}" semgrep
pipx_install "cve-bin-tool==${CVE_BIN_TOOL_VERSION}" cve-bin-tool

install_cosign(){
  local expected_version="v${COSIGN_VERSION}"
  local expected_sha="${COSIGN_SHA256_LINUX_AMD64}"
  local target="$HOME/.local/bin/cosign"
  local url="https://github.com/sigstore/cosign/releases/download/${expected_version}/cosign-linux-amd64"
  local tmp
  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' RETURN

  if [[ -x "$target" ]] && printf '%s  %s\n' "$expected_sha" "$target" | sha256sum -c - >/dev/null 2>&1; then
    echo "PASS cosign ${COSIGN_VERSION} verified"
    return 0
  fi

  if ! curl -fL --retry 3 --retry-delay 2 -o "$tmp" "$url"; then
    if command -v curl.exe >/dev/null 2>&1; then
      curl.exe -fL --retry 3 --retry-delay 2 -o "$(wslpath -w "$tmp")" "$url" >/dev/null
    else
      echo 'FAIL cosign: download failed and Windows curl fallback unavailable' >&2
      return 1
    fi
  fi

  printf '%s  %s\n' "$expected_sha" "$tmp" | sha256sum -c - >/dev/null || {
    echo 'FAIL cosign: SHA256 verification failed' >&2
    return 1
  }
  install -m 0755 "$tmp" "$target"
  printf '%s  %s\n' "$expected_sha" "$target" | sha256sum -c - >/dev/null
  echo "PASS cosign ${COSIGN_VERSION} installed and verified"
}
install_cosign

"$ROOT/scripts/bootstrap-context-tools.sh"

"$ROOT/scripts/configure-git.sh"
pre-commit install --install-hooks
pre-commit install --hook-type pre-push

if command -v powershell.exe >/dev/null 2>&1; then
  WINROOT="$(wslpath -w "$ROOT")"
  powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "$(wslpath -w "$ROOT/scripts/test-windows-workstation-collection.ps1")" | tr -d '\r'
  powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "$(wslpath -w "$ROOT/scripts/test-windows-workstation-noninteractive.ps1")" | tr -d '\r'
  powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "$(wslpath -w "$ROOT/scripts/windows-workstation.ps1")" -RepoWindowsPath "$WINROOT" | tr -d '\r'
else
  echo 'FAIL Windows automation: powershell.exe unavailable from WSL'
  exit 5
fi

# Docker Desktop may need a few seconds after Windows-side start; do bounded polling, not manual retries.
for _ in $(seq 1 30); do docker info >/dev/null 2>&1 && break; sleep 2; done
docker info >/dev/null 2>&1 || { echo 'FAIL Docker: daemon not reachable after automated start'; exit 6; }

"$ROOT/scripts/doctor-workstation.sh"
make governance
make lint
make security
make ansible
make terraform
echo 'PASS workstation bootstrap completed.'
