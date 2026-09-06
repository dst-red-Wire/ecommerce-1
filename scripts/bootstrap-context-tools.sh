#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/config/toolchain/versions.env"
mkdir -p "$HOME/.local/bin"
export PATH="$HOME/.local/bin:$PATH"

fetch_verified(){
  local url="$1" sha="$2" out="$3" tmp
  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' RETURN
  if ! curl -fL --retry 3 --retry-delay 2 -o "$tmp" "$url"; then
    command -v curl.exe >/dev/null 2>&1 || { echo "FAIL download: $url" >&2; return 1; }
    curl.exe -fL --retry 3 --retry-delay 2 -o "$(wslpath -w "$tmp")" "$url" >/dev/null
  fi
  printf '%s  %s\n' "$sha" "$tmp" | sha256sum -c - >/dev/null || { echo "FAIL checksum: $url" >&2; return 1; }
  install -m 0755 "$tmp" "$out"
}

install_tar_binary(){
  local name="$1" url="$2" sha="$3" member="$4" target="$5" archive dir
  archive="$(mktemp)"; dir="$(mktemp -d)"
  trap 'rm -f "$archive"; rm -rf "$dir"' RETURN
  if ! curl -fL --retry 3 --retry-delay 2 -o "$archive" "$url"; then
    command -v curl.exe >/dev/null 2>&1 || return 1
    curl.exe -fL --retry 3 --retry-delay 2 -o "$(wslpath -w "$archive")" "$url" >/dev/null
  fi
  printf '%s  %s\n' "$sha" "$archive" | sha256sum -c - >/dev/null || { echo "FAIL checksum: $name" >&2; return 1; }
  tar -xzf "$archive" -C "$dir"
  install -m 0755 "$dir/$member" "$target"
}

install_zip_binary(){
  local name="$1" url="$2" sha="$3" member="$4" target="$5" archive dir
  archive="$(mktemp)"; dir="$(mktemp -d)"
  trap 'rm -f "$archive"; rm -rf "$dir"' RETURN
  if ! curl -fL --retry 3 --retry-delay 2 -o "$archive" "$url"; then
    command -v curl.exe >/dev/null 2>&1 || return 1
    curl.exe -fL --retry 3 --retry-delay 2 -o "$(wslpath -w "$archive")" "$url" >/dev/null
  fi
  printf '%s  %s\n' "$sha" "$archive" | sha256sum -c - >/dev/null || { echo "FAIL checksum: $name" >&2; return 1; }
  python3 - "$archive" "$dir" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as z: z.extractall(sys.argv[2])
PY
  install -m 0755 "$dir/$member" "$target"
}

if ! command -v rg >/dev/null 2>&1 || [[ "$(rg --version | head -n1)" != "ripgrep ${RIPGREP_VERSION}" ]]; then
  install_tar_binary ripgrep "https://github.com/BurntSushi/ripgrep/releases/download/${RIPGREP_VERSION}/ripgrep-${RIPGREP_VERSION}-x86_64-unknown-linux-musl.tar.gz" "$RIPGREP_SHA256_LINUX_AMD64" "ripgrep-${RIPGREP_VERSION}-x86_64-unknown-linux-musl/rg" "$HOME/.local/bin/rg"
fi
if ! command -v fd >/dev/null 2>&1 || [[ "$(fd --version)" != "fd ${FD_VERSION}" ]]; then
  install_tar_binary fd "https://github.com/sharkdp/fd/releases/download/v${FD_VERSION}/fd-v${FD_VERSION}-x86_64-unknown-linux-musl.tar.gz" "$FD_SHA256_LINUX_AMD64" "fd-v${FD_VERSION}-x86_64-unknown-linux-musl/fd" "$HOME/.local/bin/fd"
fi
if ! command -v yq >/dev/null 2>&1 || [[ "$(yq --version)" != *"v${YQ_VERSION}"* ]]; then
  fetch_verified "https://github.com/mikefarah/yq/releases/download/v${YQ_VERSION}/yq_linux_amd64" "$YQ_SHA256_LINUX_AMD64" "$HOME/.local/bin/yq"
fi
if ! command -v ast-grep >/dev/null 2>&1 || [[ "$(ast-grep --version)" != *"${AST_GREP_VERSION}"* ]]; then
  install_zip_binary ast-grep "https://github.com/ast-grep/ast-grep/releases/download/${AST_GREP_VERSION}/app-x86_64-unknown-linux-gnu.zip" "$AST_GREP_SHA256_LINUX_AMD64" ast-grep "$HOME/.local/bin/ast-grep"
fi

for cmd in rg fd yq ast-grep; do command -v "$cmd" >/dev/null 2>&1 || { echo "FAIL context tool missing: $cmd" >&2; exit 4; }; done
python3 -m unittest discover -s tests/context -p 'test_*.py'
echo 'PASS context reduction toolchain installed and validated.'
