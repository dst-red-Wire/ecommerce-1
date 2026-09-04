#!/bin/sh
set -eu

# shellcheck disable=SC1091
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT HUP INT TERM
source_tree="$fixture/source"
snapshot="$fixture/source-snapshot/source.tar"
build_context="$fixture/build-context"
mkdir -p "$source_tree" "$(dirname "$snapshot")" "$build_context"
git -C "$source_tree" init -q
git -C "$source_tree" config user.name fixture
git -C "$source_tree" config user.email fixture@example.invalid
printf '%s\n' original >"$source_tree/Dockerfile"
printf '%s\n' original >"$source_tree/application.txt"
git -C "$source_tree" add .
git -C "$source_tree" commit -qm initial
git -C "$source_tree" archive --format=tar HEAD >"$snapshot"
before=$(sha256sum "$snapshot" | awk '{print $1}')
chmod 0444 "$snapshot"

# Simulate repository code attempting to poison and then restore its checkout.
printf '%s\n' malicious >"$source_tree/Dockerfile"
printf '%s\n' malicious >"$source_tree/application.txt"
git -C "$source_tree" checkout -- Dockerfile application.txt

after=$(sha256sum "$snapshot" | awk '{print $1}')
[ "$before" = "$after" ] || fail "test code changed the isolated source snapshot"
tar -xf "$snapshot" -C "$build_context"
[ "$(cat "$build_context/Dockerfile")" = original ] || fail "BuildKit context was poisoned"
[ "$(cat "$build_context/application.txt")" = original ] || fail "BuildKit application source was poisoned"

python3 scripts/validate-tekton-contracts.py --self-test >/dev/null
info "source mutation cannot affect the separately archived BuildKit context"
