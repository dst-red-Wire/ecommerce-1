#!/bin/sh
set -eu
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

tf_files=$(find . -type f -name '*.tf' -not -path '*/.terraform/*' -print 2>/dev/null || true)
if [ -z "$tf_files" ]; then
  info "no Terraform files found; validation skipped"
  exit 0
fi

if have tofu; then tool=tofu
elif have terraform; then tool=terraform
else fail "Terraform files exist but neither tofu nor terraform is installed"
fi

unformatted=$($tool fmt -check -recursive -diff 2>&1) || {
  printf '%s\n' "$unformatted" >&2
  fail "$tool formatting check failed"
}

printf '%s\n' "$tf_files" | sed 's,/[^/]*$,,' | sort -u | while IFS= read -r directory; do
  info "validating Terraform in $directory"
  (cd "$directory" && "$tool" init -backend=false -input=false >/dev/null && "$tool" validate)
done
