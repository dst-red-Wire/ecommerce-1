#!/bin/sh
set -eu
# shellcheck disable=SC1091
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
require sha256sum

terraform_data_root=$(mktemp -d)
cleanup_terraform_data() {
  rm -rf "$terraform_data_root"
}
trap cleanup_terraform_data EXIT HUP INT TERM

unformatted=$($tool fmt -check -recursive -diff 2>&1) || {
  printf '%s\n' "$unformatted" >&2
  fail "$tool formatting check failed"
}

printf '%s\n' "$tf_files" | sed 's,/[^/]*$,,' | sort -u | while IFS= read -r directory; do
  info "validating Terraform in $directory"
  directory_id=$(printf '%s' "$directory" | sha256sum | awk '{print $1}')
  directory_data=$terraform_data_root/$directory_id
  mkdir -p "$directory_data"
  (
    cd "$directory"
    TF_DATA_DIR="$directory_data" "$tool" init -backend=false -input=false >/dev/null
    TF_DATA_DIR="$directory_data" "$tool" validate
  )
done
