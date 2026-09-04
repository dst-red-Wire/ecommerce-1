#!/bin/sh
set -eu

# Offline restore test only. This script never connects to PostgreSQL and never
# replaces data; a real restore remains an incident procedure with human gate.
# shellcheck disable=SC1091
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

require age
require jq
require pg_restore
require realpath
require sha256sum

usage() {
  fail "usage: $0 <terraform-state-postgresql-*.manifest.json>"
}

[ "$#" -eq 1 ] || usage
: "${AGE_IDENTITY_FILE:?AGE_IDENTITY_FILE is required}"

repository=$(pwd -P)
manifest=$(realpath "$1") || fail "backup manifest does not exist"
identity=$(realpath "$AGE_IDENTITY_FILE") || fail "age identity file does not exist"
for protected_file in "$manifest" "$identity"; do
  [ -f "$protected_file" ] || fail "restore-test input is not a regular file"
  [ ! -L "$protected_file" ] || fail "restore-test input must not be a symbolic link"
done
case "$manifest" in
  "$repository"/* | /mnt/c/Users/*/OneDrive/*)
    fail "PostgreSQL backup restore tests must consume archives outside the repository and OneDrive"
    ;;
esac

jq --exit-status '
  .version == 1 and
  .component == "terraform-state-mgmt" and
  .format == "postgresql-custom-dump-age" and
  .database == "terraform_backend" and
  .schemas == ["terraform_management", "terraform_lock_probe"] and
  (.encryptedBackup | type == "string" and test("^terraform-state-postgresql-[0-9]{8}T[0-9]{6}Z\\.dump\\.age$")) and
  (.plaintextSha256 | type == "string" and test("^[0-9a-f]{64}$")) and
  (.encryptedSha256 | type == "string" and test("^[0-9a-f]{64}$")) and
  (.archiveObjectKey == ("ecommerce/backups/postgresql/" + .encryptedBackup))
' "$manifest" >/dev/null || fail "PostgreSQL backup manifest contract is invalid"

backup_name=$(jq -r '.encryptedBackup' "$manifest")
case "$backup_name" in
  */* | *..*) fail "unsafe encrypted backup filename" ;;
esac
encrypted=$(dirname "$manifest")/$backup_name
[ -f "$encrypted" ] || fail "encrypted PostgreSQL backup is unavailable"
[ ! -L "$encrypted" ] || fail "encrypted PostgreSQL backup must not be a symbolic link"

expected_encrypted_hash=$(jq -r '.encryptedSha256' "$manifest")
actual_encrypted_hash=$(sha256sum "$encrypted" | awk '{print $1}')
[ "$actual_encrypted_hash" = "$expected_encrypted_hash" ] ||
  fail "encrypted PostgreSQL backup SHA-256 mismatch"

temporary_parent=/tmp
[ -d /dev/shm ] && temporary_parent=/dev/shm
restore_directory=$(mktemp -d "$temporary_parent/terraform-state-pg-restore.XXXXXX")
plaintext=$restore_directory/postgresql.dump
listing=$restore_directory/postgresql.list
cleanup() {
  rm -f "$plaintext" "$listing"
  rmdir "$restore_directory" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM
umask 077

age --decrypt --identity "$identity" --output "$plaintext" "$encrypted"
expected_plaintext_hash=$(jq -r '.plaintextSha256' "$manifest")
actual_plaintext_hash=$(sha256sum "$plaintext" | awk '{print $1}')
[ "$actual_plaintext_hash" = "$expected_plaintext_hash" ] ||
  fail "decrypted PostgreSQL dump SHA-256 mismatch"
pg_restore --list "$plaintext" >"$listing" || fail "pg_restore cannot decode the decrypted custom dump"
grep -q 'SCHEMA .* terraform_management' "$listing" ||
  fail "restore listing does not contain terraform_management"
grep -q 'SCHEMA .* terraform_lock_probe' "$listing" ||
  fail "restore listing does not contain terraform_lock_probe"
grep -q 'TABLE .* states' "$listing" || fail "restore listing does not contain Terraform state tables"

trap - EXIT HUP INT TERM
cleanup
info "encrypted PostgreSQL backup restore test passed without database mutation"
