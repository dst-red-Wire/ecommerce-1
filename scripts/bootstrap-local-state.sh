#!/bin/sh
set -eu

# Internal reusable implementation. Invoke it only through a component wrapper
# that fixes BOOTSTRAP_ROOT, BOOTSTRAP_STATE_SLUG and BOOTSTRAP_BACKUP_PREFIX.
# shellcheck disable=SC1091
. "$(dirname "$0")/lib.sh"
cd "$(repo_root)"

: "${BOOTSTRAP_ROOT:?BOOTSTRAP_ROOT is required}"
: "${BOOTSTRAP_STATE_SLUG:?BOOTSTRAP_STATE_SLUG is required}"
: "${BOOTSTRAP_BACKUP_PREFIX:?BOOTSTRAP_BACKUP_PREFIX is required}"

require jq
require python3
require realpath
require sha256sum
require terraform

usage() {
  fail "usage: component-wrapper init | terraform <args...> | output-inventory | backup | restore-test <manifest.json>"
}

[ "$#" -ge 1 ] || usage
command_name=$1
shift

unset TF_LOG TF_LOG_CORE TF_LOG_PROVIDER TF_LOG_PATH MINIO_DEBUG
unset TF_CLI_ARGS TF_CLI_ARGS_init TF_CLI_ARGS_plan TF_CLI_ARGS_apply
unset TF_CLI_ARGS_fmt TF_CLI_ARGS_validate TF_CLI_ARGS_providers TF_CLI_ARGS_output
unset BOOTSTRAP_STATE_DIR
export TF_WORKSPACE=default

repository=$(pwd -P)
case "$BOOTSTRAP_ROOT" in
  infrastructure/hetzner/bootstrap/*) ;;
  *) fail "bootstrap root must remain under infrastructure/hetzner/bootstrap" ;;
esac
[ -d "$BOOTSTRAP_ROOT" ] || fail "bootstrap root is unavailable"
case "$BOOTSTRAP_STATE_SLUG$BOOTSTRAP_BACKUP_PREFIX" in
  *[!A-Za-z0-9_-]*) fail "unsafe bootstrap state identifier" ;;
esac

trusted_home=$(python3 -c 'import os, pwd; print(pwd.getpwuid(os.geteuid()).pw_dir)')
case "$trusted_home" in
  /*) ;;
  *) fail "trusted system home must use an absolute WSL path" ;;
esac
state_base_input=${XDG_STATE_HOME:-"$trusted_home/.local/state"}
case "$state_base_input" in
  /*) ;;
  *) fail "XDG state root must use an absolute WSL path" ;;
esac
allowed_state_root=$(python3 -c 'import os, sys; print(os.path.abspath(sys.argv[1]))' \
  "$state_base_input/ecommerce-1/terraform")
state_directory=$(python3 -c 'import os, sys; print(os.path.abspath(sys.argv[1]))' \
  "$allowed_state_root/$BOOTSTRAP_STATE_SLUG")
case "$allowed_state_root" in
  "$repository" | "$repository"/* | /mnt/c/Users/*/OneDrive/*)
    fail "allowed XDG state root must remain outside the repository and OneDrive"
    ;;
esac
case "$state_directory" in
  "$allowed_state_root"/*) ;;
  *) fail "authoritative bootstrap state must remain below the allowed XDG state root" ;;
esac
case "$state_directory" in
  "$repository" | "$repository"/* | /mnt/c/Users/*/OneDrive/*)
    fail "authoritative bootstrap state must remain outside the repository and OneDrive"
    ;;
esac

state_file=$state_directory/terraform.tfstate
terraform_data_directory=$state_directory/terraform-data
umask 077

prepare_state_directory() {
  python3 scripts/validate-bootstrap-state-path.py \
    --allowed-root "$allowed_state_root" \
    --state-directory "$state_directory" \
    --prepare
  export TF_DATA_DIR="$terraform_data_directory"
}

revalidate_state_directory() {
  python3 scripts/validate-bootstrap-state-path.py \
    --allowed-root "$allowed_state_root" \
    --state-directory "$state_directory"
}

require_authoritative_state() {
  python3 scripts/validate-bootstrap-state-path.py \
    --allowed-root "$allowed_state_root" \
    --state-directory "$state_directory" \
    --require-state
}

external_plan_path() {
  requested_plan=$1
  case "$requested_plan" in
    /*) ;;
    *) fail "bootstrap plan output must use an absolute WSL path" ;;
  esac
  resolved_plan=$(realpath -m "$requested_plan")
  case "$resolved_plan" in
    "$state_directory" | "$state_directory"/*)
      fail "bootstrap plan must remain outside the authoritative state directory"
      ;;
    "$repository" | "$repository"/* | /mnt/c/Users/*/OneDrive/*)
      fail "bootstrap plan output must remain outside the repository and OneDrive"
      ;;
  esac
  printf '%s\n' "$resolved_plan"
}

reject_state_control_arguments() {
  for terraform_argument in "$@"; do
    case "$terraform_argument" in
      -state | -state=* | --state | --state=* | \
        -state-out | -state-out=* | --state-out | --state-out=* | \
        -backup | -backup=* | --backup | --backup=*)
        fail "caller-supplied Terraform state or backup path options are forbidden"
        ;;
    esac
  done
}

case "$command_name" in
  init)
    [ "$#" -eq 0 ] || usage
    prepare_state_directory
    set +e
    terraform -chdir="$BOOTSTRAP_ROOT" init -backend=false -input=false
    init_status=$?
    set -e
    revalidate_state_directory
    [ "$init_status" -eq 0 ] || exit "$init_status"
    info "bootstrap providers initialized with Terraform data outside the repository and OneDrive"
    ;;

  terraform)
    [ "$#" -gt 0 ] || usage
    reject_state_control_arguments "$@"
    prepare_state_directory
    [ -d "$terraform_data_directory/providers" ] ||
      fail "bootstrap providers are not initialized; run the component wrapper init first"
    terraform_command=$1
    shift
    case "$terraform_command" in
      plan)
        plan_output=
        for terraform_argument in "$@"; do
          case "$terraform_argument" in
            -out=*)
              [ -z "$plan_output" ] || fail "bootstrap plan accepts exactly one -out path"
              plan_output=${terraform_argument#-out=}
              ;;
          esac
        done
        [ -n "$plan_output" ] || fail "bootstrap plan requires -out=<absolute-path>"
        external_plan_path "$plan_output" >/dev/null
        set +e
        terraform -chdir="$BOOTSTRAP_ROOT" plan -state="$state_file" "$@"
        plan_status=$?
        set -e
        revalidate_state_directory
        exit "$plan_status"
        ;;
      apply)
        [ "$#" -eq 1 ] || fail "bootstrap apply accepts exactly one reviewed saved plan"
        reviewed_plan=$(external_plan_path "$1")
        [ -f "$reviewed_plan" ] || fail "reviewed bootstrap plan is unavailable"
        [ ! -L "$reviewed_plan" ] || fail "reviewed bootstrap plan must not be a symbolic link"
        set +e
        terraform -chdir="$BOOTSTRAP_ROOT" apply \
          -state="$state_file" \
          -backup="$state_file.backup" \
          "$reviewed_plan"
        apply_status=$?
        set -e
        python3 scripts/validate-bootstrap-state-path.py \
          --allowed-root "$allowed_state_root" \
          --state-directory "$state_directory" \
          --require-state
        exit "$apply_status"
        ;;
      fmt | validate | providers)
        exec terraform -chdir="$BOOTSTRAP_ROOT" "$terraform_command" "$@"
        ;;
      *) fail "unsupported bootstrap Terraform command: $terraform_command" ;;
    esac
    ;;

  output-inventory)
    [ "$#" -eq 0 ] || usage
    [ "$BOOTSTRAP_STATE_SLUG" = bootstrap-terraform-state ] ||
      fail "output-inventory is available only for terraform-state bootstrap"
    prepare_state_directory
    require_authoritative_state
    inventory_output=$(mktemp)
    inventory_read_directory=$(mktemp -d)
    chmod 0700 "$inventory_read_directory"
    cleanup_inventory_output() {
      rm -f "$inventory_output"
      rmdir "$inventory_read_directory" 2>/dev/null || true
    }
    trap cleanup_inventory_output EXIT HUP INT TERM
    terraform -chdir="$inventory_read_directory" output \
      -state="$state_file" \
      -json \
      inventory_contract >"$inventory_output" ||
      fail "inventory_contract is unavailable from the authoritative external state"
    require_authoritative_state
    python3 scripts/render-terraform-state-inventory.py \
      --output-format json \
      "$inventory_output"
    trap - EXIT HUP INT TERM
    cleanup_inventory_output
    ;;

  backup)
    [ "$#" -eq 0 ] || usage
    require age
    : "${BOOTSTRAP_BACKUP_DIR:?BOOTSTRAP_BACKUP_DIR is required}"
    : "${AGE_RECIPIENT:?AGE_RECIPIENT is required}"
    prepare_state_directory
    require_authoritative_state

    backup_directory=$(realpath -m "$BOOTSTRAP_BACKUP_DIR")
    case "$backup_directory" in
      "$repository" | "$repository"/* | "$state_directory" | "$state_directory"/* | /mnt/c/Users/*/OneDrive/*)
        fail "encrypted backups must use independent storage outside state, repository, and OneDrive"
        ;;
    esac
    mkdir -p "$backup_directory"
    chmod 0700 "$backup_directory"

    timestamp=$(date -u '+%Y%m%dT%H%M%SZ')
    backup_name="$BOOTSTRAP_BACKUP_PREFIX-$timestamp.tfstate.age"
    encrypted=$backup_directory/$backup_name
    manifest=$backup_directory/$BOOTSTRAP_BACKUP_PREFIX-$timestamp.manifest.json
    if [ -e "$encrypted" ] || [ -e "$manifest" ]; then
      fail "backup timestamp collision"
    fi

    state_sha256=$(sha256sum "$state_file" | awk '{print $1}')
    lineage=$(jq -er '.lineage | select(type == "string" and length > 0)' "$state_file") ||
      fail "bootstrap state lineage is unavailable"
    serial=$(jq -er '.serial | select(type == "number" and . >= 0)' "$state_file") ||
      fail "bootstrap state serial is unavailable"
    state_terraform_version=$(jq -er '.terraform_version | select(type == "string" and length > 0)' "$state_file") ||
      fail "bootstrap state Terraform version is unavailable"

    age --recipient "$AGE_RECIPIENT" --output "$encrypted" "$state_file"
    chmod 0600 "$encrypted"
    jq -n \
      --arg component "$BOOTSTRAP_STATE_SLUG" \
      --arg backup "$backup_name" \
      --arg created "$timestamp" \
      --arg sha256 "$state_sha256" \
      --arg lineage "$lineage" \
      --arg terraform_version "$state_terraform_version" \
      --argjson serial "$serial" \
      '{
        version: 1,
        component: $component,
        encryptedBackup: $backup,
        createdAtUtc: $created,
        plaintextSha256: $sha256,
        lineage: $lineage,
        serial: $serial,
        terraformVersion: $terraform_version,
        encryption: "age"
      }' >"$manifest"
    chmod 0600 "$manifest"
    info "encrypted bootstrap state backup and integrity manifest created"
    ;;

  restore-test)
    [ "$#" -eq 1 ] || usage
    require age
    : "${AGE_IDENTITY_FILE:?AGE_IDENTITY_FILE is required}"
    manifest=$(realpath "$1") || fail "backup manifest does not exist"
    if [ ! -f "$manifest" ] || [ -L "$manifest" ]; then
      fail "backup manifest is unsafe"
    fi
    case "$manifest" in
      "$repository"/* | "$state_directory"/* | /mnt/c/Users/*/OneDrive/*)
        fail "restore tests must consume an independent backup outside repository, state, and OneDrive"
        ;;
    esac
    jq --exit-status --arg component "$BOOTSTRAP_STATE_SLUG" '
      .version == 1 and
      .component == $component and
      .encryption == "age" and
      (.encryptedBackup | type == "string" and length > 0) and
      (.plaintextSha256 | type == "string" and test("^[0-9a-f]{64}$")) and
      (.lineage | type == "string" and length > 0) and
      (.serial | type == "number" and . >= 0) and
      (.terraformVersion | type == "string" and length > 0)
    ' "$manifest" >/dev/null || fail "backup manifest contract is invalid"
    backup_name=$(jq -er '.encryptedBackup | select(type == "string" and length > 0)' "$manifest") ||
      fail "backup filename is absent from manifest"
    case "$backup_name" in
      */* | *..*) fail "unsafe backup filename in manifest" ;;
    esac
    encrypted=$(dirname "$manifest")/$backup_name
    if [ ! -f "$encrypted" ] || [ -L "$encrypted" ]; then
      fail "encrypted backup is unavailable or unsafe"
    fi

    temporary_parent=/tmp
    [ -d /dev/shm ] && temporary_parent=/dev/shm
    restore_directory=$(mktemp -d "$temporary_parent/ecommerce-bootstrap-restore.XXXXXX")
    restored=$restore_directory/terraform.tfstate
    cleanup_restore() {
      rm -f "$restored"
      rmdir "$restore_directory" 2>/dev/null || true
    }
    trap cleanup_restore EXIT HUP INT TERM

    age --decrypt --identity "$AGE_IDENTITY_FILE" --output "$restored" "$encrypted"
    chmod 0600 "$restored"
    jq empty "$restored" >/dev/null || fail "decrypted backup is not valid JSON"
    expected_sha256=$(jq -r '.plaintextSha256' "$manifest")
    expected_lineage=$(jq -r '.lineage' "$manifest")
    expected_serial=$(jq -r '.serial' "$manifest")
    actual_sha256=$(sha256sum "$restored" | awk '{print $1}')
    actual_lineage=$(jq -r '.lineage' "$restored")
    actual_serial=$(jq -r '.serial' "$restored")
    [ "$actual_sha256" = "$expected_sha256" ] || fail "restored state SHA-256 mismatch"
    [ "$actual_lineage" = "$expected_lineage" ] || fail "restored state lineage mismatch"
    [ "$actual_serial" = "$expected_serial" ] || fail "restored state serial mismatch"
    terraform show -json "$restored" >/dev/null || fail "Terraform cannot decode the restored state"

    trap - EXIT HUP INT TERM
    cleanup_restore
    info "encrypted bootstrap state restore test passed without replacing authoritative state"
    ;;

  *) usage ;;
esac
