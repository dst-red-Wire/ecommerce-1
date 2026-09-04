#!/bin/sh
set -eu

script_directory=$(CDPATH='' cd -- "$(dirname "$0")" && pwd -P)
export BOOTSTRAP_ROOT=infrastructure/hetzner/bootstrap/terraform-state
export BOOTSTRAP_STATE_SLUG=bootstrap-terraform-state
export BOOTSTRAP_BACKUP_PREFIX=terraform-state-bootstrap
exec "$script_directory/bootstrap-local-state.sh" "$@"
