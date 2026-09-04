#!/bin/sh
set -eu

script_directory=$(CDPATH='' cd -- "$(dirname "$0")" && pwd -P)
export BOOTSTRAP_ROOT=infrastructure/hetzner/bootstrap/object-storage
export BOOTSTRAP_STATE_SLUG=bootstrap-object-storage
export BOOTSTRAP_BACKUP_PREFIX=object-storage-bootstrap
exec "$script_directory/bootstrap-local-state.sh" "$@"
