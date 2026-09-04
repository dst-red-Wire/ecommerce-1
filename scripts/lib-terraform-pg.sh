# shellcheck shell=sh
# Shared runtime guards for the Terraform PostgreSQL backend. This file is
# sourced by POSIX sh entry points and must never print connection credentials.

terraform_pg_require_runtime() {
  pg_repository=${repository:?caller must set repository before validating PostgreSQL runtime}
  : "${PG_CONN_STR:?PG_CONN_STR is required}"
  : "${PGPASSWORD:?PGPASSWORD is required}"
  : "${PGSSLROOTCERT:?PGSSLROOTCERT is required}"

  : "${TERRAFORM_PG_TUNNEL_HOST:?TERRAFORM_PG_TUNNEL_HOST is required}"
  : "${TERRAFORM_PG_TUNNEL_PORT:?TERRAFORM_PG_TUNNEL_PORT is required}"
  require python3
  python3 "$pg_repository/scripts/validate-terraform-pg-connection.py"

  # lib/pq v1.10.3 reads these before PG_CONN_STR. The canonical URL fixes all
  # target/TLS coordinates, while rejecting the remaining variables keeps the
  # effective connection contract explicit and reproducible.
  [ "${PGHOST+x}" != x ] || fail "PGHOST must be unset; use canonical PG_CONN_STR"
  [ "${PGHOSTADDR+x}" != x ] || fail "PGHOSTADDR must be unset; use canonical PG_CONN_STR"
  [ "${PGPORT+x}" != x ] || fail "PGPORT must be unset; use canonical PG_CONN_STR"
  [ "${PGDATABASE+x}" != x ] || fail "PGDATABASE must be unset; use canonical PG_CONN_STR"
  [ "${PGUSER+x}" != x ] || fail "PGUSER must be unset; use canonical PG_CONN_STR"
  [ "${PGSERVICE+x}" != x ] || fail "PGSERVICE must be unset"
  [ "${PGSERVICEFILE+x}" != x ] || fail "PGSERVICEFILE must be unset"
  [ "${PGOPTIONS+x}" != x ] || fail "PGOPTIONS must be unset"
  [ "${PGAPPNAME+x}" != x ] || fail "PGAPPNAME must be unset"
  [ "${PGSSLMODE+x}" != x ] || fail "PGSSLMODE must be unset; use canonical PG_CONN_STR"
  [ "${PGSSLCERT+x}" != x ] || fail "PGSSLCERT must be unset"
  [ "${PGSSLKEY+x}" != x ] || fail "PGSSLKEY must be unset"
  [ "${PGREQUIRESSL+x}" != x ] || fail "PGREQUIRESSL must be unset"
  [ "${PGSSLCRL+x}" != x ] || fail "PGSSLCRL must be unset"
  [ "${PGREQUIREPEER+x}" != x ] || fail "PGREQUIREPEER must be unset"
  [ "${PGKRBSRVNAME+x}" != x ] || fail "PGKRBSRVNAME must be unset"
  [ "${PGGSSLIB+x}" != x ] || fail "PGGSSLIB must be unset"
  [ "${PGCONNECT_TIMEOUT+x}" != x ] || fail "PGCONNECT_TIMEOUT must be unset"
  [ "${PGCLIENTENCODING+x}" != x ] || fail "PGCLIENTENCODING must be unset"
  [ "${PGDATESTYLE+x}" != x ] || fail "PGDATESTYLE must be unset"
  [ "${PGTZ+x}" != x ] || fail "PGTZ must be unset"
  [ "${PGGEQO+x}" != x ] || fail "PGGEQO must be unset"
  [ "${PGSYSCONFDIR+x}" != x ] || fail "PGSYSCONFDIR must be unset"
  [ "${PGLOCALEDIR+x}" != x ] || fail "PGLOCALEDIR must be unset"
  [ "${PGPASSFILE+x}" != x ] || fail "PGPASSFILE must be unset; use PGPASSWORD"

  case "$PGPASSWORD" in
    '') fail "PGPASSWORD must not be empty" ;;
  esac
  case "$PGSSLROOTCERT" in
    /*) ;;
    *) fail "PGSSLROOTCERT must use an absolute WSL path" ;;
  esac
  [ ! -L "$PGSSLROOTCERT" ] || fail "PGSSLROOTCERT must not be a symbolic link"
  pg_root_certificate=$(realpath "$PGSSLROOTCERT") ||
    fail "PGSSLROOTCERT does not exist"
  [ -f "$pg_root_certificate" ] || fail "PGSSLROOTCERT is not a regular file"
  case "$pg_root_certificate" in
    "$pg_repository" | "$pg_repository"/* | /mnt/c/Users/*/OneDrive/*)
      fail "PGSSLROOTCERT must remain outside the repository and OneDrive"
      ;;
  esac
  export PGSSLROOTCERT="$pg_root_certificate"

  unset PG_SCHEMA_NAME PG_SKIP_SCHEMA_CREATION PG_SKIP_TABLE_CREATION PG_SKIP_INDEX_CREATION
  unset TF_LOG TF_LOG_CORE TF_LOG_PROVIDER TF_LOG_PATH
}

terraform_pg_psql() {
  psql "$PG_CONN_STR" --no-psqlrc --set=ON_ERROR_STOP=1 "$@"
}

terraform_pg_external_path() {
  pg_requested_path=$1
  pg_path_purpose=$2
  pg_repository=${repository:?caller must set repository before validating external paths}
  case "$pg_requested_path" in
    /*) ;;
    *) fail "$pg_path_purpose must use an absolute WSL path" ;;
  esac
  pg_resolved_path=$(realpath -m "$pg_requested_path")
  case "$pg_resolved_path" in
    "$pg_repository" | "$pg_repository"/* | /mnt/c/Users/*/OneDrive/*)
      fail "$pg_path_purpose must remain outside the repository and OneDrive"
      ;;
  esac
  printf '%s\n' "$pg_resolved_path"
}
