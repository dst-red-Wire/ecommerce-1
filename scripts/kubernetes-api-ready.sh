#!/bin/sh
set -eu

last_error="Kubernetes API did not answer"
for retry_delay in 0 2 4 8 16 30; do
  [ "$retry_delay" -eq 0 ] || sleep "$retry_delay"
  if response=$(kubectl --request-timeout=5s get --raw=/readyz 2>&1); then
    [ "$(printf '%s' "$response" | tr -d '\r\n')" = "ok" ] && exit 0
  fi
  last_error=$response
done

printf '[kubernetes-ready] API unavailable after bounded backoff: %s\n' "$last_error" >&2
exit 1
