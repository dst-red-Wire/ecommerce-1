#!/bin/sh
set -eu
# Compatibility alias: Product remains the golden service, but all services use ci-service.sh.
exec env SERVICE=product "$(dirname "$0")/ci-service.sh"
