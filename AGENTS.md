# Repository agent guide

## Scope

These rules apply to the whole repository.

## Development

- Keep CI entry points in `scripts/` runnable both locally and in containers.
- Write POSIX `sh`; do not depend on Bash-only syntax.
- A missing optional project area must be reported as skipped, not treated as a failure.
- Never print secrets, credentials, kubeconfigs, Terraform state, or local environment files.
- Run `make ci` before submitting CI-related changes.
- Do not commit generated reports, caches, binaries, archives, or secret-scanner output.
