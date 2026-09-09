# ADR-0002 — Capability-aware reproducible bootstrap

Status: `ACCEPTED`

## Context

The workstation bootstrap was exposed through task-oriented targets and a single Ansible
play whose platform preflight and task order could stop unrelated tooling. Docker readiness
is not a prerequisite for API contract tooling, Ansible, Terraform or Kubernetes clients.

## Decision

`config/toolchain/capabilities.json` is the machine-readable capability contract and
`config/toolchain/versions.env` remains the sole version authority. The contract separates:

- runtime `requires`, which determine whether a capability is usable;
- `provision_requires`, which describe only the mechanism needed to install it;
- executable/version probes from readiness probes;
- Docker client installation, user access, daemon readiness and logical Docker readiness.

`scripts/capability_bootstrap.py` validates the graph, computes a deterministic topological
order and evaluates every independent branch. A failed or externally blocked node causes
`SKIP` only for its transitive runtime dependants. Installation failures are `BLOCKED`;
absent or version-drifted tools are `FAIL`; unsupported OS/architecture pairs are
`UNSUPPORTED`. Neither `BLOCKED` nor `SKIP` is promoted to `PASS`.

The public interface is `make bootstrap` for reconciliation and `make env-check` for the
side-effect-free audit. Reconciliation first probes exact state and does not reinstall
compliant capabilities. A later run naturally resumes nodes that were blocked.

OS (`linux`, `darwin`, `windows`), architecture (`amd64`, `arm64`) and execution context
(`native`, `wsl2`, `ci`, or an explicit `BOOTSTRAP_CONTEXT`) are normalized independently.
An unknown OS or architecture is reported explicitly rather than reaching an unsafe
installer.

## Capability graph

Python and Ruby are independent roots. Pip depends on Python; `ansible-core` depends on pip;
`ansible-playbook` depends on `ansible-core`; Corepack depends on Node. Go, sqlc, yq,
oasdiff, ripgrep, fd, kubectl, Helm, Terraform and Kustomize have no Docker runtime
dependency. Docker readiness is layered over client installation and user access. Kind and
containerized tests alone depend on the logical Docker capability.

The existing Ansible role remains the owner of repeatable tool installation. Its invocation
is represented as a provisioning dependency, not falsely as a runtime dependency. Downloads
continue to consume pinned versions and checksums from the existing authority.

## Consequences and rollback

Audits report all reachable branches and return non-zero whenever the complete platform
contract is not satisfied. A PyPI network failure affects Ansible provisioning while other
independent branches continue. Rollback consists of reverting this ADR, the capability
contract, controller and Make targets; no persistent remote state is migrated.
