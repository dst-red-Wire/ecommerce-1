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

Python and Ruby are independent roots. `ansible-core` is a runner prerequisite, and
`ansible-playbook` plus `ansible-galaxy` are bound to that same validated provider; Corepack depends on Node. Go, sqlc, yq,
oasdiff, ripgrep, fd, kubectl, Helm, Terraform and Kustomize have no Docker runtime
dependency. Docker readiness is layered over client installation and user access. Kind and
containerized tests alone depend on the logical Docker capability.

The repository bootstrap does not install Ansible itself. A compatible Ansible Core
installation, matching the version pinned by `ANSIBLE_CORE_VERSION`, is a runner
prerequisite. The runner image, CI environment, Codex environment or developer workstation
provisioning layer owns its installation. The repository bootstrap uses that validated,
coherent Ansible provider to reconcile project-owned tools.

The authority boundary is therefore explicit: the runner supplies Python, Git, Make and
Ansible; the repository bootstrap supplies the project toolchain. The existing Ansible role
remains the owner of repeatable project-tool installation. Its invocation is represented as
a provisioning dependency, not falsely as a runtime dependency. Downloads continue to
consume pinned versions and checksums from the existing authority.

## Gate executable closure

The contract also owns `gate_requirements`, the explicit executable closure for bootstrap,
governance, contracts, lint, tests, security, Terraform, Ansible, Kubernetes readiness,
context generation and delivery. `gate_sources` identifies Python orchestration entrypoints;
their literal subprocess and `require()` commands are checked with Python's AST rather than
with a partial shell parser. Contract validation rejects an executable that has no managed
capability, seed prerequisite or justified platform primitive, as well as missing graph
dependencies, cycles, absent version pins and malformed checksum authorities.

The runner prerequisites are Python (to start the controller), Git (to locate and inspect the
checkout), Make (the public dispatcher), and the pinned Ansible Core provider with its
`ansible`, `ansible-playbook`, and `ansible-galaxy` entry points. They are audited but never
provisioned by repository bootstrap. Ruby, `tar`, `diff`, a C compiler, `gh`, `curl`
and `unzip` are explicitly justified platform primitives. This classification does not
silently turn them into managed downloads; it records who supplies them and prevents an
undeclared assumption.

Gitleaks, kubectl, Helm, Terraform, Kustomize and Kind use independent, checksum-pinned
Linux/amd64 release assets. Their contract says `UNSUPPORTED` on combinations for which this
repository does not yet implement a provisioner. `oapi-codegen` has no Go runtime dependency;
Go and Ansible are only provisioning dependencies. Kind alone retains the real Docker
runtime edge.

## Consequences and rollback

Audits report all reachable branches and return non-zero whenever the complete platform
contract is not satisfied. Missing or stale Ansible fails the runner prerequisite and skips
only project capabilities whose provisioning requires it; independent branches continue to
be audited. Rollback consists of reverting this ADR, the capability
contract, controller and Make targets; no persistent remote state is migrated.
