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

The authority boundary is therefore explicit: the runner supplies Python, Ruby, Git, Make
and Ansible; the repository bootstrap supplies the project toolchain. The existing Ansible role
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

The runner prerequisites are Python (to start the controller), Ruby (to execute deterministic
governance validators), Git (to locate and inspect the checkout), Make (the public dispatcher), and the pinned Ansible Core provider with its
`ansible`, `ansible-playbook`, and `ansible-galaxy` entry points. They are audited but never
provisioned by repository bootstrap. `tar`, `diff`, a C compiler, `gh`, `curl`
and `unzip` are explicitly justified platform primitives. This classification does not
silently turn them into managed downloads; it records who supplies them and prevents an
undeclared assumption.

Gitleaks, kubectl, Helm, Terraform, Kustomize and Kind use independent, checksum-pinned
Linux/amd64 release assets. Their contract says `UNSUPPORTED` on combinations for which this
repository does not yet implement a provisioner. `oapi-codegen` has no Go runtime dependency;
Go and Ansible are only provisioning dependencies. Kind alone retains the real Docker
runtime edge.

## Staged Ansible execution boundary

The optional `precommit-ansible` gate requires Linux bubblewrap pinned by
`BWRAP_VERSION`, plus systemd-run/systemctl and a delegated user cgroup v2 manager.
These host-provided capabilities are prerequisites only for staged Ansible lint.
Unsupported platforms, unavailable namespaces/delegation, mismatched pins or missing
controllers fail this gate closed. No installation, global host reconfiguration or
unsandboxed fallback occurs. The indexed bubblewrap pin must match the trusted
controller pin; an unstaged pin cannot hide an incompatible staged declaration.
The checkout-external tool installations and their PATH configuration remain operator
trust inputs; this boundary does not establish ownership/ACL trust for every external
executable or protect an already compromised workstation.

Ansible can discover executable plugins next to candidate YAML even with trusted
lint rules and inventory. Staged lint therefore uses private user, PID, IPC, network
and other namespaces, disables nested user namespaces, and drops all capabilities.
Indexed regular files, controller-generated configuration, the installed isolated
ansible-lint runtime, Git and system libraries are mounted read-only. Runtime
location and base-Python stdlib/shared-library paths come from the installed launcher
and verified interpreter, never candidate metadata. External Python prefixes are
supported when their declared runtime paths stay inside that installed prefix;
unrepresentable layouts fail closed. Host credentials, ambient environment, sockets
and network are absent. Standard input is closed, and candidate stdout/stderr are
discarded; only a controller-authored failure message reaches the terminal.
Controller-owned lint kinds classify only `platform/tekton/**/*.yaml` and `*.yml`
as generic YAML before Ansible filename discovery. YAML validation still applies;
Tekton contract gates retain semantic validation, and Ansible task schema checks
remain enforced for Ansible paths.

Third-party modules use the fully checksum-locked collection closure copied from
integration `623f0bd` (the PR86 collection dependency), including community.docker
5.2.2. The canonical `scripts/ansible_collections.py`, requirements and lock are
reused without another resolver or extractor. PR99 dependency commit
`ab3bedd9f0d74b2ad77b8ab439ffa0f35b6ee693` supplies the complete seed and lock
primitives; no partial bootstrap implementation is duplicated. Every archive, payload and inventory
is authenticated before mounting a concrete immutable generation read-only.
Candidate `.ansible` trees and arbitrary host collection caches never supply this
runtime. Provisioning uses the canonical collection preparer separately; lint never
downloads or repairs dependencies. The exact requirements delta is admitted in the
runner guard as this reviewed dependency, without widening runner scopes; independent
review of the controller remains required before qualification-runner use.

Each invocation owns a random transient user scope: at most 32 tasks, 768 MiB cgroup
memory, no swap, one CPU and 120 seconds lifetime. Effective memory/task/CPU cgroup
limits are verified before execution. A read-only CPU budget view keeps ansible-lint
from sizing its worker pool to the host CPU count. Inherited hard limits additionally cap each
process at 512 MiB address space, 90 CPU seconds, 128 descriptors and 16 MiB file
output. Temporary/home tmpfs mounts are limited to 64/16 MiB. Cleanup stops only that
invocation's scope, including detached descendants; PID namespace teardown adds an
independent boundary. No candidate output is accumulated in controller memory.

Regression evidence exercises valid builtin and Kubernetes YAML, malicious adjacent
filter/lookup plugins and indexed collections, closed inherited input, suppressed
diagnostics, effective resource limits and detached-process termination. A real
sandbox probe checks host-file reads/writes, credential environment, PID and network
isolation. This host exercised bubblewrap 0.9.0, systemd 255, Python 3.12 and
ansible-lint 26.8.0 (its isolated runtime uses ansible-core 2.21.4; the canonical
Galaxy/playbook installer remains pinned to 2.20.3); other
hosts must provide the same capabilities rather than receiving a claimed proof.
Rollback must preserve an equivalent execution boundary or fail this optional gate
closed.

## Consequences and rollback

Audits report all reachable branches and return non-zero whenever the complete platform
contract is not satisfied. Missing or stale Ansible fails the runner prerequisite and skips
only project capabilities whose provisioning requires it; independent branches continue to
be audited. Rollback consists of reverting this ADR, the capability
contract, controller and Make targets; no persistent remote state is migrated.
