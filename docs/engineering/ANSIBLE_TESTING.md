# Ansible testing policy

Validation follows this order when a role can be exercised safely:

1. `ansible-playbook --syntax-check`
2. `ansible-lint`
3. Molecule converge
4. Molecule idempotence
5. Testinfra verify

`developer_toolchain` is a workstation role and is not a Docker Molecule candidate: it requires the supported Ubuntu WSL2 host, user-local toolchains, and Docker Desktop integration. `rocky_baseline` manages `chronyd` through systemd; it should receive a Rocky 9 systemd-capable Molecule scenario only when the chosen runner can provide real cgroups and service management.

`rke2_server` and `rke2_agent` download and enable RKE2 services, require a token, and interact with kernel/cgroup/network prerequisites. A Docker-only scenario would be a false pass. Their first Molecule coverage must instead use a systemd-capable Rocky 9 runner with isolated RKE2 networking and non-secret test variables. Until that runner exists, syntax and lint remain the applicable local gates; this is a documented `SKIP`, not Molecule success.

Component-specific role tests live beside the role when introduced. Cross-role and repository governance tests stay in `tests/`.

## CODEOWNERS status

`config/contracts/service-ownership.yaml` records domain and data ownership, but does not identify a GitHub/Gitea user or team. `CODEOWNERS` is therefore intentionally not generated: inventing a mapping would create a second, unreliable source of truth. When real forge identities are available, add an `owners` mapping for each component (for example `owners.gitea` and `owners.github`, each containing verified forge handles) to the canonical ownership contract, then generate or validate `CODEOWNERS` from it.
