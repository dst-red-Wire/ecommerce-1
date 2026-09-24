# Ansible testing policy

The central lifecycle in `config/contracts/toolchain-lock.json` currently marks Molecule,
`molecule-plugins[docker]`, and pytest-testinfra as `deferred`. They are not installed by
bootstrap, expected by doctor, or required by a gate because the repository has no honest
local scenario that consumes them.

When a role can eventually be exercised safely, the intended validation order is:

1. `ansible-playbook --syntax-check`
2. `ansible-lint`
3. Molecule create and converge
4. Molecule idempotence
5. Testinfra verify
6. Molecule destroy

`developer_toolchain` is a workstation role and is not a Docker Molecule candidate: it requires the supported Ubuntu WSL2 host, user-local toolchains, and Docker Desktop integration. `rocky_baseline` manages `chronyd` through systemd; it should receive a Rocky 10.2 systemd-capable Molecule scenario only when the chosen runner can provide real cgroups and service management.

`rke2_server` and `rke2_agent` install and enable RKE2 services from the locked bundle, require a token, and interact with kernel/cgroup/network prerequisites. A Docker-only scenario would be a false pass. Their executable proof is the real VirtualBox/Vagrant/Rocky campaign under `platform/ansible/tests/mgmt_offline_vm/`; it remains an `external-system` proof, not Molecule success.

The Rocky 10.2 Packer profiles and `tests/test_packer_image_contract.py` are `runtime-only`
machine-image proofs. Packer must not invoke Ansible. The four lifecycle states mean:

- `active`: versioned, provisioned, consumed, probed, and backed by a gate or proof;
- `deferred`: version may be reserved, but no install, doctor expectation, or gate execution;
- `rejected`: installation and execution are forbidden with an explicit reason;
- `platform-provided`: not installed by the repository and checked through a deterministic probe.

Component-specific role tests live beside the role when introduced. Cross-role and repository governance tests stay in `tests/`. Versions are never duplicated here; the toolchain lock is the unique authority.

## CODEOWNERS status

`config/contracts/service-ownership.yaml` records domain and data ownership, but does not identify a GitHub/Gitea user or team. `CODEOWNERS` is therefore intentionally not generated: inventing a mapping would create a second, unreliable source of truth. When real forge identities are available, add an `owners` mapping for each component (for example `owners.gitea` and `owners.github`, each containing verified forge handles) to the canonical ownership contract, then generate or validate `CODEOWNERS` from it.
