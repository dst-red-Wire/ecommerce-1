# ADR-0003 — Rootless Docker Engine for WSL2 developer tests

Status: `ACCEPTED`

## Context

The Windows developer path used Docker Desktop for Go Testcontainers and `kind`.
The local six-VM RKE2 HA campaign must reserve Windows memory and already forbids
Docker Desktop while it runs. The Product integration suite uses the Docker API
through Testcontainers and has no Docker Desktop-specific source dependency.

## Decision

Ubuntu WSL2 uses the exact Docker Engine packages and APT key declared by
`config/contracts/toolchain-lock.json`. Ansible provisions the Engine in rootless
mode, disables the system/rootful Docker and containerd units, exposes only the
per-user Unix socket, and does not enable the user service at login.

The same central lock owns tag-and-SHA256-digest references for PostgreSQL,
Ryuk, and the `kind` node. Qualification passes the digest reference directly to
`kind`; before Testcontainers starts it binds Ryuk's library-defined version tag
to the locked digest and verifies both references resolve to the same image ID.
No qualification container image is selected by a mutable tag alone.

The repository keeps the Docker API as the developer container-runtime contract.
Testcontainers keeps Ryuk enabled. Docker Desktop may be uninstalled only by the
same invocation that has passed all of these checks:

1. exact rootless client/server identity through `docker info`;
2. the pinned PostgreSQL Testcontainers integration test;
3. observed Ryuk creation and zero remaining containers;
4. a ready single-node `kind` smoke cluster followed by cleanup;
5. Windows, WSL and runtime-process memory measurements before, during and after.

The runtime is stopped in a `finally` path after success or failure. The local HA
preflight independently rejects an active Linux container daemon, container
process or active container. This contract is developer/workstation-only and does
not alter PREPROD or production runtime topology.

## Consequences and rollback

Docker Linux remains the actively tested Testcontainers path and existing Go test
source remains portable. Podman socket compatibility is not the default because it
adds provider/network behavior without reducing the dominant test-container load.

Rollback reinstates Docker Desktop in the central workstation Winget policy and
reverts the rootless role and capability provider. No application data or remote
environment is migrated.
