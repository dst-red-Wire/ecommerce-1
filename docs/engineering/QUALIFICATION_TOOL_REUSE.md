# Qualification tool and cache reuse

`make qualify BASE=<immutable-base>` is the canonical local entry point. It computes the
static capability plan, prepares missing pinned prerequisites, audits the resolved tools,
and only then executes qualification. Tool/cache reuse never reuses a PASS verdict: the
normal exact base/head and signed-evidence rules remain in force.

## Persistent identities

`ECOMMERCE_TOOL_HOME` defaults to `~/.cache/ecommerce-1/qualification` and may point to a
runner-owned persistent volume outside every checkout. The Python seed (Ansible Core,
ansible-lint, and their complete Python closure) identity includes
the Python implementation and major/minor runtime, OS/architecture, complete lockfile
SHA-256, and hash-enforcing pip parameters. A checkout's `.venv/qualification` is only an
atomic local reference to that immutable environment. Repairs build a fresh generation
under `python/<identity>.generations/` at its final path, validate it, then atomically
update `<identity>.current` and the checkout reference. Venvs are never moved. Existing
generations remain for running consumers (which do not take the preparation lock);
failed preparation removes its unpublished candidate and leaves the published generation untouched. Maintenance can reclaim
unreferenced generations only after consumers have stopped. The lock includes the
conditional `ruamel-yaml-clib` dependency for Python below 3.14 and `typing-extensions`
for Python below 3.13; its closure is installable under Ubuntu 24.04's Python 3.12.

Standalone tools continue to resolve versions from `config/toolchain/versions.env` and
checksums/provenance from the existing capability and Ansible contracts. Multiple versions
occupy separate version/platform directories. In particular, templ is compiled once as
`~/.local/share/ecommerce-1/tools/templ/<version>/linux-amd64/templ`; frontend gates invoke
that binary rather than allowing `go run` to download or rebuild it. A checkout resolves
its own pin explicitly and does not depend on a mutable `current` selector.

## Concurrency, recovery, and offline operation

The seed uses a bounded per-identity filesystem lock and repeats all metadata and runtime
version checks after acquiring it. An interrupted or corrupt identity is repaired in
isolation without deleting other versions. Downloads use pip's persistent content cache;
Go module/build data use the native concurrency-safe caches. Templ preparation is guarded
by its version/platform lock. Archive-based Ansible installers validate canonical SHA-256
values before extraction and retain verified archives in the user cache.
Ansible collections resolve from
`$ECOMMERCE_TOOL_HOME/ansible/collections/<collections-lock-sha256>`. The lock includes the
complete direct and transitive closure, official Galaxy artifact metadata SHA-256 values,
the Ansible Core installer version, and layout parameters. Archives persist under
`$ECOMMERCE_TOOL_HOME/ansible/archives`; `make ansible-collections` is the only network
acquisition entry point and `make ansible-collections-offline` rebuilds an installation
strictly from those verified archives. A local digest match proves integrity against the
locked Galaxy metadata digest; it is not a signature or independent authenticity proof.
Installation is serialized by identity, rechecked after locking, built in a temporary
directory, validated, and atomically published, so equal locks in different checkouts reuse
the same collection tree without exposing partial installs.

The exported persistent caches are:

* `PIP_CACHE_DIR=$ECOMMERCE_TOOL_HOME/downloads/pip`;
* `GOMODCACHE=$ECOMMERCE_TOOL_HOME/cache/go/mod`;
* `GOCACHE=$ECOMMERCE_TOOL_HOME/cache/go/<go-version>/build`;
* `TF_PLUGIN_CACHE_DIR=$ECOMMERCE_TOOL_HOME/cache/terraform/providers`.

On a cold machine, the runner image and absent identities/caches still require downloads.
With the image present, only identities absent from it are prepared. With warm caches, a
new checkout reuses matching tools and dependencies. A pin change prepares only the new
identity and preserves the old one. Fully cached preparation works without network access;
application integration tests may independently require network access.

## Product Docker qualification

`make service-check SERVICE=product` is the canonical Product gate. When the Docker
client is missing, the existing `docker_client` Ansible tag downloads the official,
checksum-pinned archive and installs only its CLI. It does not start a daemon, alter a
global Docker context, grant socket access, or attempt privileged Docker-in-Docker.

The gate resolves the active context into `DOCKER_HOST` for both its bounded preflight
and testcontainers-go. An explicit `DOCKER_HOST` remains authoritative. Network endpoint
resolution requires `DOCKER_TLS_VERIFY=1` for TCP/HTTP/HTTPS and preserves context TLS
certificates; SSH remains an authenticated transport.

Product qualification currently accepts only local Unix sockets or canonical local
named pipes (`npipe:////./pipe/name`). UNC server paths, encoded paths and alternate
namespace forms are refused before daemon contact. It
rejects remote endpoints before contacting the daemon: Testcontainers Go 0.44.0 creates
Ryuk separately and does not expose a supported binding override for its unauthenticated
control port. The Go fixture independently rejects remote or unresolved endpoints before
creating any container, including when invoked directly. This includes the `tc.host`
and `docker.host` property overrides. A host override, an authorized
PostgreSQL bind address, or verified Docker TLS does not waive this restriction. Remote
qualification can return only once Ryuk's interface binding can be enforced before it
starts. Local PostgreSQL publication remains loopback with a random per-run credential.

Before Go downloads or compilation, the gate requires a real server response. It then
uses the pinned PostgreSQL image to prove pull/reuse, container start, a labelled volume,
and published-port reachability. Cleanup addresses only the unique labelled container
and volume from that invocation and verifies they are absent. The Product integration
test subsequently runs uncached with the race detector and uses the pinned Ryuk image;
Ryuk, TLS, integrity checks, and Testcontainers cleanup remain enabled.

Testcontainers Go 0.44.0 hardcodes its Ryuk tag and does not consume
`RYUK_CONTAINER_IMAGE`. The preflight therefore acquires the pinned digest, checks
that the upstream tag has the same local image ID, and fails on disagreement without
retagging an existing image. The integration test also compares the running session's
Ryuk image ID to `ECOMMERCE_RYUK_IMAGE`, supplied by the gate, before testing persistence.
This detects tag drift between preflight and container creation and requires Ryuk to be
running. Docker CLI and Testcontainers use the same resolved endpoint for these checks.

To resume on a compatible runner, make a clean checkout at the exact commit, verify
`git status --porcelain=v1` is empty, pass any Docker endpoint variables explicitly for
that invocation, and run:

```text
test "$(git rev-parse HEAD)" = "$EXPECTED_SHA"
BASE="$MAIN_BASELINE_SHA" make service-check SERVICE=product
```

Successful command output is execution evidence only when it includes the exact Git
identity, Docker client and server identities, the runtime-proof cleanup PASS, and the
real PostgreSQL/Testcontainers test PASS. A repository runner definition or `docker
info` alone is not runtime evidence.

Maintenance is explicit: stop qualification processes, then remove only unused identity
directories or cache entries below `ECOMMERCE_TOOL_HOME`. Never delete a referenced Python
identity, never clean these caches at bootstrap time, and never place sources, credentials,
kubeconfigs, Terraform state, or qualification evidence there.

## Tekton/Harbor handoff

The Tekton `runner-image` parameter remains an immutable Harbor `@sha256:` reference. Build
and publish a runner image only when the toolchain identity changes, then update the
management-plane runtime input after digest verification. Application-only changes do not
rebuild it. Ephemeral Task workspaces should mount runner-owned persistent volumes for the
four caches above; retention and garbage collection are platform policy, not a source
checkout lifecycle. This repository change prepares that wiring and performs no remote
publication or infrastructure mutation.

## PR #86 review hardening

The execution order is the checkout's locked Python seed, managed user tools, then
inherited system commands. Docker endpoints resolve once: an explicit `DOCKER_HOST`
wins; otherwise the selected context supplies the endpoint and TLS settings. The
resolved environment removes `DOCKER_CONTEXT` for both CLI and Testcontainers.
Docker subprocess diagnostics are redacted before output, exceptions or persisted
qualification logs. Cleanup inspects the unique invocation label before removing
containers by ID, then volumes by name, and verifies disappearance even after a
partial creation failure. Cleanup failure retains the initial diagnostic.

Seed validation evaluates PEP 508 markers inside the target interpreter using pip's
vendored parser, then checks exact installed versions and `pip check`. Simulated
Python 3.12/3.13/3.14 marker tests do not count as running those interpreters.

Collection identities use `ansible_collections.identity()` through the portable
Python CLI. Installation records the resolved Galaxy executable and its probed
Ansible Core version. Existing installations without this provenance are invalid
and rebuilt once from checksum-verified cached archives; complete installations
with matching provenance retain the local fast path without invoking Galaxy.
The Make preparation entry points prepare the seed first. Direct helper callers
must supply a conforming installer; a mismatch fails before publication.

The `docker_client` and `terraform` tags both initialize their configured directories.
The standalone Terraform gate checks the pinned executable and
`TF_PLUGIN_CACHE_DIR` before init, invoking only Terraform reconciliation when either
is missing or invalid. A warm gate avoids Ansible preparation entirely.

### Second PR86 review

Make does not calculate collection identities during parsing. Its Ansible recipe
wrapper prepares Python first, resolves the single collection identity, prepares the
collection tree under the locked provider, and invokes the seed's absolute playbook
executable. This works for mixed and parallel Make goals without a target allowlist.
Direct collection preparation checks both Galaxy and playbook versions before cold
installation or warm reuse; warm verification does not acquire Galaxy artifacts.
Resolved contexts clear foreign TLS parameters before applying their own metadata;
missing required context certificates fail explicitly. Explicit DOCKER_HOST retains
its associated TLS settings and precedence over DOCKER_CONTEXT.

Gate subprocesses clear the repository-local Git variables reported by
`git rev-parse --local-env-vars`. This prevents temporary fixture repositories
from inheriting a commit hook's index or worktree, while the parent verification
keeps the intended commit index and all hook checks remain enabled.

### Five active PR86 findings

Collection reuse verifies every installed archive member against the locally retained,
SHA-256-locked archive, including MANIFEST.json and FILES.json themselves. The tar
inventory preserves the actual symlink types used by the pinned Galaxy releases
(FILES format 1 lists these as files). Paths, parent directories, link targets and
member types are checked; an altered inventory cannot authorize altered payloads.
The warm path requires the verified archives and performs no acquisition or install.
Missing or invalid archives cause an explicit offline failure, or bounded acquisition
through the existing preparation entry point.

Repairs publish `<identity>.current` atomically, selecting a validated directory under
`<identity>.generations/`. Each Make, workstation, controller and bootstrap consumer
resolves that selector to a concrete directory before launching Ansible. Legacy
`<identity>` directories and previously published generations stay in place. Failed
unpublished candidates are removed; interrupted candidates may remain and are never
selected by directory scanning. No automatic destructive collection is performed.
A dangling selector inside its identity is treated as an invalid cache and repaired
from locked archives; selectors escaping that identity remain rejected.
The generation root itself must not be a symlink. Unexpected non-file archive
paths fail with a controlled diagnostic and retain their contents for reconciliation.

Docker client reconciliation probes presence, executability and the canonical version,
extracts only the client into a unique candidate beside the destination, validates it,
and publishes the file with a same-filesystem atomic rename. Concurrent preparations
use independent candidates and only publish validated clients. A conforming destination
is not reinstalled. The canonical checksum protects the retained official archive.
Publication replaces destination symlinks without following them. An unexpected
destination directory is safely refused and left intact for explicit reconciliation.
The runtime capability audit uses the same selected executable as repoctl and compares
only the client with DOCKER_CLIENT_VERSION; the environment owns the daemon version.
Malformed Docker URL/port errors become redacted capability diagnostics before any
daemon probe or resource creation.
Successful context inspection retains its raw stdout only for internal endpoint
parsing, preserving SSH user selection. Emitted diagnostics and failed captures
remain redacted.

The full collection inventory is checked in both directions: unlisted files,
directories and bytecode caches invalidate a generation. Wrapped Ansible consumers
set `PYTHONDONTWRITEBYTECODE=1`, so ordinary imports do not pollute managed trees.
The existing provider binding also applies to Docker access/readiness probes, which
reuse the validated client executable without applying its pin to the server.
`make env-check` remains a read-only audit; only `make qualify` orders bootstrap,
then the audit, then qualification, including under parallel Make execution.


## Reproducing installation, cache and integrity checks

These regression tests are source-controlled and run through the existing cumulative
`make qualify BASE=<immutable-base-sha>` and `make ci BASE=<immutable-base-sha>` gates.
They do not read session evidence archives or depend on a particular developer checkout.
The bootstrap supplies the pinned seed, tools and checksum-locked Galaxy archive closure;
a fresh machine needs access to those upstream artifacts for that initial acquisition.
No tool version is defined by these examples: the existing versions file, dependency
locks and image digests remain authoritative.

| Coverage | Versioned tests | Execution boundary |
| --- | --- | --- |
| Cold seed, warm reuse, corrupt seed repair, concurrent writers and active readers | `tests/test_seed_repair_real.py` | Real isolated Python environments; lock-pinned acquisition |
| Cold Docker client destination, damaged executable, warm inode reuse, failed candidate and concurrent repair | `tests/test_pr86_repairs_real.py::DockerClientRepairReal` | Real Ansible; temporary destinations; pinned Docker archive; no daemon changes |
| Offline Galaxy installation, repair, old readers and warm closure verification | `tests/test_pr86_repairs_real.py::CollectionsRepairReal` | Real pinned Ansible/Galaxy using the archive closure prepared by bootstrap |
| Cold archive transfer, warm/offline reuse, corrupt cache replacement, truncated or checksum-mismatched transfer | `tests/test_qualification_reproducibility.py::ArchiveAcquisitionTests` | Real loopback HTTP and filesystem; synthetic checksum-locked fixture; no upstream network |
| OS/architecture support matrix and WSL2/native/CI normalization | `tests/test_qualification_reproducibility.py::PlatformContractTests` | Simulated platforms, canonical capability contract; no host provisioning |
| Installed payload/inventory tampering, extra files, symlink boundaries and incomplete archives | `tests/test_pr86_five_active.py::CollectionIntegrityGenerationTests` | Temporary fixtures and real archive/content validation |
| Plaintext Docker refusal and secure-remote Ryuk restriction | `tests/test_pr86_security.py` | Preflight boundary; asserts no daemon calls |
| Direct Go invocation and actual `tc.host`/`docker.host` overrides | `TestQualificationRefusesUnsafeConfigurationInSubprocess` in the Product integration suite | Fresh test subprocesses, temporary HOME/properties, expected refusal before container creation |
| Product persistence, immutable images and owned cleanup | Product integration suite | Real local Docker, PostgreSQL and Ryuk; no remote daemon claim |

For a focused run after canonical bootstrap, use the qualification Python interpreter:

```console
.venv/qualification/bin/python -m unittest discover -s tests -p test_qualification_reproducibility.py
.venv/qualification/bin/python -m unittest discover -s tests -p 'test_*real.py'
```

The Product gate (`make service-check SERVICE=product`) runs both the Go subprocess
regressions and real local persistence tests. Platform simulations prove dispatch and
rejection behavior; they do not certify native execution on macOS, Windows or ARM64.
Published evidence remains a generated result outside Git; test logic and fixtures are
reproducible from the committed source.

### Testcontainers configuration boundary

Before creating any container, the Product fixture validates the effective cached
Testcontainers configuration from both environment variables and
`.testcontainers.properties`. It rejects privileged or disabled Ryuk and nonempty
`hub.image.name.prefix` values. These settings can bypass cleanup or substitute
an executable image before a post-start digest check can protect the host.
The pinned dependency and image digests remain unchanged. Fresh subprocess tests
cover each unsafe setting from both sources using a nonexistent local socket;
the normal local integration gate verifies that the safe configuration still runs.
