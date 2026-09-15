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
atomic local reference to that immutable environment; the venv is created directly at its
final path because virtual environments contain absolute paths.

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
and testcontainers-go. An explicit `DOCKER_HOST` remains authoritative. For a remote
daemon, `TESTCONTAINERS_HOST_OVERRIDE` must identify the address at which the test
process can reach published ports; it is derived only for a non-loopback TCP hostname.
This avoids treating the client namespace's forwarding sysctl as evidence about a
remote server. TLS variables from the selected context are propagated rather than
disabled.

Before Go downloads or compilation, the gate requires a real server response. It then
uses the pinned PostgreSQL image to prove pull/reuse, container start, a labelled volume,
and published-port reachability. Cleanup addresses only the unique labelled container
and volume from that invocation and verifies they are absent. The Product integration
test subsequently runs uncached with the race detector and uses the pinned Ryuk image;
Ryuk, TLS, integrity checks, and Testcontainers cleanup remain enabled.

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
