# Qualification tool and cache reuse

`make qualify BASE=<immutable-base>` is the canonical local entry point. It computes the
static capability plan, prepares missing pinned prerequisites, audits the resolved tools,
and only then executes qualification. Tool/cache reuse never reuses a PASS verdict: the
normal exact base/head and signed-evidence rules remain in force.

## Persistent identities

`ECOMMERCE_TOOL_HOME` defaults to `~/.cache/ecommerce-1/qualification` and may point to a
runner-owned persistent volume outside every checkout. The Python seed identity includes
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
`$ECOMMERCE_TOOL_HOME/ansible/collections/<requirements-sha256>` and installation is
serialized by that identity, so checkouts with equal locks reuse the same collection tree.

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
