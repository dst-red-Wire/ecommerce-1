# Repository-local yq and oasdiff

Pinned `yq` and `oasdiff` executables live in `.tools/bin` for each checkout.
`config/toolchain/versions.env` is the version and checksum authority, and
`scripts/repository_tools.py` verifies both cached release artifacts and installed
binaries before reuse.

Use `make tools`, or the narrower `make tools-yq` and `make tools-oasdiff`, to
reconcile them. Stateful workstation bootstrap delegates to the same provisioner;
it does not install a competing home-directory copy. The `context`, `nx-graph`,
`contracts`, and `ci` targets reconcile their required tool first. Direct
`scripts/repoctl.py` calls prepend the current checkout's `.tools/bin`, including
inside isolated Tekton workspaces.

Audit commands remain observational: provisioning occurs only through explicit
tool targets or through targets whose operation requires the pinned executable.
To roll back, revert this migration and reconcile the prior Ansible-managed paths.
