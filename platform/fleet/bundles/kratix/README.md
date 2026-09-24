# Kratix OSS Fleet bundle

This M4 bundle composes Kratix with Kustomize from upstream commit `d50cebceb33defc1f6b9882a009bb1436f0aa3f4` and replaces both controller and pipeline-adapter references with OCI index digest `sha256:0810b20ca820c627ce176c58798c41c9858b85917daeb474f904348cc41ce0e7`.

The generated state path is deliberately separate from this source repository:

`Developer Portal -> Kratix Promise/API -> Gitea GitStateStore -> Fleet -> RKE2 destinations`

Fleet maps independent generated paths to cluster labels:

- `destinations/lab/*` -> RKE2 LAB (`VirtualBox` is the local example substrate);
- `destinations/preprod/*` -> canonical RKE2 PREPROD;
- `destinations/prod/*` -> canonical RKE2 PROD-A and PROD-B clusters labelled `environment=prod`.

Kratix writes with `kratix-gitea-writer`; Fleet reads with `kratix-gitea-reader` from `fleet-default`. Both Secrets are runtime-only OpenBao/ESO outputs and are not defined here. The writer cannot administer Gitea and the reader cannot write. SSH host-key verification is mandatory.

Fleet remains the only GitOps/CD authority. The Kratix quick-start is not used because it installs Flux and a bundled object store. Helm is the governed Promise/chart package format; its version comes from the repository toolchain lock.

This bundle is `CONTRACTED` and intentionally `paused: true`, not runtime-proven. The pinned upstream image is currently blocked by the repository CVE policy because `CVE-2026-93990` affects `libexpat 2.8.4-r0` and a `2.8.5-r0` fix exists. No automatic exception is allowed. A reviewed PR must replace the digest with an upstream or governed rebuild that passes the current policy before unpausing.

M4 activation also requires ready Gitea, Fleet, cert-manager, OpenBao/ESO, a pre-provisioned `platform/kratix-state` repository, runtime credentials, and a Harbor mirror that preserves the replacement digest.
