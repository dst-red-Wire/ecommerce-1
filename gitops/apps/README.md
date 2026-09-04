# Application bases

Each deployable service gets one reusable base in `gitops/apps/<service>`.
The Deployment uses the canonical image name, for example:

```yaml
image: ghcr.io/dst-red-wire/ecommerce-1/catalog
```

Each service owns three overlays and each overlay sets the immutable digest:

```text
gitops/apps/<service>/
├── base/
│   ├── deployment.yaml
│   └── kustomization.yaml
└── overlays/
    ├── integration/kustomization.yaml
    ├── preproduction/kustomization.yaml
    └── production/kustomization.yaml
```

```yaml
images:
  - name: ghcr.io/dst-red-wire/ecommerce-1/catalog
    newName: ghcr.io/dst-red-wire/ecommerce-1/catalog
    digest: sha256:<digest-returned-by-ghcr>
```

No placeholder digest is committed. A service is added only after its source,
Dockerfile, probes, resources, security context and tests exist.

The corresponding cluster `kustomization.yaml` must list the service overlay
as a resource. `scripts/validate-gitops-images.sh` rejects an overlay digest
unless its `images[].name` is referenced by an actual base workload and the
cluster includes that exact overlay. With no business service in this
repository yet, application validation is explicitly reported as skipped.
