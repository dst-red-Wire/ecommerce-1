# Supply-chain secret contracts

No credential or private key is stored in this repository. The following
Kubernetes Secrets must be provisioned out of band before a PipelineRun or
Tekton Chains installation is authorized.

## GHCR push

- Namespace: `tekton-ci`
- Name: `ghcr-push`
- Type: `kubernetes.io/dockerconfigjson`
- Annotation: `tekton.dev/docker-0: https://ghcr.io`
- Attached ServiceAccount: `tekton-image-push` only
- Minimum capability: publish packages under
  `ghcr.io/dst-red-wire/ecommerce-1/*`

For a self-hosted Tekton worker, GitHub currently requires an appropriate GHCR
token for package publication. It must be delivered through the secret manager
or Ansible Vault workflow, never a manifest or shell script in Git.

## GHCR CI/image scan pull

- Namespace: `tekton-ci`
- Name: `ghcr-pull`
- Type: `kubernetes.io/dockerconfigjson`
- Attached ServiceAccount: `tekton-image-read` only
- Capability: package read only

This credential is distinct from `ghcr-push`. Source clone, tests, source
scanners, evidence binding and Git promotion receive neither one.

## GHCR application runtime pull

Packages are private by default. A public package requires explicit review and
no pull Secret. A private package receives a namespace-scoped, read-only
`ghcr-pull` Secret attached to the service-specific application ServiceAccount;
that ServiceAccount disables Kubernetes API token automount. Runtime pull
credentials are never copied from `tekton-ci` and never grant package write.
Rotate CI push, CI pull and runtime pull credentials independently, with a
bounded overlap and a named owner. The declarative mapping is
`contracts/supply-chain/ghcr-repositories.json` and contains no credential.

## Git desired-state write

- Namespace: `tekton-ci`
- Name: `github-git-write`
- Type: `Opaque`
- Required key: `.git-credentials`
- Mount as the `git-auth` Secret workspace only for the promotion PipelineRun.

A GitHub App installation token with repository Contents write permission is
preferred. If a token is used, scope it to this repository and protect the
target branches so the task proposes a reviewed change instead of bypassing
approvals.

## Chains signing

- Namespace: `tekton-chains`
- Name: `signing-secrets`
- Integration option: encrypted Cosign/x509 key material provisioned out of
  band and rotated.
- Production option: KMS reference, preferably backed by the selected secrets
  platform.

## Chains GHCR provenance publication

- Namespace: `tekton-chains`
- Name: `chains-ghcr-write`
- Type: `kubernetes.io/dockerconfigjson`
- Attached ServiceAccount: `tekton-chains-controller` only
- Capability: publish provenance referrers under the project GHCR scope

This controller credential is distinct from `ghcr-push` and is never mounted
into tests, scans, evidence creation, or promotion verification. Its repository
contract is `platform/tekton/chains/registry-secret.contract.yaml`.

Missing any required secret is a hard stop. Do not create placeholder values,
run the build pipeline, or enable Chains signing until the contract is met.

## Promotion trust root

`promotion-trust-root` is a ConfigMap contract, not a Secret. It must contain
the final attestor public key as `cosign.pub` plus byte-exact copies of
`promotion-proof.schema.json` and `delivery-evidence.schema.json`. Their
SHA-256 values are pinned by the contract and verifier Task. Admission fixes
the `trust` workspace to that ConfigMap and `git-auth` to
`github-git-write`; callers may not provide their own key or schema. No real
trust root is committed in this pass, so promotion remains `NOT PROVEN`.
