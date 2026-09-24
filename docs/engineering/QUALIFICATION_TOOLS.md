# Qualification toolchain

Status: `EXACT STATIC CONTRACT`; runtime results remain evidence-bound.

`architecture.lock.yaml` registers the subordinate contract
`config/contracts/qualification-tools.yaml`. Exact versions, official sources,
artifact hashes and lifecycle state exist only in
`config/contracts/toolchain-lock.json`; the qualification contract references
that authority and does not duplicate pins.

## Ownership and placement

| Tool | Owner | Placement | Gate/result boundary |
| --- | --- | --- | --- |
| OpenSCAP + SCAP Security Guide | platform security | Rocky 10.2 RKE2 image | Explicit CIS Server L1 profile; a node runtime evaluation is required for PASS. |
| kube-bench | platform security | Rocky 10.2 RKE2 image | The pinned release lacks the RKE2 CIS 1.12 profile required by Kubernetes 1.37, so runtime qualification is `BLOCK`. |
| OPA + Conftest | repository governance | controller tool cache | Shared Rego policy; valid, denied and invalid fixtures are mandatory. |
| k6 | performance engineering | controller tool cache | One-VU/one-iteration loopback smoke uses the central normal SLO; baseline, load and stress require an authorized campaign. |
| Nuclei | application security | controller tool cache | Loopback or contracted lab targets only; automatic updates, Interactsh, unsafe and destructive templates are forbidden. |
| Hubble | network platform | controller tool cache | Assertions require a qualified multi-node Cilium runtime. CLI 1.19.4 compatibility with locked Cilium 1.20.1 is unverified, so runtime qualification is `BLOCK`. |
| Pint | observability platform | controller tool cache | Mandatory when Prometheus rule inputs exist. The current repository has no such rules, so only availability and controlled fixtures are qualified. |

Node-side OpenSCAP content is sourced from the signed, locked Rocky RPM graph.
Every other downloaded archive or binary has an exact SHA-256. OpenTofu adds
authenticated release-manifest verification through the official OpenPGP
signature, exact key artifact hash and pinned primary-key fingerprint. Online
reconciliation populates the cache; setting
`ECOMMERCE_TOOL_OFFLINE=1` makes missing or mismatched cache inputs fail closed.

## Deterministic checks

Use these public entry points:

```text
make qualification-tools
make qualification-tools-smoke
make opentofu
```

`qualification-tools` validates authority, ownership, inputs, policies, output
contracts and bounded evidence parsers without requiring a runtime cluster.
`qualification-tools-smoke` installs the exact controller tools and exercises
OPA/Conftest, Pint, k6 and Nuclei against repository fixtures and a temporary
loopback HTTP endpoint. It records evidence below ignored `.context/evidence`.

OpenSCAP, kube-bench and Hubble never receive a static PASS. Their parsers
distinguish invalid evidence, blocking findings, non-proving results and
unsupported compatibility. Runtime scans must name the target and tool version
and remain `BLOCK` until the contract's exact environment and assertions are
available.

The historical HCL identifiers `terraform {}`, `.terraform/`,
`.terraform.lock.hcl`, `terraform_remote_state` and applicable `TF_*` variables
remain OpenTofu-compatible syntax. They do not authorize the Terraform CLI.
The sole IaC executable is `tofu`; repository governance rejects a second active
IaC engine or a `terraform` command capability.
