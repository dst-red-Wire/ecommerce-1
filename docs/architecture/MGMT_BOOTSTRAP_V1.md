# Persistent MGMT bootstrap V1

Status: `EXACT`

This document derives from `architecture.lock.yaml` V5 and the machine-readable
`config/infrastructure/mgmt-bootstrap.yaml`. It records implementation readiness,
not evidence that infrastructure or software is deployed, proven, or runtime
qualified.

## Boundary and ownership

M2.5 is unlocked by M1 alone. It creates no M3 PREPROD resources and does not
activate M4. Terraform/OpenTofu owns one Hetzner Network, its six contract-derived
subnets, seven servers (three RKE2 servers, three agents, and the dedicated
WireGuard gateway), private attachments, and two provider firewalls. Node names,
addresses, profiles, and segments are decoded directly from the canonical YAML.
Provider server-type and Rocky Linux 10.2 image mappings remain explicit reviewed
runtime inputs because provider SKUs cannot be inferred from resource intent.

Terraform does not install packages, render RKE2 configuration, configure
systemd, or install Kubernetes software. Packer owns the common Rocky Linux 10.2
prerequisites; Ansible owns runtime machine identity and configuration,
private address aliases, the WireGuard host, and pinned RKE2 server/agent setup.
The RKE2 token remains a runtime secret input. WireGuard has two deliberately
separate phases: first bootstrap generates a temporary key locally on `wg-01`
and accepts only identity-associated peer public keys at runtime; steady state
uses Ansible runtime reads from OpenBao. Kubernetes/Fleet owns later platform
activation.

## Access and trust boundary

The six RKE2 nodes have provider public networking disabled. The dedicated
`wg-01` Z5 gateway is the only public transport. During bootstrap only, a human
may enable TCP/22 for explicit runtime source CIDRs (never `0.0.0.0/0` or
`::/0`); Ansible then reaches private RKE2 addresses through a controlled
ProxyJump. The rule is disabled by default and its removal after WireGuard proof
is mandatory. In steady state provider ingress admits only the canonical
WireGuard UDP port and public SSH is forbidden. Internal-node SSH is limited to
the canonical management segment. Host routing and exact scoped SNAT remain
Ansible-owned, default forwarding is denied by contract,
and operator/break-glass peer issuance remains a separately authorized runtime
ceremony. No operator CIDR is invented by Terraform.

Management, Kubernetes, storage, and backup addresses remain distinct canonical
segments. Hetzner realizes them as subnets in one private Network and reserves
non-primary addresses as server aliases; Ansible persistently reconciles those
aliases. This provider constraint does not collapse their trust or traffic-policy
ownership.

## Non-circular state transition

The same non-circular rule applies to WireGuard authority. The bootstrap key is
generated cryptographically on `wg-01`, stays root-owned mode `0600`, and never
returns to Terraform, inventory, Git, or controller output. After M4 performs a
governed OpenBao activation, it must establish persistent records, rotate to a
new OpenBao-controlled gateway key (copying the bootstrap key is forbidden),
switch Ansible to `runtime-openbao-read`, delete the bootstrap key and peer
staging, and remove temporary SSH. M2.5 models and automates readiness for this
transition; it does not initialize or read/write a real OpenBao instance.

1. A human authorizes first provisioning using local state on an encrypted,
   operator-controlled workstation. State, plans, and credentials are forbidden
   from Git. This boundary cannot depend on MGMT services.
2. The resulting MGMT runtime is qualified far enough to activate the governed
   SeaweedFS S3 state target and its independent locking/credential controls.
3. A human reviews a state backup and migration plan, initializes the persistent
   backend configuration, migrates state, and verifies identical resource
   identity. No migration occurs in M2.5 static qualification.
4. Only after verification is bootstrap state retired under the evidence and
   rollback policy. Failure rolls back to the encrypted bootstrap copy; it never
   triggers an automated destroy.

The dependency direction is therefore bootstrap state -> provider MGMT ->
persistent backend -> reviewed migration. MGMT never requires its own unavailable
backend for first creation.

## Platform bootstrap order

After real RKE2 qualification, M4 may activate the pinned sequence recorded in
the machine contract: Cilium, Tetragon foundation, OpenBao initialization
ceremony, ESO, Gitea, Harbor, Rancher/Fleet, and Tekton. Gitea and Harbor require
persistent storage, runtime secret references, probes, and Z5-only exposure.
Harbor enforces immutable-image ownership and forms the future Tekton/BuildKit
push-by-digest boundary. Fleet—not Flux or Argo CD—is GitOps authority; Tekton—not
Woodpecker—is CI authority. OpenBao contains no fake initialized state, unseal
key, or root token, and ESO starts only after scoped OpenBao authentication exists.
Tetragon enforcement remains unproven until the deferred runtime window.

## Lifecycle, cost, and evidence

The static declaration is seven persistent servers, one network, six subnets,
two firewalls, no volumes, no load balancers, and no floating IPs. Only the
gateway requires provider public IPv4/IPv6; servers and public addresses are
potentially billable, but no price is fabricated without provider evidence.

No apply, destroy, Kubernetes mutation, Helm installation, DNS mutation, or
remote Ansible execution is authorized by this milestone. A future provisioning
run requires the architecture human gate, explicit provider mappings, runtime
secrets, reviewed non-mutating plan, and evidence capture. Rollback before apply
is configuration reversion; rollback after an authorized future apply follows
the reverse deployment DAG and preserves evidence before resource deletion.

## Consolidation security corrections and remaining readiness blocker

Static qualification does not authorize provisioning. The offline path below
addresses the missing installation transport from finding #80 4003692249. A real
six-node installation remains unvalidated until targets, approved artifact bundle,
internal DNS/NTP and a separate provisioning gate exist. Local container evidence
must not be reported as proof of six Rocky machines or a running RKE2 cluster.

WireGuard runtime peer records require a canonical 32-byte base64 `public_key`, a
unique `identity`, and one unique `/32` `allowed_ip` inside the workforce pool.
`scope: break-glass` additionally requires separate runtime authorization and its
own canonical pool. Private key records receive the same strict base64 validation;
newlines and configuration directives fail before rendering. This is input
validation, not a substitute for workforce issuance authorization.

The dedicated firewalld policy persists MGMT-only forwarding and bounded pre-SNAT
flow logging across reloads. `WGMG-FLOW` records retain peer source, destination and
ports; `wg-peer-map` journal events preserve identity/public-key/address correlation
when assignments change. Logging is rate limited and is not an exhaustive packet
capture. Persistent local journal retention is bounded to 200 MiB and 30 days;
central delivery follows the canonical infrastructure telemetry pipeline.

After OpenBao activation, the bootstrap phase cannot be re-entered. A transition
flushes firewall and service handlers, verifies the live replacement public key,
and waits up to five minutes for a newly authenticated configured peer handshake
before recording authority and deleting temporary material. The operator must
connect with the rotated gateway key during that window. Failure preserves the
bootstrap key and peer staging for investigation; it never declares the transition
complete. No runtime transition or deployment was performed by static qualification.

The persistent policy uses the upstream [firewalld policy schema](https://firewalld.org/documentation/man-pages/firewalld.policy.html).

## Offline installation without a bootstrap dependency cycle

An independently approved directory on the Ansible controller is the bootstrap
source. It exists before Kubernetes and transfers over the already governed SSH
transport. The six nodes do not download from Internet repositories. This avoids
creating a new infrastructure domain and requires neither cluster-hosted Harbor
nor Istio Egress Gateway. No proxy or WireGuard Internet NAT is introduced.

The connected preparation machine gathers the canonical RKE2 version's native
binary, core image archive and Cilium image archive, plus the complete Rocky 10.2
RPM dependency closure. `scripts/mgmt_airgap.py` defines the mandatory package
inventory (`REQUIRED_RPMS` and mutually exclusive `RPM_VARIANTS`), including host tools, firewalld/nftables, kernel module tools and SELinux
policies. Rocky minimal curl/coreutils providers are retained where compatible; conflicting
full/minimal alternatives are rejected before installation, without allowing
removal of protected packages. Every RPM record includes NEVRA, SHA256 and its manifest-bound signing
key; every binary/archive includes SHA256. Archives also expose pinned image
identities. Include all dependencies even when installed on the preparation host;
a successful connected `dnf download --resolve --alldeps` is only preparation,
and an actual offline transaction on a fresh target verifies dependency closure.
The manifest must be reviewed and its digest supplied independently of the bundle.
A manifest self-declaring a complete closure is insufficient installation evidence.

Required runtime inputs are `mgmt_offline_bundle_dir`,
`mgmt_offline_manifest_sha256`, `mgmt_internal_dns`, and `mgmt_internal_ntp`.
The repository supplies no available service endpoints for those last two values.
Addresses in the network plan describe intended topology, not availability checks.
DNS and NTP are internal IPv4 addresses and must be verified on the real target.

Ansible validates the source before transfer and validates bytes again on each
node. Package transactions use only supplied local RPMs with every repository
disabled and signature checks enabled. Missing, tampered or unsafe artifacts fail
before installation. The native RKE2 binary is copied directly; no remote install
script runs. Core and Cilium images are preloaded from verified archives, SELinux
remains enabled, and registry default-endpoint fallback is disabled.

The network role installs a persistent, owned nftables table with DROP policies
for both IPv4 and IPv6 output and forwarding. It allows canonical private cluster
CIDRs, internal DNS/NTP, DHCP renewal and replies to incoming management traffic.
Only that owned table is reconciled. RKE2 depends on successful egress enforcement.
A persistent dummy interface provides the RKE2-required default route through an
unreachable TEST-NET peer; it supplies no Internet forwarding. This follows the
upstream [RKE2 offline installation requirements](https://docs.rke2.io/install/airgap).

Local Docker Desktop testing uses an immutable Rocky image, a fresh target root
filesystem, an explicit `--network none` boundary, and copied artifacts. It can
verify hashes, archive safety, RPM dependency installation, native binary version,
missing-artifact failure and absence of target downloads. It does not validate
Hetzner networking, real node kernel modules, systemd startup ordering, SELinux
enforcement, Cilium, multi-node quorum, internal DNS/NTP availability or the full
six-node installation. Those remain real-target acceptance checks carried by #101.
