# Persistent MGMT bootstrap V1

Status: `STATIC READY FOR REAL PROVISIONING`

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
Provider server-type and Rocky Linux 9 image mappings remain explicit reviewed
runtime inputs because provider SKUs cannot be inferred from resource intent.

Terraform does not install packages, render RKE2 configuration, configure
systemd, or install Kubernetes software. Ansible owns Rocky Linux 9 prerequisites,
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
