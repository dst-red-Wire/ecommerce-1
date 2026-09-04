# SECURITY TRUST ZONES V2 — EXACT

Status: `EXACT`

## Zones

### Z0 — Internet / untrusted

Clients, public networks and external providers. No implicit trust.

### Z1 — Public Edge / DMZ

Components: HAProxy, Caddy, Coraza, ATS public-facing paths, Kong edge-facing ingress, public DNS roles.

Controls:
- TLS termination only at approved points;
- WAF/Coraza policies;
- rate limiting;
- no direct database access;
- no secret-management administrative endpoints;
- minimal inbound ports;
- audited egress.

### Z2 — Kubernetes ingress / service mesh

Components: Istio Gateway, mesh sidecars/ambient components as approved, service endpoints.

Controls:
- Istio mTLS STRICT;
- SPIFFE identities;
- default-deny Cilium policies;
- explicit service-to-service authorization;
- no direct public exposure of internal services.

### Z3 — Application workloads

17 Go services + Storefront/Admin workloads.

Controls:
- Pod Security `restricted`;
- non-root containers;
- read-only root filesystem where feasible;
- seccomp/default profile;
- resource requests/limits;
- NetworkPolicy default deny;
- service account least privilege;
- secrets only via OpenBao/ESO-approved paths.

### Z4 — Stateful data

PostgreSQL/CNPG, Kafka, RabbitMQ, Redis, OpenSearch, SeaweedFS, Apicurio.

Controls:
- reachable only from approved workload/platform identities;
- no public ingress;
- encryption in transit;
- storage access constrained to owning nodes/operators;
- backups isolated from source failure domain;
- stateful admin interfaces restricted to operator/MGMT paths.

### Z5 — Permanent MGMT

Gitea, Harbor, Rancher/Fleet management, Tekton control integrations, OpenBao administrative plane, NetBox, Grafana administrative plane, Terraform state backend, Backstage and supporting control services.

Controls:
- workforce IAM only;
- privileged accounts require hardware-backed WebAuthn/passkeys;
- no customer identity access path;
- administrative access via controlled WireGuard/management network;
- audited privileged actions;
- break-glass separately controlled.

### Z6 — Backup / evidence / DFIR

Immutable/object evidence and backups, external copies and forensic archives.

Controls:
- write identities separate from delete/admin identities;
- Object Lock/immutability where policy requires;
- evidence references include release/environment/test identity;
- compromise response may delay normal JIT teardown until evidence acquisition is complete.

## Human IAM separation

- Keycloak `customers` realm: customer identities.
- Keycloak `workforce` realm: staff/operators.
- privileged workforce flows require WebAuthn/passkeys backed by hardware keys.
- no customer token is accepted for MGMT administrative APIs.

## Workload identity

SPIRE trust domains remain environment-specific:

- PREPROD
- PROD-A
- PROD-B

Cross-environment workload identity is denied by default. Any federation requires explicit architecture/security review.

## Secret flow

`OpenBao -> ESO -> Kubernetes Secret/runtime mount` where applicable.

Forbidden:
- secrets in Git;
- secrets in image layers;
- secrets in CI logs;
- long-lived bootstrap credentials left active after PREPROD destroy;
- application access to OpenBao administrative credentials.

## Egress

Default deny. External application egress uses approved Istio Egress/Squid path with logging and documented exception. Payment, carrier, e-invoicing and notification providers receive explicit destination policies.

## Compromise boundary

For reproducible compromised nodes/workloads:

`isolate -> acquire evidence -> destroy -> rebuild via GitOps/IaC`.

No manual cleaning is considered restoration of trust unless a specialized forensic requirement explicitly dictates otherwise.
