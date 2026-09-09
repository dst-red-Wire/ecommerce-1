# SECURITY TRUST ZONES V2 — EXACT

Status: `EXACT`

Machine authority: `config/contracts/security-trust-zones.yaml`, resolved through
`architecture.lock.yaml.machine_contracts.security_trust_zones`. The machine contract maps every active deployment
component and all 19 canonical services to exactly one trust zone; this document describes the corresponding controls.

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

Exactly 19 Go backend services, including `checkout` and `fulfillment`, plus Storefront/Admin workloads and the customer-facing Keycloak runtime endpoint.

Keycloak is placed in Z3 because its `customers` realm is part of the application authentication path. This placement does not expose Keycloak administration to customers: admin and workforce-management endpoints remain reachable only from approved Z5/MGMT identities through explicit Z2 service-mesh policy.

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

PostgreSQL/CNPG (including lakeFS/MLflow metadata), Kafka, RabbitMQ, Redis, OpenSearch Business, SeaweedFS, Apicurio, VictoriaMetrics, VictoriaLogs, ClickHouse, MongoDB (HyperDX metadata only), OpenSearch Security.

Controls:
- reachable only from approved workload/platform identities;
- no public ingress;
- encryption in transit;
- storage access constrained to owning nodes/operators;
- backups isolated from source failure domain;
- stateful admin interfaces restricted to operator/MGMT paths.

### Z5 — Permanent MGMT

Gitea, Harbor, Rancher/Fleet management, Tekton control integrations, OpenBao administrative plane, NetBox, Grafana administrative plane, Terraform state backend, Backstage and supporting control services. Keycloak administration and workforce-management access originate from this zone, but the customer authentication endpoint itself is not a Z5 subject.

Controls:
- workforce IAM only;
- privileged accounts require hardware-backed WebAuthn/passkeys;
- no customer identity access path to MGMT administrative APIs;
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

- Keycloak `customers` realm: customer identities served through the approved application ingress path to the Z3 Keycloak runtime.
- Keycloak `workforce` realm: staff/operators.
- privileged workforce flows require WebAuthn/passkeys backed by hardware keys.
- Keycloak admin/workforce-management endpoints accept only approved Z5/MGMT identities and are not exposed on the customer route.
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