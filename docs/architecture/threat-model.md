# Threat model global ecommerce-1

Ce modèle initial applique `ARCH-002` depuis
[`governance/controls.yaml`](../../governance/controls.yaml). Statut :
`DOCUMENTED / NOT_PROVEN_RUNTIME`. Il priorise les risques ; il ne prétend pas
que toutes les mitigations sont déjà implémentées.

## Assets, actors et entry points

- Assets `RESTRICTED` : identities, sessions, PII, orders, payment/PSP tokens,
  credentials, signing identity, source et deployment provenance.
- Assets `CONFIDENTIAL` : inventory internals, fraud signals, logs, backups,
  infrastructure state et configuration management.
- Actors : Internet client, customer, admin/back-office, developer, operator,
  workloads, PSP/webhook provider, cloud API et adversaire externe/interne.
- Entry points : Caddy public edge, APIs, auth flows, admin UI, uploads,
  webhooks, messaging, Git, Tekton, Harbor/GHCR, Flux, Kubernetes, cloud APIs,
  SSH/break-glass et secret delivery.

## Trust boundaries et data flows

| Boundary | Flow | Contrôles attendus | État |
|---|---|---|---|
| Internet → Caddy | HTTPS h1/h2, target h3/QUIC | TLS, rate limit, protocol parity, headers | H3 `NOT_PROVEN_RUNTIME` |
| Caddy → Istio/API Gateway | authenticated request context | mTLS, workload identity, OPA | `PLANNED / NOT_PROVEN_RUNTIME` |
| User/admin → Keycloak | credentials, tokens, sessions | MFA/admin policy, session security, audit | `NOT_PROVEN_RUNTIME` |
| Services → RabbitMQ/Kafka | commands/events/outbox | authz, integrity, idempotence, bounded retry, DLQ | `PLANNED` |
| Services → PostgreSQL/MongoDB/Redis/object storage | business/state data | private network, least privilege, encryption, backup | partiellement prouvé selon registre |
| Developer → Git/Tekton | source and build request | review, immutable revision, isolated identity | statique, runtime à prouver |
| Tekton → registry → GitOps → Flux | artifact, digest, proof | scan, SBOM, provenance, signature verification | statique, crypto runtime non prouvé |
| Management plane → Kubernetes/cloud APIs | infrastructure change | separate identity, plan/review/human gate | backend `NOT_MIGRATED` |
| Secret store/env → workloads | credentials/keys | hors Git/logs, rotation, per-environment | runtime futur |

## STRIDE et abuse cases

| ID | Menace / STRIDE | Risque | Mitigations ciblées | Risque résiduel / preuve |
|---|---|---|---|---|
| TM-01 | account takeover, credential stuffing, session theft — S/I/E | CRITICAL | Keycloak, MFA admin, rate limit, session rotation, audit | `NOT_PROVEN_RUNTIME` |
| TM-02 | IDOR/BOLA, privilege escalation, admin abuse — E/R | CRITICAL | object-level authz, OPA, least privilege, admin audit | tests ASVS et runtime manquants |
| TM-03 | price/cart/order tampering, promotion/coupon abuse — T | CRITICAL | server-side price authority, invariants, signed/audited commands | service designs encore `PLANNED` |
| TM-04 | payment replay, webhook spoofing, refund abuse, fraud-rule bypass — S/T/R | CRITICAL | provider signature, timestamp/nonce, idempotency key, separation of duties | PSP design et probes manquants |
| TM-05 | inventory manipulation, duplicate/replayed events, event tampering — T/R | HIGH | transactional Outbox, message authz, dedupe, bounded retry, DLQ | broker choisi par contexte, runtime non prouvé |
| TM-06 | SSRF, injection, XSS, CSRF — S/T/I | CRITICAL | allowlists, parameterization, contextual encoding, CSRF protection where relevant | application tests futurs |
| TM-07 | file upload abuse — T/I/D | HIGH | type/size validation, isolated scan/storage, no execution | workflow futur |
| TM-08 | PII exfiltration, secret leakage — I | CRITICAL | minimization, classification, encryption, Gitleaks, log redaction, egress control | runtime egress/log coverage non prouvée |
| TM-09 | supply-chain compromise, CI compromise, registry poisoning — S/T/E | CRITICAL | immutable source/digest, isolation, SBOM, provenance, signing and verification | SLSA/signature runtime non prouvés |
| TM-10 | lateral movement — E/I | CRITICAL | mTLS, workload identity, default-deny, environment isolation | mesh/network runtime non prouvé |
| TM-11 | denial of service h1/h2/h3, APIs, broker or databases — D | HIGH | rate limit, quotas, backpressure, resources, fallback observability | load/failure tests requis |
| TM-12 | repudiation of admin, deployment or break-glass action — R | HIGH | structured audit, correlation, commit/digest/provenance binding | retention et alerting TBD |

## Risques de composants explicitement couverts

Le scope comprend browser/mobile, Caddy, Istio, API Gateway, Keycloak, OPA,
admin/back-office, microservices, messaging, PostgreSQL, MongoDB, Redis, object
storage, Git source, Tekton, Harbor/GHCR, Flux, Kubernetes, management plane,
cloud APIs, secret store/env et developer/control node.

## Acceptance criteria globaux

- Aucun endpoint public implicite, database publique ou secret en clair.
- Authz objet et métier testée pour chaque nouvelle API.
- Idempotence/replay testés sur checkout, payment, refund, webhook et messages.
- Image production liée par digest au scan, SBOM, provenance et signature.
- Restore, failure, audit et protocol visibility prouvés en production-like.
- Tout residual risk non traité passe par `COMP-002` avec expiry.

La prochaine revue doit être déclenchée par le premier microservice significatif,
le choix messaging, l'intégration PSP, l'activation du management backend ou le
premier test H3 production-like.
