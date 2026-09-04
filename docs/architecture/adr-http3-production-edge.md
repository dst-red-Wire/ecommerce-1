# ADR — Production HTTP/3 / QUIC edge

Statut : **ACCEPTED / NOT_PROVEN_RUNTIME**

Date : 2026-08-21

La source canonique est [`governance/controls.yaml`](../../governance/controls.yaml),
contrôles `H3-001`, `H3-002` et `H3-003`.

## Décision

```text
Internet client
  -> Caddy public edge: HTTP/3 over QUIC when supported
  -> Istio / internal platform
  -> services
```

`H3_REQUIRED_FOR_PRODUCTION_EDGE = true`. Caddy reste le public edge prévu.
HTTP/2 fallback est obligatoire ; HTTP/1.1 fallback est obligatoire lorsque la
compatibilité l'exige. Le réseau production doit gouverner explicitement
UDP/443 pour QUIC tout en maintenant TCP/443. Ce milestone n'ouvre aucun port.

HTTP/3 n'est pas imposé east-west. Istio/mTLS et workload identity restent
prioritaires en interne ; toute adoption H3 interne exige une validation
runtime-first séparée.

## 0-RTT

`ZERO_RTT_POLICY = DISABLED_BY_DEFAULT`. Aucun 0-RTT pour `POST`, `PUT`,
`PATCH`, `DELETE`, checkout, payment, refund, authentication ou admin action.
Une future exception exige un threat model spécifique, une idempotence prouvée
et une mitigation du replay. Rien ne l'active ici.

## Gate de preuve future

La promotion vers `PROVEN_RUNTIME` exige sur un endpoint production-like :

1. HTTPS normal et certificat/hostname valides ;
2. TLS `1.3` et négociation `curl --http3-only` réussie ;
3. UDP/443 reachable et Alt-Svc correct lorsqu'utilisé ;
4. HTTP/2 fallback réussi, puis HTTP/1.1 si attendu ;
5. logs/metrics indiquant h1/h2/h3 ;
6. mêmes authn/authz, rate limits, headers et contrôles sécurité sur H3 ;
7. preuve qu'un changement de protocole ne contourne ni WAF ni policy ;
8. evidence sanitized et Independent Reviewer.

Le [harness](../../scripts/test-http3.sh) couvre h3-only, H2, TLS et quelques
préconditions sans cible implicite ni mutation. Il ne suffit pas seul à prouver
les points observabilité/WAF/policy. Le statut reste donc
`HTTP/3 production edge = NOT_PROVEN_RUNTIME`.
