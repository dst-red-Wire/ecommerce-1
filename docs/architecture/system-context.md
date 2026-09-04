# System context et trust boundaries

Les contrôles structurants sont dans
[`governance/controls.yaml`](../../governance/controls.yaml). Cette vue applique
`SEC-002`, `IAM-001`, `NET-001`, `ARCH-003` et `SUPPLY-005`.

```mermaid
flowchart LR
  U[Internet client\nbrowser/mobile] -->|HTTPS h1/h2 + target h3 UDP/443| C[Caddy edge]
  C --> I[Istio ingress / mesh]
  I --> G[API Gateway]
  G --> K[Keycloak]
  G --> O[OPA]
  G --> S[Microservices\nCQRS command/query]
  A[Admin / back-office] --> C
  S --> M[RabbitMQ or Kafka\ndecision by context]
  S --> P[(PostgreSQL)]
  S --> N[(MongoDB)]
  S --> R[(Redis)]
  S --> B[(Object storage)]

  subgraph Delivery[CI/CD supply-chain boundary]
    D[Developer / control node] --> V[Git source\nGitHub current / Gitea target context]
    V --> T[Tekton]
    T --> H[OCI registry\nGHCR current / Harbor management target]
    T --> E[SBOM + provenance + signature evidence]
    H --> F[GitOps digest]
    F --> X[Flux]
  end
  X --> S

  subgraph Management[Management plane boundary]
    MG[Management services] --> CP[Cloud APIs]
    MG --> KS[Kubernetes / platform APIs]
    SS[SOPS + age / runtime secret delivery] --> MG
  end
```

## Frontières

1. Internet vers Caddy : entrée non fiable, TLS obligatoire, HTTP/3 cible mais
   `NOT_PROVEN_RUNTIME`; aucun bypass de rate limit ou policy par protocole.
2. Edge vers mesh : identity service et mTLS futurs à prouver ; H3 n'est pas
   imposé east-west.
3. User/admin vers Keycloak/OPA : authn et authz séparées ; admin abuse fait
   partie du threat model.
4. Services vers state/messaging : credentials minimaux, réseau non public,
   transactions CQRS + Outbox et consumers idempotents avec retry borné/DLQ.
5. Source vers build/registry/GitOps : commit, snapshot, digest, SBOM, provenance
   et signature doivent rester liés ; Flux déploie uniquement le digest Git.
6. Management vers cloud/platform : séparation de credentials et human gates.
   Le Management backend reste `NOT_MIGRATED`.
7. Secrets : le contrat local reste hors dépôt/OneDrive ; SOPS + age est la
   cible GitOps chiffrée, sans clé réelle dans cette vue.

Les environnements ne se font aucune confiance implicite et ne partagent ni
secret, credential, PII réelle ni state.
