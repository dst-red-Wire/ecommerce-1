# E-Commerce Platform

Plateforme e-commerce self-hosted, cloud-native, multi-site actif/actif, construite autour d'une architecture microservices, d'une plateforme Kubernetes et d'un modèle GitOps strict.

## 1. Objectif

Le projet vise à construire une plateforme e-commerce capable de supporter :

- 500 000 comptes utilisateurs ;
- 50 000 utilisateurs actifs par jour ;
- 10 000 utilisateurs simultanés au pic ;
- 250 000 produits et 1 million de SKU à l'initial ;
- jusqu'à 1 million de produits et 3 millions de SKU sans refonte majeure ;
- 20 000 commandes/jour en nominal ;
- 50 000 commandes/jour en pic ;
- 500 RPS REST en nominal et 2 000 RPS en pic ;
- 1 000 req/s gRPC en nominal et 5 000 req/s en pic ;
- 1 000 événements Kafka/s en nominal, 5 000/s en pic et 10 000/s en burst.

La plateforme est conçue pour être maintenable, observable, testable, automatisée et portable.

## 2. Architecture métier

Le backend est organisé en microservices Go autonomes :

- `catalog`
- `product`
- `pricing`
- `inventory`
- `cart`
- `order`
- `payment`
- `tax`
- `tracking`
- `user-profile`
- `notification`
- `returns`
- `billing`
- `fraud-risk`

Le modèle commercial est mono-vendeur.

### Responsabilités

- **Catalog** : catégories, collections, navigation, merchandising, visibilité commerciale.
- **Product** : fiches produit, SKU, variantes, attributs, médias, prix de référence.
- **Pricing** : prix calculés, promotions, coupons, règles commerciales.
- **Inventory** : stock, quantités, réservations, disponibilité.
- **Cart** : panier et prix indicatifs.
- **Order** : commande, orchestration métier, snapshot immuable du checkout.
- **Payment** : transactions, captures, remboursements.
- **Tax** : TVA, règles fiscales, calculs et versionnement.
- **Returns** : workflow de retour et déclenchement des remboursements.
- **Billing** : factures, avoirs, numérotation et documents.
- **Fraud/Risk** : scoring, règles antifraude, décisions `allow/review/deny`.
- **Tracking** : suivi logistique.
- **User Profile** : données utilisateur strictement nécessaires.
- **Notification** : orchestration métier des notifications.

## 3. Protocoles

### APIs externes

- REST/JSON
- OpenAPI 3.1
- versioning explicite
- contrôle des breaking changes en CI

### Inter-services synchrones

- gRPC
- Protocol Buffers
- Buf

### Asynchrone

**Kafka** est réservé aux événements métier durables :

- event streaming
- intégration inter-services
- projections CQRS
- audit/replay
- CDC ciblé

**RabbitMQ** est réservé aux jobs opérationnels :

- génération PDF
- traitement d'images
- email/SMS/push
- imports/exports
- purge CDN
- tâches distribuées
- retries différés
- TTL/DLQ

## 4. Structure backend Go

Chaque microservice suit cette structure :

```text
services/<service>/
├── cmd/
├── internal/
│   ├── domain/
│   ├── application/
│   ├── infrastructure/
│   └── transport/
│       ├── rest/
│       └── grpc/
├── api/
├── migrations/
├── tests/
├── Dockerfile
├── go.mod
└── README.md
```

Règle impérative :

> REST et gRPC appellent les mêmes use cases. La logique métier ne doit jamais être dupliquée dans les transports.

Stack standard :

- Go
- pgx
- sqlc
- Atlas ou Goose
- go-redis
- franz-go
- OpenTelemetry
- log/slog JSON
- testing
- testcontainers-go

## 5. Monorepo

Structure cible :

```text
ecommerce/
├── services/
│   ├── catalog/
│   ├── product/
│   ├── pricing/
│   ├── inventory/
│   ├── cart/
│   ├── order/
│   ├── payment/
│   ├── tax/
│   ├── tracking/
│   ├── user-profile/
│   ├── notification/
│   ├── returns/
│   ├── billing/
│   └── fraud-risk/
├── frontend/
│   ├── storefront/
│   └── admin/
├── contracts/
│   ├── openapi/
│   ├── grpc/
│   ├── events/
│   └── buf/
├── platform/
│   ├── kubernetes/
│   ├── helm/
│   ├── flux/
│   ├── tekton/
│   ├── terraform/
│   ├── ansible/
│   ├── awx/
│   ├── cluster-api/
│   ├── rancher/
│   └── policies/
├── observability/
│   ├── otel/
│   ├── prometheus/
│   ├── grafana/
│   ├── loki/
│   ├── tempo/
│   ├── alertmanager/
│   └── splunk/
├── tests/
│   ├── bdd/
│   ├── e2e/
│   ├── performance/
│   └── chaos/
├── docs/
│   ├── architecture/
│   ├── adr/
│   ├── security/
│   ├── runbooks/
│   ├── api/
│   └── diagrams/
├── scripts/
├── tools/
├── go.work
├── README.md
├── LICENSE
├── .gitignore
├── .editorconfig
├── .gitattributes
├── CODEOWNERS
├── CONTRIBUTING.md
├── SECURITY.md
└── Makefile
```

Le monorepo utilise `go.work` tout en conservant l'autonomie stricte de chaque microservice.

## 6. Frontend

### Storefront

- Next.js
- TypeScript
- Tailwind CSS
- composants maison/headless
- CSS variables
- design tokens
- mobile-first
- RSC/SSR privilégiés
- JavaScript client limité
- Core Web Vitals surveillés

### Admin Backoffice

- Next.js
- TypeScript
- Tailwind CSS
- shadcn/ui
- Radix UI

L'Admin Backoffice n'est pas un microservice métier séparé.

## 7. IAM et sécurité

### Humains

Keycloak fournit :

- OIDC/OAuth2
- JWT
- OTP/MFA
- Passkeys
- rôles
- permissions/scopes

Rôles de base :

- `super_admin`
- `catalog_manager`
- `inventory_manager`
- `order_manager`
- `finance_manager`
- `support_agent`
- `customer`

### Workloads

- SPIFFE/SPIRE pour les identités machine
- OpenBao pour les secrets et credentials dynamiques

### Baseline Kubernetes

- Pod Security `restricted`
- `runAsNonRoot=true`
- `readOnlyRootFilesystem=true`
- `allowPrivilegeEscalation=false`
- `capabilities.drop=["ALL"]`
- `seccompProfile=RuntimeDefault`
- Cilium `default-deny`
- Kyverno pour l'admission

## 8. Réseau et service mesh

### CNI

- Cilium
- Hubble

### Mesh

- Istio Ambient Mesh
- ztunnel pour mTLS/L4
- waypoints uniquement lorsque le L7 est nécessaire

### Chaîne API

```text
Internet
  ↓
PowerDNS + dnsdist
  ↓
HAProxy
  ↓
Caddy + Coraza
  ↓
Kong
  ↓
Istio Gateway
  ↓
Microservices
```

### Web/CDN

```text
www.example.com
  ↓
Apache Traffic Server
  ↓
Next.js Storefront
```

```text
cdn.example.com
  ↓
Apache Traffic Server
  ↓
MinIO / assets
```

## 9. Données

### PostgreSQL

- source de vérité métier
- CloudNativePG
- PgBouncer si nécessaire
- LocalPV NVMe pour les bases critiques
- migrations `expand -> migrate -> contract`

### Redis

Redis Cluster pour :

- cache
- panier temporaire
- rate limiting
- état temporaire

Redis n'est jamais source de vérité.

### OpenSearch

Read model reconstruisible pour la recherche avancée lorsque justifié.

### MinIO

Stockage objet pour :

- assets
- artefacts métier
- Loki
- Tempo
- sauvegardes
- objets métier

### Ceph

- Ceph RBD pour bloc RWO
- CephFS uniquement pour RWX
- un cluster Ceph par site

## 10. Multi-site actif/actif

Deux sites autonomes :

- cluster Kubernetes par site
- Kafka par site
- Redis par site
- RabbitMQ par site
- Ceph par site
- Istio par site

Aucun cluster étendu sur WAN.

Les écritures PostgreSQL utilisent un modèle d'ownership avec `home_site`.

Le failover exige :

- health checks
- quorum
- fencing
- promotion contrôlée
- protection split-brain

## 11. CI/CD

### CI : Tekton

Pipeline cible :

1. format/lint
2. tests unitaires
3. tests d'intégration
4. contract tests
5. tests BDD
6. build OCI
7. Trivy
8. Syft/SBOM
9. Tekton Chains / Cosign provenance et signatures
10. publication GHCR et récupération du digest OCI réel

### Registry

- GitHub Container Registry (`ghcr.io`)
- convention applicative `ghcr.io/dst-red-wire/ecommerce-1/<service>`
- images déployées exclusivement par digest SHA256
- un seul build, puis promotion du même digest entre environnements

### CD

- FluxCD

### Progressive delivery

- Flagger
- canary
- blue/green
- A/B si pertinent
- rollback automatique

## 12. Tests

- unitaires : Go
- intégration : testcontainers-go
- contrats : REST, gRPC, Kafka
- BDD : Gherkin + Godog
- E2E : Playwright
- performance : k6
- chaos : Chaos Mesh

Les résultats BDD doivent être exportables en JUnit et Cucumber.

## 13. Observabilité

- OpenTelemetry
- Prometheus
- Grafana
- Loki
- Tempo
- Alertmanager
- Splunk pour les événements de sécurité ciblés

SLO :

- API publique : 99,9 %
- Order : 99,95 %
- Payment : 99,95 %

Latences :

- REST p95 < 300 ms
- REST p99 < 1 s
- gRPC p95 < 100 ms
- gRPC p99 < 300 ms
- Catalog/Product search p95 < 250 ms
- Kafka consumer lag normal < 30 s

## 14. Infrastructure as Code

- Terraform : provisioning
- Ansible : configuration, hardening, bootstrap OS
- AWX : orchestration Ansible
- Cluster API : lifecycle Kubernetes lorsque le provider est suffisamment mature
- Rancher : visibilité et administration multi-cluster

Rancher ne remplace pas GitOps.

## 15. Configuration et secrets

Configuration non sensible :

- Git
- Helm
- Kustomize
- ConfigMap

Secrets :

- OpenBao comme source de vérité
- injection/fetch runtime privilégié
- External Secrets Operator uniquement si nécessaire

Aucun secret longue durée dans Git.

## 16. Feature flags

- OpenFeature côté applications
- Flipt comme backend

## 17. Paiement / PCI

La plateforme ne stocke jamais :

- PAN complet
- CVV

Les paiements utilisent tokenisation, Hosted Fields ou mécanisme équivalent.

## 18. Webhooks

Tous les webhooks externes passent par Kong et doivent appliquer :

- signature/authentification
- anti-replay
- idempotence
- validation de schéma
- rate limiting
- audit

## 19. Événements Kafka

Enveloppe standard :

```text
event_id
event_type
aggregate_id
aggregate_version
occurred_at
producer
correlation_id
causation_id
trace_id
```

Clé de partition : `aggregate_id`.

Les consommateurs doivent être idempotents.

## 20. Gouvernance

Principes :

- GitOps first
- Infrastructure as Code
- API contracts first
- backward compatibility
- least privilege
- privacy by design
- data minimization
- observability by default
- idempotence
- immutable artifacts
- ADR pour les décisions structurantes
- aucune duplication métier

## 21. Contribution

Avant toute modification :

1. identifier le domaine propriétaire ;
2. vérifier les contrats existants ;
3. préserver la compatibilité ;
4. ajouter ou adapter les tests ;
5. ne pas introduire de secret ;
6. ne pas contourner les policies ;
7. ne pas modifier manuellement la production ;
8. documenter les décisions architecturales significatives.

## 22. Bootstrap maître

La création initiale de l'arborescence est gouvernée par :

```text
PROMPT_IA_00_BOOTSTRAP_MONOREPO.md
```

Les prompts IA ultérieurs doivent compléter cette structure et ne pas la recréer.

## 23. Licence

Voir [LICENSE](./LICENSE).
