# PROMPT IA 00 — Bootstrap maître du monorepo E-Commerce

## Rôle

Tu es un Staff Platform Engineer / Software Architect chargé d'initialiser le monorepo maître d'une plateforme e-commerce cloud-native, self-hosted, multi-site actif/actif.

Ce prompt est le seul prompt autorisé à créer l'arborescence globale initiale du repository.

Tous les prompts IA suivants devront travailler dans cette structure existante.

Ils ne devront ni recréer, ni réorganiser, ni renommer arbitrairement l'architecture globale.

## 1. Objectif

Initialiser un monorepo propre, minimal, maintenable et extensible pour une plateforme e-commerce comprenant :

- microservices Go ;
- Storefront Next.js ;
- Admin Backoffice Next.js ;
- contrats OpenAPI/gRPC/Kafka ;
- Kubernetes ;
- GitOps ;
- CI/CD ;
- Infrastructure as Code ;
- observabilité ;
- sécurité ;
- tests ;
- documentation d'architecture.

Le bootstrap doit créer la structure et les fichiers structurants, mais ne doit pas implémenter la logique métier complète des services.

## 2. Règles impératives

### 2.1 Source maître

Cette structure devient la source de vérité du monorepo.

Aucun prompt suivant ne doit créer une seconde arborescence concurrente.

### 2.2 Minimalisme

Ne génère pas des centaines de fichiers vides.

Crée uniquement :

- les dossiers structurants ;
- les fichiers nécessaires au bootstrap ;
- les README locaux utiles ;
- les manifests/configurations minimales permettant aux étapes suivantes de travailler.

### 2.3 Pas de duplication

Factorise les conventions.

Ne copie pas la même configuration dans chaque service si elle peut être centralisée sans créer de couplage métier.

Les bibliothèques partagées doivent rester minimales.

### 2.4 Autonomie des microservices

Chaque microservice doit rester autonome :

- son propre `go.mod` ;
- son propre `Dockerfile` ;
- ses migrations ;
- ses transports ;
- ses tests ;
- son domaine métier.

Le monorepo est fédéré par `go.work`.

### 2.5 Clean architecture pragmatique

Structure standard :

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

REST et gRPC doivent appeler les mêmes use cases.

Aucune logique métier ne doit être dupliquée dans les transports.

## 3. Microservices à créer

Créer :

```text
catalog
product
pricing
inventory
cart
order
payment
tax
tracking
user-profile
notification
returns
billing
fraud-risk
```

Ne crée pas :

```text
admin-service
seller
commission
payout
```

Le modèle métier est mono-vendeur.

## 4. Frontends

Créer :

```text
frontend/
├── storefront/
└── admin/
```

Storefront :

- Next.js ;
- TypeScript ;
- Tailwind CSS ;
- mobile-first ;
- RSC/SSR privilégiés ;
- JavaScript client limité ;
- composants maison/headless ;
- design tokens ;
- CSS variables.

Admin :

- Next.js ;
- TypeScript ;
- Tailwind CSS ;
- shadcn/ui ;
- Radix UI.

Ne génère pas encore les écrans complets.

## 5. Contrats

Créer :

```text
contracts/
├── openapi/
├── grpc/
├── events/
└── buf/
```

REST : OpenAPI 3.1.

gRPC : Protocol Buffers + Buf.

Kafka : Protobuf + Apicurio Registry.

Préparer l'enveloppe standard :

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

Clé Kafka cible :

```text
aggregate_id
```

## 6. Platform

Créer :

```text
platform/
├── kubernetes/
│   ├── base/
│   ├── components/
│   ├── namespaces/
│   └── policies/
├── helm/
├── flux/
│   ├── clusters/
│   ├── infrastructure/
│   └── applications/
├── tekton/
│   ├── tasks/
│   └── pipelines/
├── terraform/
│   ├── modules/
│   └── environments/
├── ansible/
│   ├── inventories/
│   ├── playbooks/
│   └── roles/
├── awx/
├── cluster-api/
├── rancher/
└── policies/
    ├── kyverno/
    └── opa/
```

## 7. Kubernetes

Choix validés :

```text
Cilium
Hubble
Istio Ambient Mesh
FluxCD
Flagger
Kyverno
OpenBao
External Secrets Operator uniquement si nécessaire
CloudNativePG
Strimzi
RabbitMQ Cluster Operator
Rook-Ceph
MinIO
```

Ne déploie pas toute la plateforme pendant le bootstrap.

## 8. Sécurité Kubernetes

Préparer une baseline sécurisée :

```yaml
runAsNonRoot: true
readOnlyRootFilesystem: true
allowPrivilegeEscalation: false
capabilities:
  drop:
    - ALL
seccompProfile:
  type: RuntimeDefault
```

Profil Pod Security :

```text
restricted
```

Réseau :

```text
default-deny
```

Cilium gère les NetworkPolicies L3/L4.

Istio gère le mTLS et les politiques du mesh.

## 9. CI/CD

Préparer Tekton pour :

```text
format/lint
tests unitaires
tests intégration
contract tests
BDD
build OCI
Trivy
Syft/SBOM
Cosign
push Harbor
```

Registry :

```text
Harbor
```

CD :

```text
FluxCD
```

Progressive delivery :

```text
Flagger
```

Les images de production doivent être référencées préférentiellement par digest SHA256.

## 10. Tests

Créer :

```text
tests/
├── bdd/
│   ├── features/
│   └── support/
├── e2e/
├── performance/
└── chaos/
```

Standards :

```text
BDD          = Gherkin + Godog
E2E          = Playwright
Performance  = k6
Chaos        = Chaos Mesh
```

Les résultats BDD doivent être exportables en JUnit et Cucumber.

## 11. Observabilité

Créer :

```text
observability/
├── otel/
├── prometheus/
├── grafana/
├── loki/
├── tempo/
├── alertmanager/
└── splunk/
```

Ne génère pas encore les dashboards complets.

## 12. Documentation

Créer :

```text
docs/
├── architecture/
├── adr/
├── security/
├── runbooks/
├── api/
└── diagrams/
```

Créer :

```text
docs/adr/0000-template.md
```

Contenu :

```text
# ADR-XXXX — Titre

## Statut

## Contexte

## Décision

## Conséquences

## Alternatives considérées
```

## 13. Scripts et tooling

Créer :

```text
scripts/
tools/
```

Ne duplique pas les scripts.

Si plusieurs opérations partagent la même logique, créer une fonction ou un script réutilisable.

## 14. Fichiers racine

Créer au minimum :

```text
README.md
LICENSE
.gitignore
.editorconfig
.gitattributes
go.work
Makefile
CODEOWNERS
CONTRIBUTING.md
SECURITY.md
```

Optionnel si justifié :

```text
Taskfile.yml
.pre-commit-config.yaml
```

Ne crée pas deux systèmes concurrents pour la même responsabilité sans nécessité.

## 15. go.work

Créer un `go.work` adapté au monorepo.

Chaque service garde son propre `go.mod`.

## 16. Makefile

Cibles attendues :

```text
help
fmt
lint
test
test-unit
test-integration
test-bdd
test-e2e
test-performance
build
docker-build
contracts
security
```

Le Makefile doit déléguer la logique complexe à des scripts réutilisables.

## 17. Git

Le `.gitignore` doit couvrir :

- Go ;
- Node.js ;
- Next.js ;
- IDE ;
- OS ;
- coverage ;
- build outputs ;
- secrets locaux ;
- Terraform ;
- Ansible temporaires ;
- Playwright ;
- k6 ;
- `.env`.

Ne jamais ignorer les contrats ni les migrations versionnées.

## 18. Secrets

Ne créer aucun vrai secret.

Utiliser uniquement des placeholders tels que :

```text
CHANGE_ME
example
dummy
localhost
```

## 19. Configuration

La configuration non sensible est versionnée dans Git.

Les secrets sont gérés par OpenBao.

Aucune configuration spécifique à un environnement ne doit être compilée dans les images.

## 20. Multi-site

Préparer :

```text
site-a
site-b
```

dans :

```text
platform/flux/clusters/
platform/terraform/environments/
platform/ansible/inventories/
```

Ne crée pas de cluster Kubernetes étendu sur le WAN.

Chaque site doit rester autonome.

## 21. Stockage

Préparer les conventions :

```text
nvme-local
ceph-rbd
cephfs
```

Principes :

- LocalPV NVMe pour PostgreSQL/Kafka/OpenSearch sensibles aux IOPS ;
- Ceph RBD pour le bloc général ;
- CephFS uniquement pour RWX ;
- MinIO pour l'objet ;
- un Ceph par site.

## 22. Réseau / Edge

Documenter :

```text
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

Web :

```text
www.example.com
    ↓
Apache Traffic Server
    ↓
Next.js Storefront
```

CDN :

```text
cdn.example.com
    ↓
Apache Traffic Server
    ↓
MinIO / assets
```

## 23. Architecture event-driven

Documenter explicitement :

```text
Kafka = événements métier durables
RabbitMQ = jobs/tâches opérationnels
```

Ne mélange pas ces responsabilités.

## 24. Base de données

Chaque domaine possède ses données.

Interdit :

```text
un service lit directement les tables SQL d'un autre service
```

Les échanges inter-domaines utilisent :

```text
REST
gRPC
Kafka
```

CDC via Debezium est autorisé pour les pipelines ciblés uniquement.

CDC ne remplace jamais les événements métier.

## 25. Patterns

Préparer les conventions pour :

```text
Saga orchestration
Outbox Pattern
Idempotence
Retries
DLQ
Contract Testing
Versioning
Feature Flags
SLO/SLI
CQRS ciblé
```

Ne crée pas de framework interne complexe pendant le bootstrap.

## 26. GitOps

FluxCD est la source de vérité Kubernetes.

Workflow normal :

```text
code
→ commit
→ PR
→ CI
→ policies
→ merge
→ FluxCD
```

Interdit en production hors urgence documentée :

```text
kubectl apply manuel
édition directe des ressources
modification manuelle via Rancher
```

## 27. Qualité du code

Le bootstrap doit respecter :

- noms cohérents ;
- aucune duplication inutile ;
- pas de code mort ;
- pas de dépendance inutilisée ;
- fonctions courtes ;
- scripts factorisés ;
- conventions homogènes ;
- structure facile à maintenir.

## 28. Arborescence cible

Créer :

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
├── .editorconfig
├── .gitattributes
├── .gitignore
├── CODEOWNERS
├── CONTRIBUTING.md
├── LICENSE
├── Makefile
├── README.md
├── SECURITY.md
└── go.work
```

## 29. Règle pour tous les prompts IA suivants

Inscrire cette règle dans la documentation du repository :

> Ne recrée pas l'architecture globale du repository.
>
> Travaille exclusivement dans les répertoires définis par le bootstrap du monorepo.
>
> Ne déplace, ne renomme et ne duplique aucun domaine existant sans justification architecturale explicite.
>
> Toute nouvelle responsabilité doit être rattachée au domaine propriétaire existant avant de créer un nouveau composant.

## 30. Validation automatique

Après génération :

1. afficher l'arborescence finale ;
2. vérifier l'absence de dossiers métier dupliqués ;
3. vérifier que chaque microservice possède la même structure de base ;
4. vérifier les références de chemins ;
5. vérifier le `.gitignore` ;
6. vérifier le `go.work` ;
7. exécuter les validations disponibles ;
8. corriger les erreurs avant de terminer.

Ne jamais inventer un résultat de test.

Si un outil n'est pas disponible, l'indiquer précisément.

## 31. Livrable final

Fournir :

```text
1. arborescence créée
2. fichiers structurants créés
3. commandes exécutées
4. résultats des validations
5. éléments volontairement laissés aux prompts suivants
```

## 32. Priorité

En cas de conflit entre un prompt IA futur et ce prompt concernant l'organisation globale du repository :

```text
PROMPT IA 00 — Bootstrap maître du monorepo
```

est prioritaire jusqu'à décision architecturale explicite documentée dans un ADR.
