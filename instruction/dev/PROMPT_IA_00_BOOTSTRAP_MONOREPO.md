# PROMPT IA 00 V2 — Bootstrap maître du monorepo E-COMMERCE

## Rôle

Tu es l'agent d'implémentation chargé de créer le bootstrap minimal du monorepo. Tu implémentes une architecture déjà décidée : tu ne la redessines pas.

## Sources obligatoires

Lire avant toute modification :

1. `/AGENTS.md`
2. `/docs/architecture/BASELINE_V2.md`
3. `/architecture.lock.yaml`
4. les ADR présents sous `/docs/adr/` lorsqu'ils existent

En cas de contradiction, arrêter la partie concernée et signaler précisément le conflit. Ne jamais choisir silencieusement une troisième architecture.

## Objectif du bootstrap

Créer une structure minimale, compilable/testable progressivement, qui servira de base aux étapes suivantes. Le bootstrap ne doit pas implémenter les 17 domaines métier en profondeur.

## 1. Services

Créer exactement les 17 répertoires backend :

```text
services/
  catalog/
  product/
  inventory/
  cart/
  pricing/
  tax/
  order/
  payment/
  shipping/
  tracking/
  returns/
  billing/
  fraud-risk/
  search/
  review/
  user-profile/
  notification/
```

Ne pas créer `checkout`. `order` possède l'orchestration du checkout et la Saga de commande.

Chaque service garde son autonomie :

```text
services/<service>/
  cmd/
  internal/
    domain/
    application/
    infrastructure/
    transport/
      rest/
      grpc/
  api/
  migrations/
  tests/
  Dockerfile
  go.mod
  README.md
```

Le bootstrap peut créer des placeholders minimaux et des README, mais ne doit pas copier une fausse logique métier dans les 17 services.

## 2. Golden service

Le premier service réellement implémenté après ce bootstrap sera `product`.

Ne pas tenter de générer simultanément une implémentation complète des 17 services. Le golden service doit d'abord valider :

- structure Go ;
- REST + gRPC partageant les mêmes use cases ;
- PostgreSQL/pgx/sqlc ;
- migrations ;
- Outbox/Kafka ;
- OpenTelemetry ;
- health/readiness ;
- tests ;
- Dockerfile ;
- SBOM/signature ;
- manifests de déploiement.

## 3. Frontends

Créer :

```text
frontend/storefront/
frontend/admin/
```

Storefront : Next.js + TypeScript, mobile-first, RSC/SSR privilégiés, design tokens et JavaScript client limité.

Admin : Next.js + TypeScript + Tailwind CSS + shadcn/ui + Radix UI.

Ne pas générer tous les écrans pendant le bootstrap.

## 4. Contrats

Créer :

```text
contracts/
  openapi/
  grpc/
  events/
  buf/
```

Standards :

- OpenAPI 3.1 pour REST ;
- Protobuf + Buf pour gRPC ;
- Protobuf + Apicurio pour événements Kafka ;
- versioning et tests de compatibilité obligatoires.

Kafka transporte les événements métier durables. RabbitMQ transporte les jobs opérationnels. Ne pas mélanger ces responsabilités.

## 5. Platform

Créer :

```text
platform/
  kubernetes/
    base/
    components/
    namespaces/
    policies/
  helm/
  fleet/
    clusters/
    infrastructure/
    applications/
  tekton/
    tasks/
    pipelines/
  terraform/
    modules/
    environments/
  ansible/
    inventories/
    playbooks/
    roles/
  rancher/
  policies/
    kyverno/
```

Ne jamais créer `platform/flux/`.

Active choices:

- RKE2 ;
- Cilium + Hubble ;
- Rancher Fleet ;
- Tekton ;
- Argo Rollouts ;
- Kyverno ;
- Istio ;
- SPIRE ;
- OpenBao + ESO ;
- CloudNativePG ;
- Strimzi ;
- RabbitMQ Cluster Operator ;
- Redis Cluster ;
- OpenSearch ;
- SeaweedFS S3 ;
- Harbor.

## 6. Superseded components

Do not introduce as active defaults:

```text
FluxCD
Flagger
MinIO Community Edition / MinIO Operator
Loki as logging baseline
Splunk as SIEM baseline
```

Historical documents may mention them only as superseded choices.

## 7. Observability

Créer la structure :

```text
observability/
  otel/
  prometheus/
  alertmanager/
  grafana/
  fluent-bit/
  data-prepper/
  opensearch/
  wazuh/
```

Ne pas créer des dashboards massifs au bootstrap.

## 8. Tests

Créer :

```text
tests/
  bdd/
    features/
    support/
  e2e/
  performance/
  chaos/
  dr/
```

Ordre fonctionnel cible :

```text
unit -> integration -> contracts -> BDD -> smoke/E2E -> performance -> chaos/DR
```

Standards : testcontainers-go, Gherkin/Godog, Playwright, k6, Chaos Mesh.

## 9. Documentation

Créer :

```text
docs/
  architecture/
  adr/
  security/
  runbooks/
  api/
  diagrams/
  dr/
```

Ne pas remplacer `BASELINE_V2.md`.

Créer un template ADR si absent.

## 10. Root files

Créer si absents :

```text
.editorconfig
CODEOWNERS
CONTRIBUTING.md
SECURITY.md
go.work
```

Conserver et étendre :

```text
README.md
AGENTS.md
architecture.lock.yaml
Makefile
.gitignore
.gitattributes
```

## 11. Makefile et scripts

La logique complexe doit résider sous `scripts/` et être factorisée.

Targets à préparer progressivement :

```text
help
ci
fmt
lint
test
test-unit
test-integration
test-contract
test-bdd
test-e2e
test-performance
build
container-build
contracts
security
terraform
ansible
```

Ne pas brancher de test destructif Chaos/DR dans `make ci`.

## 12. Security baseline

Workloads Kubernetes :

- Pod Security `restricted` ;
- non-root ;
- read-only root filesystem lorsque compatible ;
- no privilege escalation ;
- drop all capabilities par défaut ;
- RuntimeDefault seccomp ;
- default-deny networking.

Aucun secret réel dans Git ou fixtures.

Images promues par digest. `latest` interdit.

## 13. Configuration and data ownership

- config non sensible : Git/ConfigMap ;
- secrets : OpenBao via ESO ;
- feature flags : OpenFeature + Flipt ;
- service database ownership strict ;
- aucun accès SQL direct à la base d'un autre domaine ;
- Redis n'est jamais une source de vérité ;
- Search/OpenSearch reste reconstruisible.

## 14. PREPROD preparation

Préparer les environnements comme conventions, sans provisionner réellement pendant le bootstrap :

```text
platform/terraform/environments/preprod
platform/terraform/environments/prod-a
platform/terraform/environments/prod-b
platform/ansible/inventories/preprod
platform/ansible/inventories/prod-a
platform/ansible/inventories/prod-b
platform/fleet/clusters/preprod
platform/fleet/clusters/prod-a
platform/fleet/clusters/prod-b
```

La création réelle PREPROD suit :

`CREATE -> VALIDATE -> ARCHIVE -> DESTROY -> VERIFY ZERO RESOURCE`.

## 15. CI bootstrap vs target CI

La configuration Woodpecker actuellement présente est transitoire et limitée aux contrôles portables du dépôt.

Ne pas y construire une seconde plateforme CI complète. Les pipelines applicatifs et de supply chain cibles appartiennent à Tekton.

## 16. Validation obligatoire

Après modification :

1. afficher/résumer l'arborescence créée ;
2. vérifier exactement 17 services et 2 frontends ;
3. vérifier absence de `checkout` ;
4. vérifier absence de `platform/flux` ;
5. rechercher les composants supersédés dans les nouveaux fichiers ;
6. vérifier qu'aucune image utilise `latest` ;
7. vérifier les scripts POSIX `sh` ;
8. exécuter les validations disponibles ;
9. exécuter `make ci` ;
10. fournir un résumé des fichiers créés, tests, limites et prochain jalon.

## 17. Definition of Done M1

Le bootstrap est terminé lorsque :

- la structure cible existe sans duplication ;
- les 17 services sont représentés sans logique métier inventée ;
- les deux frontends sont initialisés minimalement ;
- les contrats et espaces platform/tests/docs existent ;
- Fleet/Tekton sont les seules cibles actives GitOps/CI plateforme ;
- la baseline et le lock restent cohérents ;
- `make ci` passe ;
- aucun secret ou composant supersédé n'a été introduit ;
- le dépôt est prêt pour M2 `golden-service-product`.
