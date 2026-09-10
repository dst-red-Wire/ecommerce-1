# E-Commerce Platform

Plateforme e-commerce B2C mono-vendeur, cloud-native, self-hosted, multi-site A/B, construite autour de microservices Go, de Kubernetes RKE2 et d'un modèle GitOps strict.

## Environnement reproductible

`make bootstrap` réconcilie l'environnement selon le graphe de capacités. `make env-check`
effectue le même audit sans installation. Python, Git, Make et la version épinglée
d’Ansible Core sont des prérequis fournis par le runner : le dépôt ne les installe pas et
utilise Ansible pour réconcilier uniquement les outils du projet. Les états normalisés sont
`PASS`, `FAIL`, `BLOCKED`, `SKIP` et `UNSUPPORTED`; un daemon Docker indisponible ne bloque
que ses vrais dépendants, tels Kind et les tests conteneurisés. Voir
[ADR-0002](docs/adr/ADR-0002-capability-aware-bootstrap.md).

## Statut

Le dépôt est en phase `BUILD`, avec `M2-golden-service-product` comme jalon applicatif courant. Le monorepo applicatif existe déjà (`frontend/`, `services/product/`) et l'IaC MGMT est amorcée sous `platform/terraform` et `platform/ansible`; les autres services et couches de plateforme sont ajoutés progressivement selon `architecture.lock.yaml`.

## Architecture métier — 19 microservices

- `catalog`
- `product`
- `inventory`
- `cart`
- `checkout`
- `pricing`
- `tax`
- `order`
- `payment`
- `fulfillment`
- `shipping`
- `tracking`
- `returns`
- `billing`
- `fraud-risk`
- `search`
- `review`
- `user-profile`
- `notification`

La chaîne transactionnelle centrale est `Cart -> Checkout -> Order -> Payment -> Fulfillment`. Ces cinq domaines sont autonomes. `Fulfillment` reste distinct de `Shipping` et `Tracking`, et `Order` conserve le snapshot commercial immuable de la commande confirmée.

## Frontends

- `frontend/apps/storefront` : cible Go + templ + HTMX, mobile-first.
- `frontend/apps/admin` : cible Go + templ + HTMX.
- Module unique : `frontend/go.mod`; les applications restent déployables séparément.
- Next.js/React/Node.js est la source de migration. Node.js peut rester temporairement pour Playwright, CSS/build tooling et compatibilité, mais n’est plus le runtime frontend PROD cible.
- Design system partagé : [`frontend/packages/ui`](frontend/packages/ui/README.md).
- Références et provenance NOMA : [`docs/design`](docs/design/README.md).

## Prise en main locale du site

Le frontend NOMA est directement consultable depuis le navigateur Windows lorsque le dépôt est lancé sous WSL2. Depuis la racine du dépôt :

```sh
make site
```

Cette commande installe les dépendances frontend verrouillées avec le lockfile, puis démarre simultanément le Storefront et l'Admin. Garder le terminal ouvert pendant la consultation et utiliser `Ctrl+C` pour arrêter les serveurs.

- Storefront : <http://localhost:3000>
- Admin : <http://localhost:3001>
- Admin tablette : <http://localhost:3001/tablet>
- Admin mobile : <http://localhost:3001/mobile>

Le mode par défaut utilise les données mock déterministes. Pour tester le catalogue public DummyJSON :

```sh
NOMA_DATA_ADAPTER=public make site
```

`PEXELS_API_KEY` reste optionnelle et doit être injectée comme secret côté serveur, hors Git et sans préfixe `NEXT_PUBLIC_`. Les détails de développement, de validation et les limites fonctionnelles courantes sont documentés dans [`frontend/README.md`](frontend/README.md).

## Contrats

- Externe : REST/JSON + OpenAPI 3.1.
- Registre machine des APIs : [`config/contracts/public-api-contracts.yaml`](config/contracts/public-api-contracts.yaml).
- Golden contract M2 Product : [`contracts/openapi/product.v1.yaml`](contracts/openapi/product.v1.yaml).
- Composants REST partagés : [`contracts/openapi/common.v1.yaml`](contracts/openapi/common.v1.yaml).
- Validation reproductible : `make contracts` (également inclus dans `make ci`).
- Inter-services : gRPC + Protobuf + Buf.
- Événements : Kafka + Protobuf + Apicurio Registry.
- Jobs opérationnels : RabbitMQ Quorum Queues.
- Patterns obligatoires selon le domaine : Outbox, idempotence, Saga, retry borné, DLQ, versioning et contract tests.
- Convention détaillée : [`docs/api/README.md`](docs/api/README.md).


### Golden Product runtime - M2A

Le contrat `contracts/openapi/product.v1.yaml` possède maintenant un premier runtime Go exécutable sous `services/product`. Cette tranche implémente les routes REST Product/SKU, idempotence, ETag/`If-Match`, erreurs `application/problem+json`, health/readiness et tests contractuels. La persistance PostgreSQL/pgx/sqlc, gRPC, Outbox/Kafka, OpenTelemetry et les manifests immuables restent explicitement le palier M2 suivant ; l'adaptateur mémoire actuel est uniquement local/test.

- Validation ciblée : `make product-check`
- Exécution locale : `make product-run`

## Données

- PostgreSQL / CloudNativePG : source de vérité transactionnelle des domaines concernés.
- Kafka / Strimzi KRaft : événements durables, un cluster par site, MirrorMaker2 inter-site.
- RabbitMQ : jobs asynchrones opérationnels.
- Redis Cluster : cache et état temporaire, jamais source de vérité métier.
- OpenSearch : recherche et read models reconstruisibles.
- SeaweedFS S3 : cible objet distribuée pour les nouveaux déploiements PROD, sous qualification PREPROD.
- Harbor : autorité OCI pour images, artefacts de supply chain et Modelcars OCI.

## Plateforme

- RKE2 sur Rocky Linux 9.x.
- Cilium + Hubble, LB IPAM, BGP vers FRR, Maglev.
- Istio mTLS STRICT.
- SPIFFE/SPIRE pour l'identité workload.
- Keycloak pour IAM humain.
- OpenBao + External Secrets Operator pour les secrets.
- Kyverno, Pod Security `restricted`, Tetragon, NetworkPolicy default-deny.

## Edge et DNS

Chaîne API publique :

```text
Internet
  -> DNS/GSLB
  -> HAProxy
  -> Caddy + Coraza
  -> Kong
  -> Istio Gateway
  -> services
```

DNS : ClouDNS registrar, PowerDNS Authoritative avec Hidden Primary MGMT + secondaries A/B, dnsdist, DNSSEC, ExternalDNS, CoreDNS interne et Unbound x2/site.

Web/CDN :

```text
www -> ATS -> Storefront
cdn -> ATS -> S3/assets
```

## CI/CD

- Forge cible : Gitea. Les push/PR déclenchent directement Tekton via webhook -> EventListener -> TriggerBinding -> TriggerTemplate -> PipelineRun.
- Autorité CI unique : Tekton, avec les classes de pipeline sous [`platform/tekton`](platform/tekton/README.md).
- Routage CI : affected-only à partir des chemins modifiés et des contrats machine (`make affected BASE=<sha> HEAD=<sha>`).
- Registry : Harbor, avec un artefact OCI indépendant par composant déployable.
- CD GitOps : Rancher Fleet; la CI ne déploie jamais directement les workloads.
- Progressive delivery : Argo Rollouts.
- Images : digests immuables, jamais `latest`, avec SBOM/provenance/signature.
- Supply chain : Trivy, Syft SBOM, Cosign, admission policy.

Les cibles Make restent des façades courtes : elles appellent `scripts/repoctl.py`, les outils natifs ou Ansible selon la responsabilité. Tekton est l’unique autorité CI ; les contrats canoniques sont [`config/contracts/ci-topology.yaml`](config/contracts/ci-topology.yaml) et [`config/contracts/review-policy.yaml`](config/contracts/review-policy.yaml). Gitea Actions n'est pas interdit comme fonctionnalité de forge, mais ne peut être une autorité CI/CD ni servir d'intermédiaire pour lancer Tekton.

## Observabilité

- OpenTelemetry Collector.
- Prometheus + Alertmanager + Grafana.
- Fluent Bit + Data Prepper + OpenSearch Logs.
- Wazuh pour la sécurité et l'audit.
- Archives DFIR immuables selon la politique de résilience.

## QA

- Go unit tests / TDD.
- `testcontainers-go` pour l'intégration.
- Contract tests REST/gRPC/Kafka.
- BDD Gherkin + Godog.
- E2E Playwright.
- Performance k6.
- Chaos Mesh.
- DR et restauration mesurés.

## PREPROD JIT

Ordre imposé :

```text
CREATE
-> Terraform
-> Ansible
-> Proxmox/RKE2
-> Fleet
-> plateforme
-> données synthétiques
-> validations
-> PERF/Chaos/DR conditionnels
-> ARCHIVE EVIDENCE
-> DESTROY
-> VERIFY ZERO RESOURCE
```

Trois campagnes peuvent intervenir avant la première PROD : PREPROD standard 24 h, endurance 72 h et `PREPROD-CERT PROD-EQUIVALENT` sur six hôtes équivalents PROD.

## Résilience

Règle après compromission d'un composant reproductible :

```text
isoler -> acquérir les preuves -> détruire -> reconstruire via GitOps/IaC
```

- PCA = continuer.
- DFIR = comprendre et préserver.
- PRI = reconstruire et restaurer.

## Structure du monorepo

```text
services/
frontend/
contracts/
platform/
  tekton/
  terraform/
  ansible/
tests/
docs/
scripts/
```

Les répertoires de plateforme supplémentaires apparaissent uniquement lorsqu’ils portent un contenu de jalon réel. Aucun ancien chemin `platform/flux/` ne doit être créé. Aucun nouveau code ne doit dépendre de MinIO CE, Flagger, Loki ou Splunk comme composants actifs de l'architecture cible.

## Autorités documentaires

Priorité :

1. règles système et sécurité ;
2. `architecture.lock.yaml`, seule autorité canonique de l’architecture ;
3. index `docs/architecture/EXACT_TOPOLOGY_V5.md`, dérivé du verrou ;
4. ADR et documentation spécialisés, subordonnés au verrou pour l’architecture ;
5. specs et issues d'implémentation ;
6. anciens prompts/PDF uniquement comme historique.

Une décision supersédée reste historique mais ne doit pas être réintroduite comme cible active.

## Développement

Avant toute PR :

1. identifier le domaine propriétaire ;
2. vérifier les contrats et ADR ;
3. limiter le scope ;
4. ajouter les tests ;
5. préserver la compatibilité ;
6. ne jamais introduire de secret ;
7. ne jamais contourner GitOps/policies ;
8. exécuter `make ci` ;
9. documenter rollback et preuve attendue.

## Bootstrap maître

La création initiale du monorepo est gouvernée par :

```text
instruction/dev/PROMPT_IA_00_BOOTSTRAP_MONOREPO.md
```

Ce prompt doit rester synchronisé avec la baseline V2 avant toute exécution Codex.
