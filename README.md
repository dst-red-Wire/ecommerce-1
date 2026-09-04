# E-Commerce Platform

Plateforme e-commerce B2C mono-vendeur, cloud-native, self-hosted, multi-site A/B, construite autour de microservices Go, de Kubernetes RKE2 et d'un modèle GitOps strict.

## Statut

Le dépôt est en phase `ARCHITECTURE_SYNC -> BUILD`. L'architecture générale est verrouillée, mais le monorepo applicatif et l'IaC ne sont pas encore implémentés. Toute implémentation doit suivre `docs/architecture/BASELINE_V2.md` et `architecture.lock.yaml`.

## Architecture métier — 17 microservices

- `catalog`
- `product`
- `inventory`
- `cart`
- `pricing`
- `tax`
- `order`
- `payment`
- `shipping`
- `tracking`
- `returns`
- `billing`
- `fraud-risk`
- `search`
- `review`
- `user-profile`
- `notification`

Il n'existe pas de microservice `checkout`. `Order` orchestre la Saga de commande et conserve le snapshot immuable du checkout.

## Frontends

- `frontend/storefront` : Next.js, TypeScript, mobile-first, RSC/SSR privilégiés.
- `frontend/admin` : Next.js, TypeScript, Tailwind CSS, shadcn/ui, Radix UI.

## Contrats

- Externe : REST/JSON + OpenAPI 3.1.
- Inter-services : gRPC + Protobuf + Buf.
- Événements : Kafka + Protobuf + Apicurio Registry.
- Jobs opérationnels : RabbitMQ Quorum Queues.
- Patterns obligatoires selon le domaine : Outbox, idempotence, Saga, retry borné, DLQ, versioning et contract tests.

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

- CI plateforme : Tekton.
- Registry : Harbor.
- CD GitOps : Rancher Fleet.
- Progressive delivery : Argo Rollouts.
- Images : digests immuables, jamais `latest`.
- Supply chain : Trivy, Syft SBOM, Cosign, admission policy.

La CI Woodpecker présente dans le dépôt est uniquement un bootstrap transitoire du repository. Elle ne doit pas devenir une seconde CI applicative concurrente de Tekton.

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

## Structure cible du monorepo

```text
services/
frontend/
contracts/
platform/
  kubernetes/
  helm/
  fleet/
  tekton/
  terraform/
  ansible/
  rancher/
  policies/
observability/
tests/
docs/
scripts/
tools/
```

Aucun ancien chemin `platform/flux/` ne doit être créé. Aucun nouveau code ne doit dépendre de MinIO CE, Flagger, Loki ou Splunk comme composants actifs de l'architecture cible.

## Autorités documentaires

Priorité :

1. règles système et sécurité ;
2. ADR et Skills spécialisés validés ;
3. `docs/architecture/BASELINE_V2.md` ;
4. `architecture.lock.yaml` ;
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
