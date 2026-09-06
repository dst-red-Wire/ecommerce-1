# Frontend NOMA - Phase 1

Ce workspace contient un Storefront et un Backoffice NOMA exécutables localement avec des données simulées déterministes. Il ne se connecte à aucun microservice, aucune API métier ni aucun fournisseur IAM.

## Prérequis

- Node.js `24.20.0` (voir `.node-version` et `.nvmrc`) ;
- Corepack, fourni avec la distribution Node.js retenue ;
- pnpm `11.24.0`, automatiquement sélectionné par `packageManager`.

## Installation et lancement

```sh
cd frontend
corepack enable
corepack pnpm install --frozen-lockfile
corepack pnpm dev
```

- Storefront : <http://127.0.0.1:3000>
- Admin : <http://127.0.0.1:3001>
- Vue Admin tablette : <http://127.0.0.1:3001/tablet>
- Vue Admin mobile d'urgence : <http://127.0.0.1:3001/mobile>

Pour lancer une seule application :

```sh
corepack pnpm dev:storefront
corepack pnpm dev:admin
```

Les mêmes commandes sont disponibles dans le `Makefile` local (`make dev`, `make check`). Le `Makefile` racine n'est volontairement pas modifié, car il contient déjà des changements utilisateur hors de cette milestone.

## Architecture

```text
frontend/
├── apps/
│   ├── storefront/
│   │   ├── app/                 # routes et composition RSC
│   │   ├── application/         # cas d'usage de lecture UI
│   │   ├── ports/               # besoins de données du frontend
│   │   ├── adapters/            # adapter mock de Phase 1
│   │   ├── domain/              # view models, pas des DTO backend
│   │   ├── fixtures/            # données déterministes
│   │   └── components/
│   └── admin/                   # même séparation, adaptée au Backoffice
├── packages/
│   ├── ui/                      # tokens et primitives NOMA partagés
│   └── config/                  # configuration TypeScript stricte
└── e2e/                         # smoke tests et captures Playwright
```

La composition actuelle est :

```text
UI / RSC
  -> application
  -> frontend port
  -> mock adapter
```

L'intégration future remplacera uniquement le binding du mock adapter :

```text
OpenAPI officiel
  -> client généré
  -> adapter BFF côté serveur Next.js
  -> application
  -> UI existante
```

Le navigateur ne doit pas appeler directement les futurs microservices métier.

## Écrans Storefront

- `/` : Home responsive ;
- `/catalogue` : catalogue, recherche, filtres, tri et état vide ;
- `/produit/baskets-noma-court` : galerie, variantes, quantité, panier simulé, détails et recommandations ;
- états globaux `loading`, `error` et `not-found`.

Les pages reproduisent les six références mobile/desktop du pack Storefront au moyen d'un unique layout responsive.

## Écrans Admin

- `/` : Dashboard ;
- `/products` : Products List ;
- `/products/baskets-noma-court/edit` : Product Editor ;
- `/orders` : Orders List ;
- `/orders/ORD-2026-008471` : Order Detail ;
- `/inventory` : Inventory et drawer d'ajustement simulé ;
- `/payments/PAY-2026-008471` : Payment et dialog de remboursement simulé ;
- `/tablet` : adaptation tablette ;
- `/mobile` : supervision mobile d'urgence.

Les autres entrées de navigation correspondent à l'architecture cible et aboutissent volontairement à l'état `not-found`; aucun workflow métier absent n'est inventé.

## Design system

`packages/ui/src/tokens.css` centralise la palette NOMA, les espacements, rayons, ombres, couleurs fonctionnelles, focus et règles de mouvement. Les composants partagés incluent les boutons, badges, prix, notation et illustrations produit temporaires.

Les illustrations vectorielles sont des placeholders accessibles centralisés dans `packages/ui/src/product-art.tsx`. Elles remplacent les photographies intégrées aux maquettes raster, qui ne sont pas des assets sources réutilisables.

## Fixtures et limites de sécurité

Les fixtures ne contiennent aucune donnée personnelle réelle. Les identités, commandes, paiements et stocks affichés sont fictifs et stables.

- `KNOWN` : structure et direction visuelle issues des packs NOMA ;
- `MOCKABLE` : view models et données strictement nécessaires à la démonstration ;
- `CONTRACT_REQUIRED` : API BFF/OpenAPI, DTO, erreurs, pagination, filtres, cache et idempotence ;
- `IAM_REQUIRED` : realm, clients, callbacks, claims et matrice de permissions Keycloak ;
- `ASSET_REQUIRED` : logo vectoriel final, photographies produit, iconographie de marque et fontes licenciées ;
- `CONTENT_REQUIRED` : traductions anglaises, contenus commerciaux, mentions légales, CGV et politiques de livraison/retour.

L'utilisateur Admin affiché n'est pas authentifié. Les masquages ou interactions UI ne constituent aucune autorisation. Les actions sensibles affichent explicitement leur nature simulée et devront être revalidées par le backend et l'IAM.

## Internationalisation

La langue française est la racine publique prévue. La branche `/en/` est réservée à une prochaine milestone, car aucune traduction commerciale validée n'est fournie. Aucun DNS ni redirection de domaine n'est configuré ici.

## Validation

```sh
corepack pnpm lint
corepack pnpm typecheck
corepack pnpm test
corepack pnpm build
corepack pnpm exec playwright install chromium
corepack pnpm test:e2e
```

Les captures de validation sont écrites dans `frontend/screenshots/`. Ce répertoire est ignoré par Git et ne doit pas être commité.

## Passage aux APIs réelles

Avant de remplacer les mocks, fournir les contrats OpenAPI/BFF officiels, les règles d'erreur et de pagination, la configuration IAM exploitable, les URL par environnement et les règles de cache/fraîcheur. Aucun fichier OpenAPI ou DTO réseau provisoire n'est créé dans cette Phase 1.
