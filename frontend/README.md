# Frontend NOMA — migration vers Go + templ + HTMX

## Cible et état actuel

La cible PROD est constituée de deux applications Go + templ + HTMX, conservées dans `apps/storefront` et `apps/admin`, sous un module Go commun `frontend/go.mod`. Elles restent déployables séparément. Aucun `go.mod` par application ne doit être créé.

L'implémentation actuelle Next.js/React/Node.js est **LEGACY / MIGRATION SOURCE** : elle reste exécutable pendant la migration et conserve les écrans, parcours, mocks et références NOMA décrits ci-dessous. La migration Go n'est ni implémentée, ni qualifiée en PREPROD, ni déployée en PROD.

## Exécution de l'implémentation legacy actuelle

## Prérequis

- Node.js `24.20.0` (voir `.node-version` et `.nvmrc`) ;
- Corepack, fourni avec la distribution Node.js retenue ;
- pnpm `11.24.0`, automatiquement sélectionné par `packageManager`.

## Prise en main locale

Depuis la racine du dépôt, la commande canonique est :

```sh
make site
```

Elle exécute l'installation reproductible (`pnpm install --frozen-lockfile`) puis lance les deux applications en parallèle. Depuis le répertoire `frontend/`, la commande équivalente est également `make site`.

Ouvrir ensuite dans le navigateur Windows :

- Storefront : <http://localhost:3000>
- Admin : <http://localhost:3001>
- Vue Admin tablette : <http://localhost:3001/tablet>
- Vue Admin mobile d'urgence : <http://localhost:3001/mobile>

Le terminal qui exécute `make site` doit rester ouvert. Utiliser `Ctrl+C` pour arrêter Storefront et Admin.

Le mode par défaut reste déterministe et hors ligne :

```sh
make site
```

Pour utiliser les produits de démonstration DummyJSON :

```sh
NOMA_DATA_ADAPTER=public make site
```

Les photos Pexels restent optionnelles. `PEXELS_API_KEY` doit être injectée uniquement côté serveur et hors Git ; elle ne doit jamais utiliser le préfixe `NEXT_PUBLIC_`. Sans cette clé, le mode public continue avec les illustrations locales NOMA.

Pour lancer une seule application depuis `frontend/` :

```sh
make dev-storefront
make dev-admin
```

Pour vérifier le frontend sans lancer les serveurs :

```sh
make check
make e2e
```

## Architecture legacy actuelle

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
  -> adapter BFF côté serveur (actuellement Next.js, cible Go)
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

## Références de conception

Le design system exécutable est versionné dans [`packages/ui`](packages/ui/README.md). La provenance des packs NOMA, la politique d'archivage et les références Storefront/Admin sont versionnées dans [`../docs/design`](../docs/design/README.md). Les ZIP de maquettes bruts ne sont volontairement pas commités.

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


## Données publiques de démonstration

Le mode par défaut reste `NOMA_DATA_ADAPTER=mock` afin que les builds, tests et démonstrations hors ligne soient déterministes. Pour tester des données publiques structurées, définir `NOMA_DATA_ADAPTER=public` dans un fichier local non commité. Le catalogue utilise alors DummyJSON comme source de données de démonstration.

Les photos Pexels sont un enrichissement optionnel côté serveur. Définir `PEXELS_API_KEY` uniquement dans un secret local/de déploiement ; la clé ne doit jamais utiliser le préfixe `NEXT_PUBLIC_`. Sans clé ou si Pexels est indisponible, le catalogue public continue avec les illustrations NOMA locales. Les photos affichées conservent un lien de crédit vers leur page Pexels et leur photographe.

Les profils clients, commandes, paiements et signaux fraude restent volontairement synthétiques : une photo ou un profil public ne doit pas être présenté comme un vrai client, acheteur ou fraudeur. Les fournisseurs publics sont des données de démonstration, pas des contrats métier ecommerce-1.

## Passage aux APIs réelles

Avant de remplacer les mocks, fournir les contrats OpenAPI/BFF officiels, les règles d'erreur et de pagination, la configuration IAM exploitable, les URL par environnement et les règles de cache/fraîcheur. Aucun fichier OpenAPI ou DTO réseau provisoire n'est créé dans cette Phase 1.
