# Backend REST / OpenAPI contracts

Status: `BUILD CONTRACT — M2 GOLDEN PRODUCT`

Les contrats REST publics/edge d'ecommerce-1 sont versionnés dans `contracts/openapi/` et enregistrés dans le contrat machine `config/contracts/public-api-contracts.yaml`. Ils suivent la baseline : REST/JSON + OpenAPI 3.1 pour les APIs externes, tandis que les appels synchrones inter-services restent gRPC/Protobuf.

## Tranche actuelle

Le premier contrat est volontairement celui du service `product`, conformément à la séquence de build imposée `M2 golden product service` avant réplication des conventions aux autres services.

- `contracts/openapi/common.v1.yaml` : composants REST partagés (Problem Details, auth bearer JWT, idempotence, concurrence optimiste, pagination/correlation).
- `contracts/openapi/product.v1.yaml` : API Product v1 destinée à l'Admin.
- `config/contracts/public-api-contracts.yaml` : registre machine exact des contrats publiés.

Le contrat Product ne contient que les données appartenant au domaine `product` : produits, SKUs, attributs et faits produit de base. Il exclut explicitement les catégories/assortiments/métadonnées de présentation (`catalog`), les prix (`pricing`), le stock (`inventory`), les avis (`review`) et les états de commande/paiement.

## Invariants automatisés

```sh
make contracts
```

La validation échoue si un contrat enregistré :

- n'est pas OpenAPI 3.1.0 ou diverge de son registre machine ;
- déclare un service non canonique ou `checkout` ;
- diverge de l'ownership exact de `config/contracts/service-ownership.yaml` ;
- utilise un `$ref` distant ou non résolu ;
- omet `operationId` ou une réponse 2xx ;
- expose une commande sans authentification, `Idempotency-Key`, ou sans `If-Match` pour un PATCH ;
- utilise un chemin qui ne respecte pas le major versionné du contrat.

Le gate `contracts` fait partie de `make ci` et du bootstrap CI Woodpecker. Les tests négatifs du validateur sont exécutés par `make test`.

## Convention Product v1

Les écritures sont authentifiées par JWT Keycloak, rejouables via `Idempotency-Key`, et les mises à jour PATCH utilisent `If-Match`/ETag pour éviter les pertes de mise à jour. Les erreurs utilisent `application/problem+json` et les réponses exposent `X-Request-ID` lorsque défini par le contrat.

Le chemin HTTP est versionné en `/v1/...`; la version sémantique du document est distincte (`info.version`). Les `$ref` restent locaux au dépôt pour garder les validations reproductibles et hors réseau.

## Suite

Une fois la convention du golden service `product` validée par implémentation et revue, les contrats externes suivants sont ajoutés par tranches métier, sans créer de service `checkout`. Le Storefront public doit ensuite s'appuyer sur les contrats des propriétaires appropriés (notamment `catalog`) plutôt que contourner les frontières de domaine.
