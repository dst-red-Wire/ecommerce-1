# NOMA Storefront

## Référence

Le Storefront est dérivé du pack de référence `design-pack-storefront-noma.zip`. Le binaire du pack n'est pas stocké dans Git; sa provenance est enregistrée dans `design-sources.yaml`.

L'implémentation versionnée se trouve sous `frontend/apps/storefront`. Les six références mobile/desktop du pack sont représentées par un layout responsive commun plutôt que par des implémentations séparées.

## Parcours actuellement représentés

- `/` : accueil responsive.
- `/catalogue` : catalogue, recherche, filtres, tri et état vide.
- `/produit/[slug]` : galerie, variantes, quantité, panier de démonstration, détails et recommandations.
- États applicatifs : loading, error et not-found.

## Design system consommé

Le Storefront doit réutiliser `@noma/ui` pour les primitives partagées et `frontend/packages/ui/src/tokens.css` pour les tokens globaux. Les styles spécifiques à une page peuvent rester dans l'application, mais ne doivent pas dupliquer un token ou une primitive déjà canonique.

## Données et médias

Le design ne définit pas les contrats métier. Les données mock restent déterministes par défaut; DummyJSON et Pexels sont uniquement des sources de démonstration optionnelles. Les médias externes doivent conserver leur provenance et respecter les règles de licence/attribution applicables.
