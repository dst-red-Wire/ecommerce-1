# @noma/ui

`@noma/ui` est le design system exécutable partagé entre le Storefront et l'Admin NOMA.

## Sources canoniques

- `src/tokens.css` : palette, états fonctionnels, rayons, espacements, conteneur, ombres, focus, typographie globale, accessibilité motion et styles de base.
- `src/primitives.tsx` : `Button`, `Badge`, `Rating` et `Price`.
- `src/product-art.tsx` : illustrations produit temporaires et accessibles utilisées lorsque aucun média licencié n'est disponible.
- `src/index.ts` : surface publique du package.

## Contrat d'utilisation

Les applications doivent réutiliser les tokens `--noma-*` et les primitives partagées avant de créer une variante locale. Un nouveau token ou composant partagé doit être ajouté ici lorsqu'il représente une règle visuelle commune aux deux applications.

Les composants doivent conserver les exigences d'accessibilité déjà présentes : focus visible, taille d'interaction adaptée, labels accessibles et respect de `prefers-reduced-motion`.

## Références de conception

La provenance des packs NOMA et les règles de versionnement sont documentées dans `../../../docs/design/README.md` et `../../../docs/design/design-sources.yaml`.
