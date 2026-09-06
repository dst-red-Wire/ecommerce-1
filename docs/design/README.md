# NOMA design references

Ce répertoire versionne la traçabilité du design NOMA utilisé par le Storefront et l'Admin ecommerce-1. Les fichiers exécutables du design system restent dans `frontend/packages/ui`; les packs de maquettes bruts ne sont pas commités dans Git afin d'éviter les binaires lourds, les doublons et les ambiguïtés de licence.

## Autorités

- Design system exécutable : `frontend/packages/ui/`.
- Tokens globaux : `frontend/packages/ui/src/tokens.css`.
- Primitives React : `frontend/packages/ui/src/primitives.tsx`.
- Illustrations produit temporaires : `frontend/packages/ui/src/product-art.tsx`.
- Références Storefront : `docs/design/storefront.md`.
- Références Admin : `docs/design/admin.md`.
- Registre de provenance : `docs/design/design-sources.yaml`.

Les fichiers de ce répertoire documentent la provenance et l'intention. Ils ne remplacent pas les composants et tokens réellement utilisés par l'application.

## Politique de versionnement

Sont versionnés dans Git : les tokens, composants, icônes/illustrations sources autorisées, documentation, métadonnées de provenance et spécifications nécessaires à la reconstruction de l'interface.

Ne sont pas versionnés : les ZIP de maquettes, exports de conception volumineux, captures Playwright générées, images sans licence/provenance claire et fichiers temporaires. Les archives originales doivent être conservées dans un stockage documentaire externe approprié; leur SHA-256 doit être ajouté au registre lorsqu'un emplacement d'archive stable est établi.

## Évolution

Toute modification visuelle significative doit mettre à jour, dans la même PR, le design system ou l'application concernée et la documentation de référence correspondante. Une capture générée ne devient jamais automatiquement une source de vérité.
