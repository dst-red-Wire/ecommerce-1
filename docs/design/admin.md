# NOMA Admin

## Référence

L'Admin est dérivé du pack de référence `design-pack-admin-noma.zip`. Le binaire du pack n'est pas stocké dans Git; sa provenance est enregistrée dans `design-sources.yaml`.

L'implémentation versionnée se trouve sous `frontend/apps/admin` et partage le design system `@noma/ui` avec le Storefront.

## Écrans actuellement représentés

- `/` : Dashboard.
- `/products` : liste produits.
- `/products/[slug]/edit` : éditeur produit.
- `/orders` : liste commandes.
- `/orders/[id]` : détail commande connu, sinon 404.
- `/inventory` : inventaire et ajustement simulé.
- `/payments/[id]` : paiement connu et remboursement simulé, sinon 404.
- `/tablet` : adaptation tablette.
- `/mobile` : supervision mobile d'urgence.

## Contraintes

Les identités, commandes, paiements et stocks de démonstration restent synthétiques. Une restriction visuelle dans l'Admin ne constitue pas une autorisation : l'IAM et les contrôles backend restent les autorités futures pour les opérations sensibles.
