# Primitives de livraison vérifiée

Ce prérequis installe dans `main` les primitives nécessaires au contrôleur BASE de la PR #171. L’autorité de qualification et de fusion reste le contrôleur issu de l’exact `base_sha`.

## Responsabilités

- `repoctl.py` orchestre les lectures fraîches GitHub, la qualification BASE, la fusion, le nettoyage et la clôture.
- `evidence_bundle.py` inventorie les octets des preuves ; son manifeste ne porte pas de verdict.
- `post_merge_verify.py` signe le témoin prémerge et vérifie la signature, la lignée Git, les arbres, les preuves conservées et l’état post-fusion.
- `issue_completion.py` valide les preuves et la relation PR/work-item avant clôture, puis relit GitHub.
- `issue_lifecycle.py` et `work_package.py` valident les relations, l’acceptation et les dépendances déclarées.
- `runtime_authority.py` conserve la validation indépendante des preuves runtime lorsqu’un package les exige.

## Séquence

1. Le contrôleur BASE réexécute sa qualification finale et valide son enveloppe de compatibilité.
2. Après les dernières lectures des revues, de l’autorisation et des protections, il exige que preuve et audit canoniques correspondent aux octets archivés et validés.
3. Il crée et vérifie un bundle lié à BASE, HEAD, tree, toolchain et identité de qualification, puis signe `write_pre_merge_witness` avant la mutation GitHub.
4. Après fusion, nettoyage et réconciliation roadmap, il produit la preuve post-fusion signée.
5. La boucle ne devient `DONE` qu’après clôture vérifiée du work-item et contrôle final de la roadmap.

`post-merge-verify --pr <numéro>` vérifie une preuve existante ou récupère une preuve absente à partir du témoin signé. Une preuve invalide ou partiellement publiée reste bloquante. Un témoin prémerge ne se fabrique pas après fusion.

Le contrôle `roadmap_sync.py check --document-only` vérifie le document sans rappeler la projection des preuves, afin d’éviter une récursion pendant la vérification post-fusion.

## Périmètre du prérequis

Le bundle construit par ce contrôleur contient la qualification et l’audit BASE finaux. Il satisfait les besoins de #171, dont le package n’exige ni runtime ni récupération. La clôture des packages qui les exigent reste bloquée sans les véritables preuves et producteurs enregistrés. Les revues CODE et SECURITY sont relues auprès de GitHub par leur vérificateur canonique.

La planification M7, son package, les nouveaux niveaux de risque et sa publication enrichie restent dans #171. Les schémas de capacités inclus ici permettent au validateur de work-package de vérifier des paramètres bornés ; les commandes exécutables restent définies par la BASE vérifiée.

Cette PR préalable est qualifiée et revue sur son SHA exact, puis fusionnée par le contrôleur BASE existant. Après sa fusion, #171 réintègre `main` et reçoit une nouvelle qualification et de nouvelles revues. Aucun témoin rétroactif n’est revendiqué pour la première installation des primitives.

## Vérification et retour arrière

Les tests couvrent la signature et la relecture des preuves, les archives divergentes, les relations et dépendances d’issues, l’ordre témoin/fusion, la récupération, l’échec de clôture et le refus d’un succès fondé seulement sur GitHub `MERGED`.

Le retour arrière passe par une PR de revert signée, qualifiée et revue ; les preuves et témoins existants restent conservés.
