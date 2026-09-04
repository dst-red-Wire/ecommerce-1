# Immutable Infrastructure, Reproducibility et Zero Trust

La policy canonique est [`governance/controls.yaml`](../../governance/controls.yaml),
notamment `ARCH-003`, `SEC-002`, `IAM-001`, `IAM-002`, `IMM-001` et `IMM-002`.

## Modèle d'état

- un application artifact production est immuable et référencé par digest ;
- l'infrastructure est déclarative via Git + Terraform + Ansible + GitOps selon
  sa couche ;
- les données stateful persistantes sont sauvegardées et restaurables, pas
  détruites pour satisfaire une définition dogmatique de l'immutabilité ;
- une réparation break-glass est temporaire, auditée puis réconciliée dans la
  source déclarative.

`PROD infrastructure MUST NOT be manually mutated during normal operations`.
Toute correction durable retourne dans Git. Une mutation d'urgence suit la
policy incident et ne crée jamais de drift permanent.

## Reproductibilité

Terraform et providers utilisent versions/lockfiles ; les modules sont pinnés.
Ansible core, collections et tooling sont verrouillés. Les images de base et
outils utilisent versions, digests ou checksums exacts. Les build dependencies
ont leurs lockfiles. Les generated files ont des inputs explicites, les defaults
cachés dépendants de l'environnement sont interdits et la promotion réutilise le
même digest.

Quand le byte-for-byte n'est pas réalisable, le statut reste
`REPRODUCIBILITY_TARGET` avec le delta documenté et testable.

## Zero Trust

La localisation réseau seule n'accorde aucune confiance. Keycloak porte les
identités user/admin prévues, Istio la cible service identity + mTLS, et OPA les
décisions explicites. Chaque workload, pipeline, base, registry et cloud API a
une identité et des permissions minimales. Les credentials courts sont préférés
et aucun credential production partagé longue durée n'est accepté.

DEV, integration, preproduction, production et management ont des secrets,
credentials, policies et data boundaries distincts. Aucun state n'est réutilisé
directement entre environnements. La segmentation et la vérification continue
limitent le lateral movement.
