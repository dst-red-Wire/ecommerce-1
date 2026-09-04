# Privacy by Design et Data Policy

Les sources machine-readable sont
[`governance/controls.yaml`](../../governance/controls.yaml) et
[`governance/data-policy.yaml`](../../governance/data-policy.yaml). Cette policy
implémente `PRIV-001`, `PRIV-002`, `PRIV-003`, `DATA-001`, `DATA-002`,
`DATA-003` et `DATA-004`. Elle ne constitue pas un avis juridique.

## Classification

| Classe | Usage | Protection minimale |
|---|---|---|
| `PUBLIC` | publication approuvée | intégrité et TLS |
| `INTERNAL` | activité interne | accès authentifié et stockage géré |
| `CONFIDENTIAL` | besoin métier explicite | chiffrement transit/repos, logs minimisés |
| `RESTRICTED` | dommage élevé ou donnée réglementée | least privilege audité, chiffrement, pas de valeur dans les logs |

PII, credentials, auth tokens, PSP tokens et toute cardholder data sont
`RESTRICTED`. Le public catalog n'est `PUBLIC` qu'après approbation de
publication.

## Inventaire et cycle de vie

Chaque dataset documente purpose, owner role, source, destinataires, personal
data boundary, classification, accès, chiffrement, retention, deletion, backup,
restore et restrictions lower-environment. Seules les données nécessaires à la
finalité sont collectées. Les exports sont bornés, autorisés et audités.

Les durées inconnues restent
`TBD_REQUIRES_BUSINESS_OR_LEGAL_APPROVAL`; aucune durée légale ou métier n'est
inventée. L'audit doit démontrer la suppression et traiter les copies/backups
selon la décision approuvée.

DEV, integration et preproduction utilisent des données synthétiques ou
anonymisées par défaut. Toute exception sur des PII réelles est ciblée,
chiffrée, expirante et revue. Les logs ne contiennent ni credentials, tokens,
payment data, secrets, ni PII non nécessaire.

## Droits, DPIA et tiers

L'architecture doit permettre recherche, export, correction, restriction et
suppression contrôlées sans accès direct non audité aux bases. Une nouvelle
surveillance systématique, donnée sensible, décision automatisée à impact,
croisement à grande échelle ou frontière tierce déclenche une revue DPIA par le
rôle `privacy`. L'inventaire des processors reste explicitement TBD tant que la
décision business/legal n'existe pas.

## Payment data

Le design par défaut utilise un PSP externe et la tokenisation pour minimiser le
scope PCI. Le CVV ne doit jamais être persisté, même chiffré. Le PAN brut ne
doit pas entrer dans nos systèmes si le PSP l'évite. Les PSP tokens sont
`RESTRICTED`. Logs, traces, events et DLQ ne contiennent aucune donnée carte.

Toute introduction réelle de cardholder data déclenche avant code un nouveau
gate architecture/security/compliance et une détermination de scope PCI DSS.
