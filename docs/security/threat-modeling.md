# Threat Modeling policy

La source canonique du contrôle est
[`governance/controls.yaml`](../../governance/controls.yaml) (`ARCH-002`). Le
[template](threat-model-template.md) et le
[threat model global](../architecture/threat-model.md) sont les artefacts de référence.

## Méthode

La revue décrit assets, actors, trust boundaries, data flows, entry points et
emploie STRIDE : Spoofing, Tampering, Repudiation, Information Disclosure,
Denial of Service et Elevation of Privilege. Chaque menace possède likelihood,
impact, risk, mitigation, residual risk, owner role, evidence attendue et statut.

Le modèle est mis à jour lors de toute nouvelle frontière, identité, donnée
`RESTRICTED`, intégration tierce, protocole, pipeline, permission, stockage ou
mode de recovery. Les changements e-commerce évaluent explicitement fraude,
replay et manipulation de logique métier, pas seulement les CVE techniques.

## Workflow

1. L'owner de design prépare le delta avec le template.
2. `security`, `privacy`, `data` ou `platform` participent selon la portée.
3. Les mitigations deviennent des acceptance criteria et contrôles testables.
4. Le risque résiduel non acceptable bloque ; un risque temporaire suit
   `COMP-002` et ne devient jamais une exclusion silencieuse.
5. Le runtime est validé séparément. `DOCUMENTED` n'implique jamais
   `PROVEN_RUNTIME`.

Une revue indépendante est obligatoire pour les risques critiques, les gates
payment/cardholder data, les changements identity/admin, les builders et les
preuves runtime critiques.
