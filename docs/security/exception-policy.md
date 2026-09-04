# Risk Acceptance and Exception Policy

Le registre machine-readable est
[`governance/exceptions.yaml`](../../governance/exceptions.yaml) et les contrôles
restent dans [`governance/controls.yaml`](../../governance/controls.yaml),
notamment `COMP-002`.

Une exception contient obligatoirement :

- `id` et `control_id` existant ;
- `reason` et `risk` explicites ;
- `compensating_controls` non vides ;
- `scope` exact sans wildcard global ;
- `environments` bornés ;
- `approver_role` parmi les rôles gouvernés ;
- `reference`, `created_at` et `expires_at`.

Une exception permanente, expirée, sans justification, sans expiry ou globale
échoue au validator. Elle ne désactive pas le contrôle, ne transforme pas son
statut et ne vaut pas preuve runtime. Une annotation Kubernetes n'est reconnue
par Rego que si l'enregistrement correspondant existe et matche exactement
control, kind, namespace, name et environnement.

À expiration, le contrôle redevient bloquant sans action implicite. Le
renouvellement est une nouvelle décision de risque avec une nouvelle revue. Les
contrôles dont `exception_allowed: false` ne peuvent pas être dérogés.
