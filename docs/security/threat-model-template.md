# Threat model template

Ce template applique `ARCH-002` depuis
[`governance/controls.yaml`](../../governance/controls.yaml). Le document rempli
est versionné avec le design concerné et ne contient aucun secret.

```yaml
system: TBD
change_reference: TBD
owner_role: application
reviewer_roles: [security]
assets:
  - id: ASSET-001
    classification: INTERNAL
    description: TBD
actors:
  - id: ACTOR-001
    trust: untrusted
trust_boundaries:
  - id: TB-001
    from: TBD
    to: TBD
data_flows:
  - id: DF-001
    source: TBD
    destination: TBD
    protocol: TBD
    authentication: TBD
    data_classification: INTERNAL
entry_points:
  - id: EP-001
    exposure: TBD
threats:
  - id: THREAT-001
    stride: Spoofing
    abuse_case: TBD
    likelihood: TBD
    impact: TBD
    risk: TBD
    mitigations: [TBD]
    residual_risk: TBD
    evidence: [TBD]
    owner_role: security
    status: PLANNED
privacy_delta:
  personal_data: TBD
  purpose: TBD
  minimization: TBD
  retention_status: TBD_REQUIRES_BUSINESS_OR_LEGAL_APPROVAL
failure_modes: [TBD]
recovery: [TBD]
security_acceptance_criteria: [TBD]
approvals: []
```

Les valeurs `TBD` bloquent la promotion d'un composant significatif. La seule
valeur TBD admise durablement par le modèle de rétention est
`TBD_REQUIRES_BUSINESS_OR_LEGAL_APPROVAL`, qui signale une décision externe
encore manquante plutôt qu'une durée inventée.
