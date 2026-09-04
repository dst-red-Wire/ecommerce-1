# Resilience, Evidence, Audit et Change Management

La source canonique est [`governance/controls.yaml`](../../governance/controls.yaml),
contrôles `IAM-003`, `OBS-001`, `OBS-002`, `RES-001`, `RES-002` et `COMP-003`.

## Recovery

Chaque state critique définit backup, copie off-host, chiffrement, integrity,
restore-test et owner role. RPO/RTO doivent être décidés avant production ; ils
restent `TBD_REQUIRES_BUSINESS_APPROVAL` tant que le business ne les approuve
pas. Un backup non restauré ne vaut pas preuve.

Idempotence, bounded retry, DLQ, dependency failure, locking, reboot persistence
et state integrity ont des tests distincts. `reboot persistence` reste
`PROVISIONAL_RUNTIME_PASS` jusqu'à sa revue indépendante séparée.

## Evidence-driven engineering

```text
static validation -> JIT runtime probe -> sanitized evidence
                  -> independent review -> PROVEN_RUNTIME
```

`Documentation compatibility != Runtime proof`. Une preuve est scoped,
reproductible, horodatée, sanitized, hashée lorsque pertinent, reviewable et
liée au contrôle. Les types admis incluent test, policy test, config, Terraform
plan review, runtime probe, scanner output, SBOM, provenance, signature
verification et independent review.

## Logging et audit

Les logs structurés portent correlation IDs, authn/authz decisions, security
events, admin actions, source commit, image digest, deployment provenance,
protocol h1/h2/h3 et timestamps synchronisés. Ils n'exposent aucun secret,
credential, auth token, payment data ou PII inutile. Audit retention reste
`TBD_REQUIRES_BUSINESS_OR_LEGAL_APPROVAL`.

## Incident et break-glass

L'accès d'urgence est attribuable, minimal, temporaire et audité. Aucun shared
emergency credential permanent n'est autorisé. Après incident, les actions sont
revues et réconciliées dans Git/Terraform/Ansible/GitOps.

## Change management

Les changements infrastructure significatifs suivent obligatoirement :

```text
plan -> Independent Reviewer -> Human Gate -> apply
```

Les mutations payantes, destructives, cloud ou runtime demandent une
autorisation séparée. Un gate humain non franchi ne peut pas être simulé par un
test statique ou une policy.
