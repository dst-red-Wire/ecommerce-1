# Secure by Design, Secure by Default et Secure SDLC

La policy canonique est [`governance/controls.yaml`](../../governance/controls.yaml),
notamment `ARCH-001`, `SEC-001` et `SDLC-001`.

## Gate avant implémentation

Tout nouveau composant significatif ou changement de trust boundary fournit
avant le code :

- assets et responsables par rôle ;
- trust boundaries, data flows et entry points ;
- authentication, authorization et workload identity ;
- secrets, classification et personal-data boundaries ;
- failure modes, abuse cases et delta de threat model ;
- logging, audit, recovery et dépendances ;
- risques résiduels et security/privacy acceptance criteria.

Le flux obligatoire est :

```text
design
  -> threat/security/privacy review
  -> implementation
  -> unit/integration tests
  -> static/SAST/secret/dependency/IaC/policy validation
  -> SBOM/provenance/signature
  -> staging runtime validation
  -> human/policy promotion
  -> production
  -> continuous monitoring
```

Une architecture critique ne passe jamais directement de `idea` à `code`.
Le reviewer peut exiger le [template de threat model](threat-model-template.md),
une revue privacy ou un gate payment avant d'autoriser l'implémentation.

## Secure by Default

Les defaults sont deny-by-default et least-privilege. L'authentification est
requise sauf ressource explicitement publique. Il n'existe aucun credential
admin par défaut, base publique, secret en clair, debug production ou exposition
réseau implicite. Le chiffrement et les secure headers sont activés par défaut.
La télémétrie production exclut secrets, tokens, payment data et PII inutile.

Les opérations destructives requièrent un gate. Les retries sont bornés, les
consommateurs de messages sont idempotents et les événements non traitables
rejoignent une DLQ ; ces propriétés devront être précisées par service avec le
pattern CQRS + Outbox + RabbitMQ retenu au moment de leur création.

## Critères d'acceptation

Le changement doit pointer vers les tests, configs ou probes qui prouvent chaque
critère. Une incompatibilité est corrigée avant promotion ou enregistrée via la
[policy d'exception](exception-policy.md). Aucune dérogation ne peut contourner
silencieusement une validation.
