# Gouvernance sécurité, privacy et supply chain

La source de vérité structurée est [`governance/controls.yaml`](../../governance/controls.yaml).
Les catalogues auxiliaires décrivent les
[frameworks](../../governance/frameworks.yaml), les
[environnements](../../governance/environments.yaml), la
[classification des données](../../governance/data-policy.yaml) et les
[exceptions](../../governance/exceptions.yaml). Aucun autre document ne remplace ces fichiers.

## Portée et claims

Ce socle applique Secure by Design, Secure by Default, Privacy by Design,
Zero Trust, Least Privilege, Deny by Default, Defense in Depth et une approche
evidence-driven. Il ne certifie pas ecommerce-1. Un mapping ISO/IEC 27001:2022,
NIST, OWASP ASVS, SLSA, GDPR ou PCI DSS n'est ni un audit, ni une certification,
ni un avis juridique.

Le modèle sépare :

- `DOCUMENTED`, `STATICALLY_ENFORCED`, `RUNTIME_ENFORCED`, `PLANNED` pour
  l'enforcement ;
- `PROVEN_RUNTIME`, `NOT_PROVEN_RUNTIME`, `NOT_APPLICABLE` pour la preuve ;
- `PROVISIONAL_RUNTIME_PASS` et `NOT_MIGRATED` uniquement dans le registre de
  transition runtime explicitement verrouillé.

Une policy écrite peut être `DOCUMENTED` et rester `NOT_PROVEN_RUNTIME`. Une
validation Rego peut être `STATICALLY_ENFORCED` et rester `NOT_PROVEN_RUNTIME`.
`EXCEPTION` est un état de décision attaché à une dérogation expirante, jamais
un substitut à ces deux axes.

## Baselines normatives

- SLSA `v1.2`, statut `Approved`, pour Build Track, Source Track, provenance et
  verification ;
- NIST SP 800-218 / SSDF `1.1`, statut `Final`, comme baseline SDLC ;
- NIST SP 800-218 Rev. 1 / SSDF `1.2`, statut `Draft`, surveillé mais non utilisé
  comme baseline finale ;
- OWASP ASVS `5.0.0`, stable, pour les exigences application, web et API ;
- NIST CSF `2.0` pour les outcomes de gouvernance et de risque ;
- ISO/IEC 27001:2022 uniquement comme mapping informatif ;
- GDPR/RGPD comme baseline de conception privacy, sans claim juridique ;
- PCI DSS uniquement si le périmètre cardholder data le rend applicable ;
- CIS Controls/Benchmarks uniquement après vérification de la version de chaque
  cible, sans numéro inventé.

Les contrôles pivots sont `ARCH-001`, `COMP-001`, `COMP-002` et `OBS-002`.

## Validation canonique

```sh
make governance
make ci
```

Le validator refuse notamment les IDs dupliqués, statuts invalides, framework
inconnu, evidence path invalide, preuve runtime sans evidence et exception
expirée. Les résultats générés, scans et rapports restent hors Git.
