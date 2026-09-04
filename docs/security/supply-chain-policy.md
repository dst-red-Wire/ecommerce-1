# Software Supply Chain Security

La source de vérité est [`governance/controls.yaml`](../../governance/controls.yaml),
contrôles `SUPPLY-001` à `SUPPLY-005` et `SDLC-003`.

## Baseline et maturité SLSA

SLSA `v1.2` `Approved` est le modèle. Le projet ne revendique actuellement
aucun niveau Build ou Source. Pour chaque artifact production, la cible est :

```text
baseline
  -> provenance liée au digest
  -> provenance authentifiée
  -> isolated/trusted builder avec génération non forgeable
  -> verification avant déploiement
```

`TARGET_SLSA_BUILD_LEVEL = L3` est conditionnel : il devient une claim seulement
si le builder final prouve hosted build, provenance authentique et non forgeable,
isolation entre builds, environnement éphémère, protection de la signing identity
et absence de persistance/cache poisoning. Tekton/Chains compatible ne suffit
pas. L'état courant reste `NOT_PROVEN_RUNTIME`.

Le Source Track mesure séparément version control, immutable revision, change
history, source provenance, contrôles organisationnels et code review. Les
protections Git/Gitea/GitHub doivent fournir la preuve par branche ; le présent
mapping ne revendique aucun Source Level.

## Artifact contract

Chaque image production doit avoir :

- un digest OCI retourné par le registry ;
- un SBOM CycloneDX ou SPDX lié à ce digest ;
- un scan de vulnérabilités associé ;
- une provenance de build archivée ;
- une signature et des attestations vérifiables ;
- la relation source commit, builder identity, artifact digest et GitOps digest.

Sigstore/Cosign ou un mécanisme équivalent signe images, provenance et SBOM.
OIDC/keyless est préféré lorsque l'environnement le permet, mais reste
`PLANNED / REQUIRES_RUNTIME_VALIDATION`. Aucune clé réelle ni service n'est
provisionné par cette policy.

## Promotion

```text
build -> scan -> SBOM -> provenance -> signature -> verification
      -> registry digest -> GitOps digest -> Flux deployment
```

Harbor/GHCR conservent des tags humains, mais seul le digest est autoritatif.
Production interdit `latest`, un rebuild distinct par environnement et une
promotion sans vérification. Les registries sont explicitement approuvés.

Sources, dependencies, build tools et base images sont pinnés ; lockfiles et
checksums sont obligatoires. Les scans source, secret, dependency, container et
IaC échouent selon la policy. Aucun finding ignoré ne disparaît du registre : il
requiert une exception expirante.
