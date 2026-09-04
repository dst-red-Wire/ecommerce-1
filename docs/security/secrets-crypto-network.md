# Secrets, Cryptographic Baseline et Network Security

La source canonique est [`governance/controls.yaml`](../../governance/controls.yaml),
contrôles `SEC-003`, `NET-001`, `NET-002` et `CRYPTO-001`.

## Secrets

L'unique emplacement local canonique des secrets réels est
`$HOME/.config/ecommerce-1/.env`, hors dépôt et hors OneDrive. Les secrets ne
doivent apparaître ni dans Git, logs, image layers, artifacts, plans/state
Terraform lorsque évitable, ni arguments de processus. Ils sont séparés par
environnement, exposés au minimum, rotatables et jamais partagés durablement en
production. SOPS + age reste la cible pour des secrets GitOps chiffrés lorsque
pertinent ; cette policy ne change pas le contrat actuel.

## Cryptographic baseline

TLS est requis sur les interfaces externes ; mTLS interne est la cible quand
Istio le fournit. TLS `1.0` et `1.1` sont interdits. TLS `1.3` est supporté et
préféré ; QUIC utilise TLS `1.3`. Certificate validation et hostname verification
sont obligatoires. Les clés privées ne sont jamais loggées, le random est
cryptographiquement sûr et la rotation est prévue.

Aucune custom crypto n'est autorisée. Une baseline algorithmique séparée doit
être versionnée et renouvelable : la crypto agility évite une liste figée qui
deviendrait obsolète sans revue.

## Réseau

Ingress et egress sont default-deny lorsque possible, puis autorisés
explicitement. Les bases ne sont jamais publiques. L'accès management est
restreint, SSH est limité et orienté break-glass, et aucun lateral movement n'est
implicite. Le service mesh porte mTLS interne.

Le public edge conserve TCP/443 pour H2/H1 et gouverne séparément UDP/443 pour
HTTP/3. Cette exigence n'autorise aucune ouverture réseau dans ce milestone ;
l'ADR edge demeure `NOT_PROVEN_RUNTIME`.
