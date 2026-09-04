# Fondation backend Terraform PostgreSQL — runbook avant mutation

Ce runbook décrit des gates ordonnés. Il ne constitue jamais une autorisation
d'`apply`, de migration ou de mutation distante.

## 1. Architecture retenue

La trajectoire est Hetzner uniquement :

```text
Terraform WSL / future CI
          |
          | SSH tunnel + TLS verify-full
          v
terraform-state-mgmt (PostgreSQL 16, loopback)
          |
          +-- terraform_management.states (workspace default)
          +-- PostgreSQL advisory locks
          +-- terraform_lock_probe.states
          |
          +-- volume Hetzner 10 Go protégé

Hetzner Object Storage existant
          +-- backups age + preuves, jamais locking autoritatif
```

`terraform-state-mgmt` est distinct de `data-mgmt`, des bases Gitea/Harbor et de
CloudNativePG applicatif. AWS et HCP Terraform sont `NOT_SELECTED`. Le locking
S3 Hetzner est `INCOMPATIBLE`; le locking PostgreSQL est la cible mais reste
`NOT_PROVEN_RUNTIME` avant le gate 7.

## 2. Validation locale — exécutable maintenant

Depuis WSL et la racine du dépôt :

```sh
terraform version
make test-management-foundation
make terraform
git diff --check
```

Ces commandes utilisent `terraform init -backend=false`, des `TF_DATA_DIR`
temporaires et l'inventaire d'exemple. Elles n'ouvrent aucun tunnel, ne
contactent aucun serveur et ne créent aucune ressource.

## 3. GATE HUMAIN — plan bootstrap payant

Préparer sans afficher les valeurs :

```sh
: "${HCLOUD_TOKEN:?HCLOUD_TOKEN is required}"
: "${TF_VAR_ssh_key_name:?existing Hetzner SSH key name is required}"
: "${TF_VAR_ssh_allowed_cidrs:?approved IPv4 CIDR JSON list is required}"
: "${BOOTSTRAP_PLAN_PATH:?absolute plan path outside repository and OneDrive is required}"
```

Commande exacte du prochain gate :

```sh
./scripts/terraform-state-bootstrap-state.sh init
./scripts/terraform-state-bootstrap-state.sh terraform plan \
  -input=false \
  -out="${BOOTSTRAP_PLAN_PATH}"
```

Le caller choisit l'intention Terraform (`-var`, `-var-file`, `-target`,
`-refresh`, `-out`), jamais son emplacement de state. Le wrapper rejette les
formes séparées ou `=` de `-state`, `-state-out` et `-backup` (simple ou double
tiret), neutralise `TF_CLI_ARGS*`, force le workspace `default` et remplace
`TF_DATA_DIR` par son répertoire autoritatif. `BOOTSTRAP_STATE_DIR` est
neutralisé : le slug du composant fixe seul le répertoire final.
`XDG_STATE_HOME`, s'il est fourni, doit être absolu, sous le home réel issu de
l'identité système, et toute la chaîne contrôlée doit être owner courant, sans
write group/other ni symlink. Le chemin `-out` reste autorisé, mais doit être
extérieur au répertoire state et ne peut pas se résoudre vers le state ou son
backup.

Revoir : une VM `cx23` x86 à `nbg1`, Ubuntu 24.04, une Primary IPv4, un
firewall avec seulement SSH 22 depuis les CIDR approuvés, un volume `ext4` de
10 Go et toutes les protections. Confirmer l'absence de port 5432, de réseau
management et de toute autre ressource. Confirmer le coût courant.

**STOP.** Ne pas exécuter le plan sans approbation distincte.

## 4. GATE HUMAIN — apply bootstrap futur

Après revue explicite seulement :

```sh
./scripts/terraform-state-bootstrap-state.sh terraform apply "${BOOTSTRAP_PLAN_PATH}"
```

Cette commande crée des ressources facturables. Immédiatement après, produire
un backup `age` du state bootstrap puis exécuter son `restore-test`. Le backup
secondaire vers Object Storage exige auparavant un plan/revue séparé de la
nouvelle policy archive ; ne jamais dépendre du locking S3.

## 5. Inventaire bootstrap séparé

Après apply autorisé, obtenir d'abord l'empreinte Ed25519 directement dans la
**console Hetzner** (pas en SSH) :

```sh
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
```

Reporter cette valeur par le canal local contrôlé. Le script suivant relit
l'IPv4 depuis le state externe autoritatif, compare la clé scannée à cette
empreinte indépendante, puis crée un `known_hosts` dédié `0600` hors
dépôt/OneDrive. Il n'emploie jamais `StrictHostKeyChecking=no` :

```sh
export TERRAFORM_STATE_SSH_HOST_KEY_FINGERPRINT='SHA256:REPLACE_FROM_HETZNER_CONSOLE'
export TERRAFORM_STATE_KNOWN_HOSTS=/secure/terraform-state/known_hosts
./scripts/pin-terraform-state-ssh-host-key.sh
```

Rendre ensuite l'inventory uniquement par l'interface sûre. Aucun
`terraform output` direct dans le root bootstrap n'est autorisé :

```sh
./scripts/terraform-state-bootstrap-state.sh output-inventory \
  | python3 scripts/render-terraform-state-inventory.py \
      --known-hosts "$TERRAFORM_STATE_KNOWN_HOSTS" \
  > infrastructure/ansible/inventory/terraform-state.generated.yml

ansible-inventory \
  -i infrastructure/ansible/inventory/terraform-state.generated.yml \
  --list >/dev/null
```

L'inventaire généré est ignoré par Git. Il ne rejoint jamais
`management.generated.yml`. `output-inventory` échoue si le state externe est
absent/non sûr, si `inventory_contract` manque ou si son schema d'identité est
invalide. Le renderer lie strictement `server_id`, nom, IPv4, `volume_id` et
`/dev/disk/by-id/scsi-0HC_Volume_<volume_id>`.

## 6. GATE HUMAIN — Ansible PostgreSQL

Le contrat de secrets autoritatif est le fichier unique
`$HOME/.config/ecommerce-1/.env`, hors dépôt, hors OneDrive et hors `/mnt/c`.
Le fichier versionné `.env.example` documente uniquement les noms attendus et
reste vide de toute valeur réelle. Aucun `secrets.yml` Ansible Vault n'est
utilisé pour terraform-state.

Lors du gate humain `GENERATE CENTRAL PROJECT SECRETS`, vérifier que
`age-keygen` est installé, puis exécuter une seule fois le helper. Le helper
crée le répertoire en `0700`, le fichier en `0600`, refuse tout symlink et
n'écrase rien sans `--force` explicite. Il génère le mot de passe, l'identity
age privée et son recipient public sans afficher les deux valeurs secrètes :

```sh
./scripts/init-project-secrets.sh
```

Ce helper n'a pas été exécuté pendant la mise en place du mécanisme. L'identity
`TERRAFORM_STATE_BACKUP_AGE_IDENTITY` reste exclusivement sur le control node ;
Ansible ne lit que `TERRAFORM_STATE_POSTGRESQL_PASSWORD` et le recipient public
`TERRAFORM_STATE_BACKUP_AGE_RECIPIENT`.

Valider localement le fichier, y compris la dérivation exacte
identity/recipient avec `age-keygen -y`, sans afficher l'identity :

```sh
python3 scripts/run-with-project-env.py --check-only
```

Puis, seulement après revue et autorisation du gate distant, exécuter Ansible
via le même loader sans `source`, `eval` ni interprétation shell du fichier :

```sh
python3 scripts/run-with-project-env.py -- \
  ansible-playbook \
    -i infrastructure/ansible/inventory/terraform-state.generated.yml \
    infrastructure/ansible/terraform-state.yml
```

Le loader refuse un fichier absent, hors ownership/permissions attendus, un
symlink ou un emplacement interdit. Avant le premier rôle mutatif, le playbook
vérifie encore la présence, la longueur et l'absence de placeholder du mot de
passe ainsi que la forme et l'absence de placeholder du recipient public. Il
compare ensuite l'ID, le nom et l'IPv4 aux
endpoints metadata Hetzner link-local, puis vérifie que le symlink de volume
dérivé de `volume_id` désigne bien un block device. Une metadata indisponible
ou différente bloque donc avant `apt`, SSH, firewall, mount et PostgreSQL.
Après ce gate, le playbook monte le volume, applique nftables default-deny,
durcit SSH tout en conservant `AllowTcpForwarding local`, puis installe PostgreSQL 16. Il
configure loopback, TLS, SCRAM, logs JSON, la base dédiée, les deux schemas et
les droits DML minimaux.

**BACKLOG / FIX BEFORE PRODUCTION :** harmoniser ultérieurement les secrets
management, Gitea et Harbor avec ce contrat central. Cette migration est hors
du milestone terraform-state et leurs mécanismes actuels ne sont pas modifiés
ici.

Copier ensuite uniquement la CA publique dans un chemin WSL sécurisé hors
dépôt/OneDrive et vérifier son empreinte par un second canal. La clé CA reste
sur le serveur.

## 7. GATE RUNTIME — tunnel, santé et advisory locking

Ouvrir un tunnel local ; aucun `5432` public n'est nécessaire :

```sh
ssh -F /dev/null \
  -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$TERRAFORM_STATE_KNOWN_HOSTS" \
  -N -L 15432:127.0.0.1:5432 root@TERRAFORM_STATE_PUBLIC_IPV4
```

Dans un autre terminal, fournir la connexion sans mot de passe dans l'URL :

```sh
export PG_CONN_STR='postgres://terraform_backend@127.0.0.1:15432/terraform_backend?sslmode=verify-full'
export TERRAFORM_PG_TUNNEL_HOST=127.0.0.1
export TERRAFORM_PG_TUNNEL_PORT=15432
export PGSSLROOTCERT=/secure/terraform-state/ca.crt
read -r -s PGPASSWORD
export PGPASSWORD
export TERRAFORM_PG_LOCKING_EVIDENCE=/secure/evidence/pg-locking-YYYYMMDD.json
./scripts/test-terraform-pg-locking.sh
```

L'URL canonique n'autorise que scheme, rôle, IPv4 de tunnel, port attendu,
database et l'unique paramètre `sslmode=verify-full`; mot de passe, CA,
overrides, doublons, fragments et paramètres inconnus sont refusés. Le harness
échoue avant tout PASS si TLS/auth/schema ne fonctionnent pas et exige aussi le
rejet d'une mauvaise CA et d'un hostname absent des SAN. Il
observe directement le lock de A dans `pg_locks`, vérifie que deux processus B
distincts échouent pour locking, annule A proprement, observe la disparition du
lock puis exige le succès après libération. Avant ce résultat :

```text
PostgreSQL advisory locking: NOT_PROVEN_RUNTIME
```

## 8. GATE — inspection du state management

Utiliser un credential Object Storage de lecture sans l'afficher :

```sh
export BUCKET_NAME=ecommerce-management-tfstate-20260820-70b94831
export MANAGEMENT_STATE_INSPECTION_EVIDENCE=/secure/evidence/management-state-inspection-YYYYMMDD.json
./scripts/inspect-management-state.sh
```

Le script vérifie les deux candidats locaux puis exécute un
`ListObjectVersions` authentifié et paginé sur la key exacte
`ecommerce/management/terraform.tfstate`. Il collecte uniquement key,
`versionId`, `latest`, delete marker et date — jamais le payload du state. Une
version active, ancienne ou masquée par un delete marker donne
`HISTORICAL_STATE_PRESENT`. Échec API, permission insuffisante, pagination
incomplète ou réponse ambiguë donnent `UNKNOWN`. Un GET/404 simple ne prouve
jamais l'absence historique et `initialize-empty` exige `ZERO_HISTORY`.

## 9. GATE HUMAIN — initialisation ou migration

Un reviewer transforme une copie externe de
`state-activation-decision.example.json` en preuve `HUMAN_APPROVED`, liée par
SHA-256 à l'inspection.

- Si les deux sources locales sont absentes et l'historique exact vaut
  `ZERO_HISTORY` : décision `initialize-empty`.
- Si une source existe : **STOP**, comparer lineage/serial/resource count et
  concevoir une migration séparée. Aucune migration n'est couverte ici.
- Si l'historique est `UNKNOWN` : **STOP**, rétablir une inspection authentifiée
  complète ; aucune approbation ne peut contourner ce verdict.

La décision doit également confirmer `postgresqlTargetExpectedEmpty: true` et
`postgresqlWriterFreezeConfirmed: true`. Ce freeze opérateur couvre la fenêtre
TOCTOU résiduelle : aucun advisory lock maison ne serait respecté par Terraform
ou un autre client, donc aucun writer management ne doit être actif pendant le
preflight, `init` et le contrôle post-init.

Pour l'initialisation vide uniquement :

```sh
export MANAGEMENT_STATE_ACTIVATION_DECISION=/secure/evidence/management-state-decision.json
./scripts/init-terraform-pg-backend.sh
```

L'initialiseur exige des preuves récentes et inspecte la base, le rôle, le
schema, la table, ses colonnes/index, le nombre de rows et leurs noms sans
afficher `data`. `NON_EMPTY` et `UNKNOWN` bloquent. Après `terraform init`, il
réinspecte immédiatement et n'accepte que zéro row ou l'unique row `default`
dont les propriétés vides ont été dérivées côté PostgreSQL, sans afficher le
JSON. Il n'appelle jamais `-migrate-state`.

## 10. GATE HUMAIN — plan management

Après activation `pg` réussie seulement :

```sh
terraform -chdir=infrastructure/hetzner/management plan \
  -input=false \
  -lock-timeout=30s
```

Revoir entièrement le plan. Un `apply` management est un gate ultérieur.

## Backup et recovery

Sur le serveur, `/usr/local/sbin/terraform-state-backup` produit un `pg_dump`
custom chiffré `age` et un manifeste SHA-256, sans conserver le dump plaintext.
Après copie sécurisée hors VM et archivage sous
`ecommerce/backups/postgresql/`, tester localement :

```sh
export AGE_IDENTITY_FILE=/secure/age/identity.txt
./scripts/test-terraform-state-postgresql-backup.sh \
  /secure/backups/terraform-state-postgresql-YYYYMMDDTHHMMSSZ.manifest.json
```

Le test déchiffre temporairement, vérifie les deux hashes et le catalogue
`pg_restore`, puis efface le plaintext. Une vraie restauration exige gel des
writers, preuve de perte, backup testé, cible isolée et approbation humaine ;
elle n'est pas automatisée par ce milestone.

## FIX BEFORE PRODUCTION

- automatiser la fréquence, la rétention, l'upload et l'alerte backup ;
- définir et tester RPO/RTO et restore drill complet ;
- superviser PostgreSQL, volume, certificats, backups et saturation ;
- rotation automatique des certificats et credentials ;
- connectivité privée/VPN ou tunnel CI durci ;
- stratégie HA/réplication si le besoin de disponibilité l'exige ;
- revue à deux personnes pour recovery et changements de policy archive.

## BACKLOG non bloquant

CloudNativePG applicatif, Redis sans consommateur, Backstage, Coder,
Crossplane, Tekton/Harbor et autres environnements restent hors de ce milestone.
