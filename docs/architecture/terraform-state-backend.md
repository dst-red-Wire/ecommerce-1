# ADR — backend Terraform management sur PostgreSQL dédié

Statut : **ACCEPTED / RUNTIME LOCKING NOT_PROVEN_RUNTIME**
Date : 2026-08-20

## Décision

Le state Terraform du management plane utilise le backend intégré `pg` de
Terraform 1.15.5 sur un PostgreSQL 16 dédié, hébergé par
`terraform-state-mgmt`. Hetzner Object Storage reste un stockage secondaire de
backups chiffrés et de preuves. AWS et HCP Terraform ne sont pas sélectionnés.

Cette instance PostgreSQL ne contient aucune base Gitea, Harbor, Backstage,
e-commerce ou applicative. Elle existe avant et indépendamment du management
plane.

## Vérification Terraform 1.15.5

La [documentation officielle du backend `pg`](https://developer.hashicorp.com/terraform/language/backend/pg)
et la [source exacte `v1.15.5`](https://github.com/hashicorp/terraform/blob/v1.15.5/internal/backend/remote-state/pg/backend.go)
établissent :

- PostgreSQL 10 ou supérieur ; la base doit déjà exister ;
- `conn_str`, `schema_name` et les trois options `skip_*_creation` ;
- `PG_CONN_STR`, `PG_SCHEMA_NAME`, `PG_SKIP_SCHEMA_CREATION`,
  `PG_SKIP_TABLE_CREATION`, `PG_SKIP_INDEX_CREATION` et les variables libpq ;
- une table `states` indexée par le nom de workspace ; sans workspace nommé,
  la clé est `default` ;
- le locking via advisory locks PostgreSQL ; `force-unlock` n'est pas supporté,
  car la fin de session libère le lock ;
- les colonnes `id bigint`, `name text`, `data text` et l'index unique
  `states_by_name` ;
- dans la source 1.15.5, une séquence globale
  `public.global_states_id_seq` évite les collisions d'identifiants de lock
  entre schemas.

Le backend est donc configuré avec `schema_name = "terraform_management"` et
les trois `skip_*_creation = true`. Ansible crée les objets exacts avant
activation. Le rôle runtime ne reçoit aucun droit DDL.

## Connexion et secrets

Le bloc HCL ne contient aucune connexion. Le runtime fournit :

- `PG_CONN_STR`, URL sans mot de passe vers le port local du tunnel et avec
  `sslmode=verify-full` ;
- `PGPASSWORD`, secret séparé ;
- `PGSSLROOTCERT`, CA publique vérifiée et stockée hors dépôt/OneDrive.
- `TERRAFORM_PG_TUNNEL_HOST=127.0.0.1` et un
  `TERRAFORM_PG_TUNNEL_PORT` canonique contrôlant le port explicite de l'URL.

Terraform 1.15.5 appelle directement `sql.Open("postgres", conn_str)` et son
`go.mod` fixe `github.com/lib/pq v1.10.3`. Dans cette version, l'environnement
est chargé avant la chaîne explicite et `ParseURL` utilise la première valeur
d'un paramètre URL dupliqué. Le guard parse donc structurellement une URL
canonique : `postgres`, rôle/base exacts, `127.0.0.1`, port attendu, aucun mot
de passe/fragment et l'unique paramètre `sslmode=verify-full`. Tous les autres
paramètres et variables PG concurrentes sont refusés ; seuls `PGPASSWORD` et
`PGSSLROOTCERT` restent externalisés.

Cette séparation suit l'avertissement officiel : les paramètres backend passés
par `-backend-config` peuvent être persistés dans `.terraform` et les plans.
Les secrets restent donc exclusivement dans l'environnement du processus.

## Privilèges minimaux

La [source du client `pg` 1.15.5](https://github.com/hashicorp/terraform/blob/v1.15.5/internal/backend/remote-state/pg/client.go)
montre que le runtime exécute `SELECT`, `INSERT ... ON CONFLICT UPDATE`,
`DELETE`, `pg_try_advisory_lock` et `pg_advisory_unlock`.

| Objet | Privilèges du rôle `terraform_backend` |
|---|---|
| base `terraform_backend` | `CONNECT` |
| schema `public` | `USAGE` uniquement |
| `public.global_states_id_seq` | `USAGE` |
| schemas `terraform_management`, `terraform_lock_probe` | `USAGE`, sans `CREATE` |
| tables `<schema>.states` | `SELECT`, `INSERT`, `UPDATE`, `DELETE` |
| fonctions advisory-lock `pg_catalog` | privilège d'exécution PostgreSQL standard |

Le rôle est `NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
NOBYPASSRLS`. `PUBLIC` perd ses droits sur la base, les schemas, la séquence et
les tables concernées.

## Réseau et persistance

PostgreSQL écoute uniquement `127.0.0.1:5432`. Le Cloud Firewall et nftables
n'ouvrent que SSH 22 depuis les CIDR explicitement approuvés. Le client WSL
utilise un tunnel `localhost -> 127.0.0.1:5432`; `hostssl` + SCRAM-SHA-256 et
`verify-full` restent obligatoires.

Les données sont sur un volume Hetzner protégé de 10 Go séparé de la VM. Cette
séparation facilite la reconstruction, mais les Volumes n'ont pas de backup
natif : `pg_dump` custom chiffré `age`, copie hors VM, archive Object Storage et
restore-test restent obligatoires.

## Preuve de locking

La documentation est une propriété attendue, pas une preuve runtime. Le harness
doit :

1. réussir TLS/auth/schema ;
2. observer directement le lock A dans `pg_locks` ;
3. faire échouer deux processus Terraform distincts pour cause de lock ;
4. vérifier que A reste vivant et que son lock ne change pas ;
5. annuler A proprement et observer la disparition du lock ;
6. faire réussir un client après libération.

Avant cette séquence, l'activation management est interdite et le statut reste
`NOT_PROVEN_RUNTIME`.

## Identité distante et activation vide

Le state bootstrap exporte les IDs, nom et IPv4 serveur ainsi que l'ID et le
by-id volume. Le premier play Ansible compare serveur/nom/IPv4 aux endpoints
metadata Hetzner link-local, puis le by-id dérivé du volume à un vrai block
device, avant tout rôle mutatif. La connexion elle-même exige un `known_hosts`
dédié lié à une empreinte Ed25519 relevée indépendamment depuis la console
Hetzner. Ces guards sont définis mais restent `NOT_PROVEN_RUNTIME` avant VM.

L'absence S3 requiert un `ListObjectVersions` authentifié, paginé et exact,
incluant versions anciennes et delete markers ; `UNKNOWN` ou tout historique
interdit `initialize-empty`. Juste avant `init`, le gate PG exige la table
`terraform_management.states` strictement vide et affiche seulement count et
noms de workspaces. Un contrôle post-init accepte uniquement l'état vide
attendu. Comme un advisory lock privé ne coordonnerait pas Terraform, un freeze
opérateur explicite borne la fenêtre TOCTOU résiduelle.

## Circularité et recovery

Le root qui crée `terraform-state-mgmt` conserve un state local autoritatif WSL
hors dépôt/OneDrive, avec SHA-256, lineage, serial, backup `age` et restore-test.
Il ne dépend jamais du PostgreSQL qu'il crée. Ainsi, une perte totale du serveur
n'empêche pas Terraform de reconstruire l'infrastructure et de rattacher le
volume ou de restaurer un backup éprouvé.

Ce state est confiné sous le home réel retourné par la base système de
l'utilisateur, et non sous un `HOME` fourni par le caller. Une éventuelle
racine `XDG_STATE_HOME` doit rester strictement sous ce home. Le helper parcourt
et crée les composants avec `dirfd` et `O_NOFOLLOW`, exige l'absence de write
group/other sur la chaîne, un owner système `root`/courant avant le home,
l'owner courant sous le home, `0700` sur les répertoires finaux, `0600` sur
state/backup et le même filesystem Linux que le home. Le wrapper fixe également
`TF_DATA_DIR`, le workspace `default` et les chemins `-state`/`-backup`,
neutralise `BOOTSTRAP_STATE_DIR`, puis rejette `-state`, `-state-out`, `-backup`
et leurs variantes avant invocation.
Une revalidation encadre Terraform. Cette garantie vise les substitutions par
un autre UID non privilégié ; elle ne prétend pas résister à `root` ni à un
processus déjà compromis sous le même UID.
