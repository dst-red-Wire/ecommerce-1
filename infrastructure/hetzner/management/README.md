# Permanent management plane

Ce root déclare la fondation d'intégration permanente, hors des clusters
Kubernetes applicatifs :

- `gitea-mgmt` (`cpx22`) : IPv4/IPv6 publiques, `10.30.0.10`, HTTPS public,
  administration SSH 22 et Git SSH 2222 limités aux CIDR approuvés ;
- `harbor-mgmt` (`cpx32`) : IPv4/IPv6 publiques, `10.30.0.20`, HTTPS public et
  administration SSH limitée ;
- `data-mgmt` (`cpx32`) : `10.30.0.30` uniquement, sans Primary IPv4/IPv6
  publique, pour PostgreSQL management exclusivement.

Le réseau et les VM activent les protections API delete/rebuild et
`prevent_destroy`. Une suppression exige donc une modification de code et un
plan destructif explicitement autorisé. Les types, la location `nbg1`, la zone
`deployfrance.com` et les labels DNS `git`/`registry` sont verrouillés sur
l'architecture revue.

## Frontière state et providers

Le backend est PostgreSQL `pg`, sur la base dédiée `terraform_backend`, le
schema `terraform_management` et le workspace `default`. Le serveur
`terraform-state-mgmt` est créé par un root bootstrap indépendant ; ce service
ne dépend ni de `data-mgmt`, ni de ce root management, ni de Kubernetes.

Terraform 1.15.5 lit la connexion depuis `PG_CONN_STR`. Le mot de passe reste
séparé dans `PGPASSWORD`; le bloc backend ne contient aucun credential. La
connexion initiale passe par un tunnel SSH local et impose
`sslmode=verify-full`. L'URL canonique fixe rôle, base, `127.0.0.1` et le port
déclaré par `TERRAFORM_PG_TUNNEL_PORT`; elle refuse overrides, doublons,
paramètres inconnus, mot de passe et CA embarqués. Ansible précrée schema, table et index ; les trois options
`skip_*_creation` empêchent d'accorder des droits DDL au rôle backend.

Le locking documenté utilise les advisory locks PostgreSQL, mais son statut
reste `NOT_PROVEN_RUNTIME`. `scripts/test-terraform-pg-locking.sh` doit observer
le lock dans `pg_locks`, rejeter deux clients concurrents et prouver la réussite
après libération. Ensuite seulement, une inspection `ListObjectVersions`
authentifiée de toute l'histoire de la key legacy et une décision humaine
`initialize-empty` ou migration peuvent autoriser l'activation. L'initialisation
vide exige aussi zéro row PG avant `init`, un freeze writers et un contrôle
post-init. `scripts/init-terraform-pg-backend.sh` ne sait volontairement pas migrer.

Hetzner Object Storage est `INCOMPATIBLE` comme backend autoritatif : un
contender a acquis un lock alors que le lock vivant du holder était directement
observé. Le bucket protégé existant est conservé uniquement pour les backups
chiffrés, les preuves et la lecture d'un éventuel ancien objet.

Les providers lisent leurs secrets depuis le processus :

- Hetzner : `HCLOUD_TOKEN` ;
- ClouDNS : `CLOUDNS_SUB_AUTH_ID` et `CLOUDNS_PASSWORD` ;
- backend PostgreSQL : `PG_CONN_STR`, `PGPASSWORD` et `PGSSLROOTCERT`.

Aucun credential ne doit être placé dans Terraform, un `.tfvars`, une ligne de
commande littérale ou le dépôt.

## DNS existant

`deployfrance.com` est une zone master existante importée déclarativement et
protégée par `prevent_destroy`. Le premier plan connecté doit montrer l'import
sans remplacement, puis uniquement les créations attendues :

- `git.deployfrance.com A <gitea-mgmt IPv4>` ;
- `registry.deployfrance.com A <harbor-mgmt IPv4>`.

Il n'existe aucun enregistrement public pour `data-mgmt`. Avant le plan,
vérifier en lecture seule qu'aucun record conflictuel `git` ou `registry`
n'existe déjà. Les records utilisent un TTL de 300 secondes. L'intégration
accepte l'IPv4 attachée à la VM ; une IP stable indépendante est obligatoire
avant production.

## Réseau et firewalls

Le réseau est `10.30.0.0/16`, le subnet `10.30.0.0/24` et les IP privées sont
dérivées avec `cidrhost`, jamais dupliquées dans Terraform. Les Cloud Firewalls
ne filtrent que les interfaces publiques :

- Gitea : 22 et 2222 depuis `ssh_allowed_cidrs`, 80/443 publics ;
- Harbor : 22 depuis `ssh_allowed_cidrs`, 80/443 publics ;
- aucun port 5432, 6379, 3000, 3128 ou 8080 public.

Hetzner Cloud Firewall ne protège pas le Cloud Network privé. Le contrat
`host-firewall.contract.json` est donc implémenté par le rôle nftables
`management_firewall` avant le démarrage des services : default-deny inbound,
SSH de `data-mgmt` seulement depuis `gitea-mgmt`, PostgreSQL seulement depuis
Gitea et Harbor, et proxy 3128 seulement de data vers Gitea. Harbor conserve
son Valkey interne au réseau Compose ; aucun Redis/Valkey partagé ni port 6379
hôte n'est créé.

## Inventory Ansible

Après un apply autorisé, produire l'inventory depuis les outputs, sans recopier
les IP :

```sh
terraform -chdir=infrastructure/hetzner/management output -json \
  > /secure/evidence/management-terraform-output.json
python3 scripts/render-management-inventory.py \
  --terraform-output /secure/evidence/management-terraform-output.json \
  --output infrastructure/ansible/inventory/management.generated.yml \
  --acme-email ops@deployfrance.com
ansible-inventory \
  -i infrastructure/ansible/inventory/management.generated.yml \
  --list >/dev/null
```

L'inventory généré est ignoré par Git. Il configure `ProxyJump` via
`gitea-mgmt` pour `data-mgmt`, le proxy egress privé `10.30.0.10:3128` et les
CIDR SSH identiques à Terraform.

## Déploiement management

`infrastructure/ansible/management.yml` exécute dans cet ordre : base Ubuntu,
Docker sur les hôtes publics, Squid privé, firewalls hôte, PostgreSQL 16 TLS sur
data, Gitea rootless, Harbor officiel, Caddy avec images immuables et health
checks systemd/journald JSON. Les secrets proviennent exclusivement d'un fichier
Ansible Vault ignoré, construit depuis
`infrastructure/ansible/examples/management-secrets.example.yml`.

Le proxy Squid sur Gitea est un compromis d'intégration pour permettre à
`data-mgmt` sans interface publique d'installer ses paquets. Il écoute seulement
sur `10.30.0.10:3128` et n'accepte que `10.30.0.30`. Une sortie dédiée et
redondante est obligatoire avant production.

## Persistence et frontière data

En intégration, les root disks et les répertoires sous
`/var/lib/ecommerce-management` sont acceptés uniquement après approbation de la
stratégie de sauvegarde du runbook. Ils ne constituent pas une architecture HA.
Avant production, volumes séparés, backups hors hôte, rétention, chiffrement,
monitoring centralisé et restore drills sont obligatoires.

PostgreSQL `data-mgmt` sert uniquement Gitea, Harbor et de futurs composants du
management plane. Aucune application e-commerce ne peut l'utiliser. Le futur
PostgreSQL applicatif appartient au Data Plane et sera fourni par
CloudNativePG ; il est hors de ce milestone.

Sur `data-mgmt`, `/etc/ecommerce-management` et
`/var/log/ecommerce-management` restent détenus par `root`, avec le groupe
système dédié `ecommerce-postgresql` et le mode `0710`. Le compte `postgres` est
le seul membre applicatif ajouté à ce groupe. Les répertoires TLS et logs
PostgreSQL restent détenus par `postgres`; la clé privée est `0600` et le
répertoire TLS `0700`. Le contrôle TLS de bootstrap utilise exclusivement
`127.0.0.1/32` avec une règle `hostssl` Gitea dédiée, `sslmode=require`, une
authentification SCRAM réelle et une vérification de `pg_stat_ssl`.

## Validation locale

Sans backend ni cloud :

```sh
terraform fmt -check -recursive infrastructure/hetzner/management
terraform -chdir=infrastructure/hetzner/management init -backend=false -input=false
terraform -chdir=infrastructure/hetzner/management validate
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements/ansible.txt
make ansible-lint-management
python3 scripts/validate-management-foundation.py
```

Ne pas exécuter `plan`, `apply`, Ansible distant ou une commande state pendant
la passe statique. Le runbook exact du prochain gate est
`docs/runbooks/management-foundation.md`.
