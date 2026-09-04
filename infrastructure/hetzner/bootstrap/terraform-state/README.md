# Bootstrap `terraform-state-mgmt`

Ce root Terraform est indépendant du management plane. Il déclare uniquement :

- une VM x86 `terraform-state-mgmt` en `nbg1`, Ubuntu 24.04 ;
- un Cloud Firewall n'autorisant que SSH 22 depuis des CIDR IPv4 approuvés ;
- une Primary IPv4 pour l'administration et le tunnel initial ;
- un volume Hetzner `ext4` protégé de 10 Go, attaché sans automount.

Il ne déclare ni AWS, ni HCP Terraform, ni Gitea, Harbor, `data-mgmt`, réseau
management, Kubernetes ou base applicative. Aucun port PostgreSQL public n'est
présent.

## Sizing et persistance

`CX23` fournit 2 vCPU, 4 Go de RAM et 40 Go de disque x86. C'est la plus petite
capacité raisonnable actuellement documentée pour quelques states Terraform et
PostgreSQL 16, sans payer le surcoût d'un CPX. Sa disponibilité et son prix
doivent être relus dans le plan humain, avec le coût de la Primary IPv4.

Le volume séparé utilise le minimum Hetzner de 10 Go. Ses blocs sont répliqués
sur trois serveurs physiques et il survit à une reconstruction de VM, mais
Hetzner ne fournit ni backup ni snapshot natif des Volumes. Le volume et la VM
ont donc `delete_protection` + `prevent_destroy`, sans remplacer les backups
PostgreSQL chiffrés hors VM.

## State du bootstrap

Le root n'utilise jamais le PostgreSQL qu'il crée pour son propre state. Toutes
les commandes passent par :

```sh
./scripts/terraform-state-bootstrap-state.sh init
./scripts/terraform-state-bootstrap-state.sh terraform validate
```

Le state autoritatif est, par défaut :

```text
${XDG_STATE_HOME:-$HOME/.local/state}/ecommerce-1/terraform/bootstrap-terraform-state/terraform.tfstate
```

Le wrapper ne fait confiance ni à `HOME` ni à un `XDG_STATE_HOME` arbitraire :
le home est obtenu depuis l'identité système courante et la racine XDG doit
rester strictement dessous. Depuis `/` jusqu'au state, les composants sont
ouverts sans suivre les symlinks ; les ancêtres système ne sont pas modifiables
par group/other et appartiennent à `root` ou à l'utilisateur, les composants
sous le home appartiennent à l'utilisateur, ne sont pas modifiables par
group/other et restent sur le même filesystem Linux que ce home. Le répertoire
final et `terraform-data` sont en `0700`, le state et son backup en `0600`.

Le wrapper refuse aussi le dépôt et `/mnt/c/Users/*/OneDrive/`. Lui seul fixe
le slug/répertoire state, `TF_DATA_DIR`, le workspace `default`, `-state` et
`-backup`; `BOOTSTRAP_STATE_DIR` et les variantes
caller de `-state`, `-state-out` et `-backup`, y compris via `TF_CLI_ARGS*`,
sont neutralisées avant Terraform. Un `-out` légitime doit en outre rester hors
du répertoire state et ne peut pas en être un alias symlink résolu. La chaîne
est revalidée juste avant et après l'opération. Dans le threat model retenu, un
autre UID non privilégié ne peut donc substituer aucun composant ; `root` et un
processus compromis exécuté avec le même UID restent hors de cette garantie
userland. Les backups `age` gardent SHA-256, lineage et serial, et
`restore-test` ne remplace jamais le state. L'interface `output-inventory` lit exclusivement ce state via
`-state=<chemin>` et ne produit que le JSON validé de `inventory_contract`.

## Prochain gate payant : plan uniquement

Après avoir fourni `HCLOUD_TOKEN`, `TF_VAR_ssh_key_name`,
`TF_VAR_ssh_allowed_cidrs` et un chemin de plan absolu hors dépôt/OneDrive :

```sh
./scripts/terraform-state-bootstrap-state.sh init
./scripts/terraform-state-bootstrap-state.sh terraform plan \
  -input=false \
  -out="${BOOTSTRAP_PLAN_PATH:?absolute reviewed plan path is required}"
```

La revue doit confirmer exactement une VM `cx23`, une Primary IPv4, un volume
10 Go, un firewall SSH restreint, aucune règle 5432 et aucune autre ressource.
Elle doit aussi confirmer le coût courant. Ne pas lancer `apply` dans ce gate.

## Ordre après un apply ultérieurement autorisé

1. Sauvegarder le state bootstrap et tester sa restauration.
2. Vérifier l'empreinte Ed25519 depuis la console Hetzner, puis exécuter
   `scripts/pin-terraform-state-ssh-host-key.sh` vers un `known_hosts` dédié.
3. Extraire via `terraform-state-bootstrap-state.sh output-inventory`, puis
   rendre avec `scripts/render-terraform-state-inventory.py --known-hosts ...`.
4. Exécuter Ansible `infrastructure/ansible/terraform-state.yml`; metadata
   Hetzner et binding du volume bloquent avant toute mutation.
5. Copier la CA publique dans un stockage WSL approuvé, vérifier son empreinte.
6. Ouvrir le tunnel SSH local et prouver santé/TLS/SCRAM.
7. Exécuter le harness advisory-lock PostgreSQL.
8. Inspecter toutes les versions/delete markers de la key legacy et les sources locales.
9. Obtenir la décision humaine initialisation ou migration et le freeze writers.
10. Prouver la cible PG vide, initialiser `pg`, valider post-init, puis produire un nouveau plan management.

Chaque étape est un gate distinct. Le présent milestone n'en exécute aucune.
