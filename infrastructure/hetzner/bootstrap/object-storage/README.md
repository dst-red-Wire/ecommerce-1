# Hetzner Object Storage — archive secondaire

Le bucket existant `ecommerce-management-tfstate-20260820-70b94831` en `nbg1`
reste privé, versionné et protégé. Il ne doit être ni supprimé, ni vidé, ni
déprotégé.

## Décision de backend

Hetzner Object Storage n'est plus un backend Terraform autoritatif. Avec
Terraform 1.15.5, le test renforcé a observé directement le `.tflock` vivant du
holder puis un contender a néanmoins acquis le lock. Statut définitif de cette
trajectoire :

```text
Hetzner Object Storage state locking: INCOMPATIBLE
PostgreSQL backend: TARGET / NOT_PROVEN_RUNTIME
```

Il est interdit de contourner ce résultat par `use_lockfile=false`,
`-lock=false`, un verrou local, un mutex CI ou des retries. Le management root
utilise désormais `backend "pg"`.

`scripts/test-hetzner-s3-locking.sh`, son root
`lock-runtime-test` et la configuration S3 canonique restent présents comme
preuve/audit diagnostique. `scripts/init-hetzner-s3-backend.sh` rejette
explicitement `management` et n'accepte que `lock-runtime-test`.

## Nouveau rôle du bucket

La policy déclarative prépare uniquement :

- lecture authentifiée de l'éventuel objet legacy
  `ecommerce/management/terraform.tfstate`, sans droit d'écriture ;
- lecture/écriture/suppression des deux objets du probe S3 conservé ;
- lecture/écriture, sans suppression ordinaire, des backups chiffrés sous
  `ecommerce/backups/postgresql/*` ;
- lecture/écriture des backups chiffrés du state bootstrap sous
  `ecommerce/backups/bootstrap-terraform-state/*` ;
- archivage des preuves sous `ecommerce/evidence/*`.

Le template utilise des ARN `arn:aws:s3` et les outils exposent des variables
`AWS_*` uniquement parce que l'API est compatible S3. Cela ne sélectionne ni ne
crée aucune ressource AWS. Architecture cloud sélectionnée : Hetzner uniquement.

La modification de policy est seulement préparée dans le code. Elle exige un
plan du root Object Storage, une revue humaine et une autorisation de mutation
séparée ; elle n'est pas appliquée dans ce milestone.

## Secrets et protection

Le provider lit `MINIO_USER` et `MINIO_PASSWORD` dans le processus. Aucun secret
n'est accepté dans Terraform, un `.tfvars`, `.tfbackend`, output ou document.
`TF_VAR_management_principal_arn` est un identifiant de principal, pas un
credential.

`force_destroy=false` et `prevent_destroy` restent déclarés. `protected=true`
reste un contrôle Hetzner Console prouvé séparément, car le provider MinIO
n'expose pas cet attribut.

## State local du bootstrap Object Storage

Le state autoritatif reste hors dépôt et OneDrive :

```text
${XDG_STATE_HOME:-$HOME/.local/state}/ecommerce-1/terraform/bootstrap-object-storage/terraform.tfstate
```

Le wrapper commun conserve les commandes historiques :

```sh
./scripts/object-storage-bootstrap-state.sh init
./scripts/object-storage-bootstrap-state.sh terraform validate
./scripts/object-storage-bootstrap-state.sh backup
./scripts/object-storage-bootstrap-state.sh restore-test /secure/backup.manifest.json
```

Le backup est chiffré avec `age`; le manifeste lie SHA-256, lineage, serial et
version Terraform. Le restore-test déchiffre en mémoire/temporaire, vérifie ces
valeurs et n'écrase jamais le state autoritatif.

## Validation locale

```sh
python3 scripts/validate-hetzner-s3-backend.py
terraform -chdir=infrastructure/hetzner/bootstrap/object-storage \
  init -backend=false -input=false
terraform -chdir=infrastructure/hetzner/bootstrap/object-storage validate
```

Ces validations ne contactent pas Hetzner et ne modifient aucune ressource.
