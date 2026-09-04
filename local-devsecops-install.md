cd /mnt/c/Users/admin/OneDrive/Bureau/ecommerce-1

sudo bash bootstrap-local-devsecops.sh

comment ouvrir ce chemin windows dans wsl
cd /mnt/c/Users/admin/Downloads/ecommerce-stack-v6.3-target-aligned

~/.config/starship.toml

cd ~/ecommerce-local-platform/terraform && terraform apply -auto-approve

## Outillage Ansible reproductible (WSL)

Depuis la racine du dépôt, préparer explicitement l'environnement local une
seule fois :

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements/ansible.txt
```

Le Makefile n'installe aucun paquet. Il vérifie les versions exactes déclarées
dans `requirements/ansible.txt` et échoue avec une instruction de préparation
si `.venv` est absent ou incohérent :

```sh
make ansible-lint-management
make ansible
```

## Gitleaks reproductible (WSL Linux x86_64)

La version et les empreintes SHA-256 sont pinnées dans `versions.mk`. Installer
explicitement le binaire officiel dans `$HOME/.local/bin` :

```sh
make install-gitleaks
```

Cette cible vérifie séparément le manifeste de checksums officiel, l'archive,
le binaire extrait et la version. Elle est idempotente. Les cibles de validation
ne déclenchent aucune installation et exigent exactement la version projet :

```sh
PATH="$HOME/.local/bin:$PATH" make security
PATH="$HOME/.local/bin:$PATH" make ci
```

Si `$HOME/.local/bin` est déjà dans `PATH`, le préfixe `PATH=...` est inutile.
