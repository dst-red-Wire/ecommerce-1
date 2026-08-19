#!/usr/bin/env bash
set -Eeuo pipefail

# Bootstrap non interactif du depot ecommerce-1.
# Docker Desktop + integration WSL2 est un prerequis.
# Aucun read, aucun prompt Ansible become, aucun commit/push.
#
# IMPORTANT :
# - ne teste PAS auth.docker.io avec curl depuis WSL ;
# - les pulls Docker passent par le daemon/proxy Docker Desktop ;
# - Quay/GHCR sont testes car Helm y accede directement depuis WSL.

log()  { printf '\n[+] %s\n' "$*"; }
die()  { printf '\n[ERREUR] %s\n' "$*" >&2; exit 1; }

BOOTSTRAP_MODE="full"
case "${1:-}" in
  "") ;;
  --preflight-only) BOOTSTRAP_MODE="preflight" ;;
  --validate-only) BOOTSTRAP_MODE="validate" ;;
  -h|--help)
    printf 'Usage: sudo bash %s [--preflight-only|--validate-only]\n' "$0"
    exit 0
    ;;
  *) die "Option inconnue : $1" ;;
esac

BOOTSTRAP_STARTED_AT="$(date +%s)"
PHASE_STARTED_AT="$BOOTSTRAP_STARTED_AT"
PHASE_REPORT=""
SKIP_COUNT=0

phase_start() {
  PHASE_NAME="$1"
  PHASE_STARTED_AT="$(date +%s)"
  log "[PHASE] $PHASE_NAME"
}

phase_end() {
  phase_duration="$(( $(date +%s) - PHASE_STARTED_AT ))"
  PHASE_REPORT="${PHASE_REPORT}${PHASE_NAME}|${phase_duration}\n"
}

report_timings() {
  total_duration="$(( $(date +%s) - BOOTSTRAP_STARTED_AT ))"
  printf '\nDurées du bootstrap :\n'
  printf '%b' "$PHASE_REPORT" | while IFS='|' read -r phase_name phase_seconds; do
    [ -n "$phase_name" ] && printf '  %-32s %4ss\n' "$phase_name" "$phase_seconds"
  done
  printf '  %-32s %4ss\n' "TOTAL" "$total_duration"
  printf '  %-32s %4s\n' "Opérations Bash SKIP" "$SKIP_COUNT"
}

phase_start "0 - Validation environnement"

if [[ "${EUID}" -ne 0 ]]; then
  die "Lance : sudo bash bootstrap-local-devsecops.sh"
fi

DEV_USER="${SUDO_USER:-}"
[[ -n "$DEV_USER" && "$DEV_USER" != "root" ]] || \
  die "Lance ce script avec sudo depuis ta session utilisateur normale."

DEV_HOME="$(getent passwd "$DEV_USER" | cut -d: -f6)"
[[ -d "$DEV_HOME" ]] || die "HOME introuvable pour $DEV_USER"
run_as_dev() {
  sudo -u "$DEV_USER" env HOME="$DEV_HOME" USER="$DEV_USER" LOGNAME="$DEV_USER" "$@"
}

BOOTSTRAP_LOG_DIR="$DEV_HOME/.cache/ecommerce-bootstrap"
run_as_dev mkdir -p "$BOOTSTRAP_LOG_DIR"

REPO_ROOT="$(run_as_dev git -C "$(pwd)" rev-parse --show-toplevel 2>/dev/null || true)"
[[ -n "$REPO_ROOT" ]] || die "Execute ce script depuis le depot Git ecommerce-1."
cd "$REPO_ROOT"

VERSIONS_FILE="$REPO_ROOT/versions.mk"
[[ -f "$VERSIONS_FILE" ]] || die "Fichier introuvable : $VERSIONS_FILE"

version_value() {
  awk -F ":=" -v key="$1" '$1 ~ "^[[:space:]]*" key "[[:space:]]*$" { gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2; exit }' "$VERSIONS_FILE"
}

TERRAFORM_VERSION="$(version_value TERRAFORM_VERSION)"
KUBECTL_VERSION="$(version_value KUBECTL_VERSION)"
HELM_VERSION="$(version_value HELM_VERSION)"
KIND_VERSION="$(version_value KIND_VERSION)"
KIND_NODE_IMAGE="$(version_value KIND_NODE_IMAGE)"
CILIUM_CHART_VERSION="$(version_value CILIUM_CHART_VERSION)"
FLUX_OPERATOR_CHART_VERSION="$(version_value FLUX_OPERATOR_CHART_VERSION)"
KUBE_PROMETHEUS_STACK_CHART_VERSION="$(version_value KUBE_PROMETHEUS_STACK_CHART_VERSION)"
KYVERNO_CHART_VERSION="$(version_value KYVERNO_CHART_VERSION)"
LOKI_CHART_VERSION="$(version_value LOKI_CHART_VERSION)"
OPENTELEMETRY_COLLECTOR_CHART_VERSION="$(version_value OPENTELEMETRY_COLLECTOR_CHART_VERSION)"
TEMPO_CHART_VERSION="$(version_value TEMPO_CHART_VERSION)"
TETRAGON_CHART_VERSION="$(version_value TETRAGON_CHART_VERSION)"
TEKTON_PIPELINES_VERSION="$(version_value TEKTON_PIPELINES_VERSION)"
FLUX_DISTRIBUTION_VERSION="$(version_value FLUX_DISTRIBUTION_VERSION)"

ANSIBLE_VERSION_ENV=(
  "TERRAFORM_VERSION=$TERRAFORM_VERSION"
  "KUBECTL_VERSION=$KUBECTL_VERSION"
  "HELM_VERSION=$HELM_VERSION"
  "KIND_VERSION=$KIND_VERSION"
  "KIND_NODE_IMAGE=$KIND_NODE_IMAGE"
  "CILIUM_CHART_VERSION=$CILIUM_CHART_VERSION"
  "FLUX_OPERATOR_CHART_VERSION=$FLUX_OPERATOR_CHART_VERSION"
  "KUBE_PROMETHEUS_STACK_CHART_VERSION=$KUBE_PROMETHEUS_STACK_CHART_VERSION"
  "KYVERNO_CHART_VERSION=$KYVERNO_CHART_VERSION"
  "LOKI_CHART_VERSION=$LOKI_CHART_VERSION"
  "OPENTELEMETRY_COLLECTOR_CHART_VERSION=$OPENTELEMETRY_COLLECTOR_CHART_VERSION"
  "TEMPO_CHART_VERSION=$TEMPO_CHART_VERSION"
  "TETRAGON_CHART_VERSION=$TETRAGON_CHART_VERSION"
  "TEKTON_PIPELINES_VERSION=$TEKTON_PIPELINES_VERSION"
  "FLUX_DISTRIBUTION_VERSION=$FLUX_DISTRIBUTION_VERSION"
  "REPO_ROOT=$REPO_ROOT"
)

PLAYBOOK_SOURCE="$REPO_ROOT/local-devsecops.yml"
PLAYBOOK_DEST="$REPO_ROOT/platform/bootstrap/local-devsecops.yml"

[[ -f "$PLAYBOOK_SOURCE" ]] || die "Fichier introuvable : $PLAYBOOK_SOURCE"

log "Depot       : $REPO_ROOT"
log "Utilisateur : $DEV_USER"

grep -qi microsoft /proc/sys/kernel/osrelease || \
  die "Ce bootstrap doit être exécuté dans WSL2."

available_kb="$(df -Pk "$DEV_HOME" | awk 'NR == 2 {print $4}')"
[[ "$available_kb" =~ ^[0-9]+$ ]] || die "Impossible de lire l'espace disque disponible."
(( available_kb >= 5 * 1024 * 1024 )) || \
  die "Moins de 5 Gio disponibles dans WSL2 ; libère de l'espace avant le bootstrap."

phase_end
phase_start "1 - WSL / Docker preflight"

if dpkg-query -W -f='${Status}' docker.io 2>/dev/null | grep -Fq 'install ok installed'; then
  die "Le paquet docker.io Ubuntu est encore installe. Supprime-le : sudo apt-get remove -y docker.io"
fi

log "Preflight Docker Desktop / WSL2"

run_as_dev bash -lc 'command -v docker >/dev/null 2>&1' || \
  die "Docker CLI introuvable. Active l'integration WSL dans Docker Desktop."

[[ -S /var/run/docker.sock ]] || die "Socket Docker absent : /var/run/docker.sock"

run_as_dev timeout 15 curl -fsS --unix-socket /var/run/docker.sock http://localhost/_ping \
  | grep -Fxq "OK" || die "Docker Engine ne repond pas via /var/run/docker.sock."

run_as_dev timeout 15 curl -fsS --unix-socket /var/run/docker.sock http://localhost/info \
  | grep -Fq '"ServerVersion"' || die "Docker Engine repond mais /info est invalide."


log "Docker Desktop est operationnel"

if [[ -f "$DEV_HOME/.kube/ecommerce-local-config" ]]; then
  log "SKIP création kubeconfig : cluster local déjà connu"
  SKIP_COUNT=$((SKIP_COUNT + 1))
fi

phase_end

if [[ "$BOOTSTRAP_MODE" == "preflight" ]]; then
  report_timings
  exit 0
fi

phase_start "2 - Dépendances Linux"

export DEBIAN_FRONTEND=noninteractive

log "Installation/vérification des dépendances bootstrap"
REQUIRED_PACKAGES=(ansible git curl ca-certificates jq make unzip)
MISSING_PACKAGES=()
for package_name in "${REQUIRED_PACKAGES[@]}"; do
  if ! dpkg-query -W -f='${Status}' "$package_name" 2>/dev/null | grep -Fq 'install ok installed'; then
    MISSING_PACKAGES+=("$package_name")
  fi
done

if (( ${#MISSING_PACKAGES[@]} > 0 )) && [[ "$BOOTSTRAP_MODE" == "validate" ]]; then
  die "Validation impossible ; paquets manquants : ${MISSING_PACKAGES[*]}"
elif (( ${#MISSING_PACKAGES[@]} > 0 )); then
  apt-get update
  apt-get install -y "${MISSING_PACKAGES[@]}"
else
  log "SKIP apt : dépendances déjà installées"
  SKIP_COUNT=$((SKIP_COUNT + 1))
fi

command -v ansible-playbook >/dev/null 2>&1 || die "ansible-playbook introuvable."
command -v timeout >/dev/null 2>&1 || die "timeout introuvable."

phase_end
phase_start "3 - Validation outils et sources"

log "Preflight Quay/GHCR pour Helm"

check_registry() {
  local endpoint="$1"

  run_as_dev timeout 45 curl \
    --silent \
    --show-error \
    --head \
    --connect-timeout 10 \
    --max-time 20 \
    --retry 2 \
    --retry-delay 2 \
    --retry-all-errors \
    "$endpoint" >/dev/null 2>&1
}

check_registry "https://quay.io/v2/" || \
  die "Quay inaccessible depuis WSL : https://quay.io/v2/"

check_registry "https://ghcr.io/v2/" || \
  die "GHCR inaccessible depuis WSL : https://ghcr.io/v2/"


log "Connectivite Quay/GHCR disponible"

if [[ "$BOOTSTRAP_MODE" == "validate" ]]; then
  log "Validation syntaxique Ansible sans modification du dépôt"
  env "${ANSIBLE_VERSION_ENV[@]}" HOME="$DEV_HOME" USER="$DEV_USER" LOGNAME="$DEV_USER" \
    ANSIBLE_CONFIG="$REPO_ROOT/ansible.cfg" \
    ANSIBLE_BECOME_ASK_PASS=False \
    ansible-playbook --syntax-check "$PLAYBOOK_SOURCE"
  phase_end
  report_timings
  exit 0
fi

DIRECTORIES=(
  "platform/bootstrap"
  "platform/ansible"
  "platform/terraform/local"
  "platform/local"
  "gitops/clusters/local"
  "gitops/infrastructure"
  "tekton/tasks"
  "tekton/pipelines"
  "tekton/triggers"
  "security/kyverno"
  "security/network-policies"
)

log "Creation de l'arborescence declarative"
for directory in "${DIRECTORIES[@]}"; do
  run_as_dev mkdir -p "$REPO_ROOT/$directory"
  run_as_dev touch "$REPO_ROOT/$directory/.gitkeep"
done

log "Synchronisation du playbook vers platform/bootstrap/"
if run_as_dev cmp -s "$PLAYBOOK_SOURCE" "$PLAYBOOK_DEST"; then
  log "SKIP copie playbook : copie déjà conforme"
  SKIP_COUNT=$((SKIP_COUNT + 1))
else
  run_as_dev cp "$PLAYBOOK_SOURCE" "$PLAYBOOK_DEST"
fi

log "Mise a jour idempotente de .gitignore"
run_as_dev touch "$REPO_ROOT/.gitignore"

GITIGNORE_ENTRIES=(
  "# -----------------------------------------------------------------------------"
  "# Local DevSecOps"
  "platform/local/.env"
  "platform/terraform/local/.terraform/"
  "platform/terraform/local/*.tfstate"
  "platform/terraform/local/*.tfstate.*"
  "platform/terraform/local/terraform.tfvars"
  ".env"
  ".env.*"
  "!.env.example"
)

for entry in "${GITIGNORE_ENTRIES[@]}"; do
  if ! grep -Fqx "$entry" "$REPO_ROOT/.gitignore"; then
    # The inner shell receives entry/path as positional arguments.
    # shellcheck disable=SC2016
    run_as_dev bash -c 'printf "%s\n" "$1" >> "$2"' _ "$entry" "$REPO_ROOT/.gitignore"
  fi
done

log "Validation syntaxique Ansible"
env "${ANSIBLE_VERSION_ENV[@]}" HOME="$DEV_HOME" USER="$DEV_USER" LOGNAME="$DEV_USER" \
  ANSIBLE_CONFIG="$REPO_ROOT/ansible.cfg" \
  ANSIBLE_BECOME_ASK_PASS=False \
  ansible-playbook --syntax-check "$PLAYBOOK_DEST"

phase_end

phase_start "4-6 - Terraform et plateforme"

log "Etat Git avant execution"
run_as_dev git -C "$REPO_ROOT" status --short

log "Lancement automatique du bootstrap local Ansible"
ANSIBLE_PROFILE_ENV=()
if ansible-doc --type callback profile_tasks >/dev/null 2>&1; then
  ANSIBLE_PROFILE_ENV+=("ANSIBLE_CALLBACKS_ENABLED=profile_tasks")
fi

env "${ANSIBLE_VERSION_ENV[@]}" "${ANSIBLE_PROFILE_ENV[@]}" \
  HOME="$DEV_HOME" USER="$DEV_USER" LOGNAME="$DEV_USER" \
  ANSIBLE_CONFIG="$REPO_ROOT/ansible.cfg" \
  ANSIBLE_BECOME_ASK_PASS=False \
  ansible-playbook "$PLAYBOOK_DEST"

phase_end
phase_start "7 - Post-validation"

log "Verification finale"
run_as_dev git -C "$REPO_ROOT" status --short

phase_end
report_timings

printf '\nAcces attendus :\n'
printf '  Gitea        : http://localhost:3000\n'
printf '  Gitea SSH    : ssh://git@localhost:2222\n'
printf '  Registry OCI : localhost:5000\n'
printf '  Kubeconfig   : %s/.kube/ecommerce-local-config\n' "$DEV_HOME"
printf '\nAucune confirmation interactive. Aucun commit. Aucun push.\n'
