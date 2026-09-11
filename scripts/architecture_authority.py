"""Deterministic V5 authority checks. Read-only; no runtime/deployment claims."""

from pathlib import Path
import json
import re
import subprocess

AUTHORITY = "architecture.lock.yaml"
INDEX = "docs/architecture/EXACT_TOPOLOGY_V5.md"
MLOPS = dict(
    dataset_versioner="lakefs", object_storage="seaweedfs-s3",
    metadata_database="cloudnativepg-postgresql", experiments_lineage="mlflow",
    artifact_registry="harbor", promotion_authority="gitea-gitops",
    orchestration="tekton", desired_state="rancher-fleet",
    progressive_delivery="argo-rollouts", runtime="kserve-vllm",
    drift="evidently-tekton-batch",
)

EXACT_CONTRACTS = {
    "resilience_governance": {
        "version": 1, "status": "exact", "architecture_authority": AUTHORITY,
        "sources": ["docs/architecture/SECURITY_TRUST_ZONES.md", "docs/architecture/DEPLOYMENT_DAG.md",
                    "docs/architecture/PROD_TOPOLOGY_V2.md", "docs/architecture/MLOPS_TOPOLOGY_V1.md"],
        "compromise": {"scope": "reproducible-compromised-nodes-and-workloads",
                       "sequence": ["isolate", "acquire-evidence", "destroy", "rebuild-via-gitops-iac"],
                       "manual_cleaning_restores_trust": False, "exception": "specialized-forensic-requirement"},
        "evidence": {"destroy_required_forensic_evidence": "forbidden", "acquisition_may_delay_jit_teardown": True,
                     "write_identity_separate_from_delete_admin": True, "immutability": "where-policy-requires"},
        "site_recovery": {"sequence": ["health-evidence", "quorum-fencing", "write-authority-decision",
                                         "stateful-promotion-recovery", "application-routing", "dns-gslb-change"]},
        "mlops_recovery": {"promotion": "frozen-during-recovery",
                           "required_assets": ["postgresql-metadata-backup", "independent-object-backup",
                                               "harbor-recovery", "tested-restore-procedures"]},
    },
    "security_trust_zones": {
        "version": 1, "status": "exact", "architecture_authority": AUTHORITY,
        "source": "docs/architecture/SECURITY_TRUST_ZONES.md",
        "zones": {"Z0": "internet-untrusted", "Z1": "public-edge-dmz",
                  "Z2": "kubernetes-ingress-service-mesh", "Z3": "application-workloads",
                  "Z4": "stateful-data", "Z5": "permanent-mgmt", "Z6": "backup-evidence-dfir"},
        "application_services_source": "architecture.lock.yaml#business.services",
        "human_iam": {"customers_realm": "customers", "workforce_realm": "workforce",
                      "privileged_authentication": "hardware-backed-webauthn-passkeys",
                      "customer_tokens_for_mgmt": "forbidden"},
        "workload_identity": {"trust_domains": ["PREPROD", "PROD-A", "PROD-B"],
                              "cross_environment": "deny-by-default",
                              "federation_requires": "architecture-security-review"},
        "secrets": {"flow": "openbao-eso-kubernetes-secret-runtime-mount-where-applicable",
                    "forbidden": ["git", "image-layers", "ci-logs", "bootstrap-credentials-after-preprod-destroy",
                                  "application-access-to-openbao-admin-credentials"]},
        "egress": {"default": "deny", "application_path": "approved-istio-egress-squid",
                   "logging": "required", "exceptions": "documented"},
        "mgmt_access_source": "config/contracts/mgmt-wireguard-access.yaml",
    },
}


def load_yaml(path):
    """Use the repository-contracted Ruby/Psych runtime; Python has no PyYAML contract."""
    command = ["ruby", "-rpsych", "-rjson", "-e",
               "data = Psych.safe_load(File.read(ARGV[0]), aliases: false); puts JSON.generate(data)", str(path)]
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    if completed.returncode:
        raise ValueError(completed.stderr.strip() or f"cannot parse {path}")
    return json.loads(completed.stdout)


def component_is_retired(sentence, component):
    """Return true only when retirement/negation applies to the named component."""
    return bool(re.search(
        rf"(?:\b(?:no|never|do\s+not|must\s+not)\s+(?:(?:use|active)\s+)?(?:{component})\b|"
        rf"\b(?:{component})\b.{{0,35}}\b(?:is\s+not|not\s+used|forbid(?:den)?|superseded|historical|removed|rejected)\b)",
        sentence, re.I,
    ))


def derived_index_errors(index, lock):
    """Cross-check facts rendered by the derived index against their lock values."""
    errors = []

    def require(fragment, field):
        if fragment not in index:
            errors.append(f"derived index drift from architecture.lock.yaml: {field}")

    require(f"derived from version {lock['version']} of that lock", "version")
    require(f"TTL is locked at {lock['dns']['critical_ttl_seconds']} seconds", "dns.critical_ttl_seconds")

    prod = lock["prod_certified_topology"]
    site_count = len(prod["sites"])
    require(f"{prod['physical_hosts_per_site']} physical failure domains", "prod physical failure domains")
    if index.count(f"{prod['physical_hosts_per_site']} physical failure domains") != site_count:
        errors.append("derived index drift from architecture.lock.yaml: PROD site failure-domain counts")
    require(f"{prod['control_planes_per_site']} CP + {prod['workers_per_site']} workers", "PROD control-plane/worker counts")
    if index.count(f"{prod['control_planes_per_site']} CP + {prod['workers_per_site']} workers") != site_count:
        errors.append("derived index drift from architecture.lock.yaml: PROD per-site control-plane/worker counts")
    require(f"{prod['data_workers_per_site']} data workers + {prod['general_workers_per_site']} general", "PROD worker roles")
    for site, values in prod["sites"].items():
        require(values["private_block"], f"prod_certified_topology.sites.{site}.private_block")
    require(lock["management_plane"]["private_block"], "management_plane.private_block")

    services = lock["business"]["services"]
    require(f"Exactly {len(services)} backend services", "business.services count")
    require("`, `".join(services), "business.services membership/order")
    frontend = lock["business"]["frontend_runtime"]
    frontend_target = f"{frontend['language'].title()} + {frontend['rendering']} + {frontend['interactions'].upper()}"
    require(f"The storefront and admin target {frontend_target}", "business.frontend_runtime target")
    require("Next.js/React/Node is only the migration source", "business.frontend_runtime migration source")
    require(f"M2.5 is `{lock['build_milestones'][3]}`", "M2.5 milestone identity")

    observability = lock["observability"]
    observability_section = index.split("## Observability", 1)[-1].split("\n## ", 1)[0]
    rendered_observability = dict(re.findall(
        r"^- `([a-z_]+)`: `([a-z0-9-]+)`\s*$", observability_section, re.M
    ))
    for field, value in observability.items():
        if rendered_observability.get(field) != value:
            errors.append(f"derived index drift from architecture.lock.yaml: observability.{field}")

    mlops_section = index.split("## MLOps", 1)[-1].split("\n## ", 1)[0]
    mlops_display = {
        "lakefs": "lakeFS", "seaweedfs-s3": "SeaweedFS S3", "cloudnativepg-postgresql": "CloudNativePG PostgreSQL",
        "mlflow": "MLflow", "harbor": "Harbor", "gitea-gitops": "Gitea GitOps", "tekton": "Tekton",
        "rancher-fleet": "Rancher Fleet", "argo-rollouts": "Argo Rollouts", "kserve-vllm": "KServe/vLLM",
        "evidently-tekton-batch": "Evidently in Tekton batch",
    }
    for field, value in lock["mlops"].items():
        if mlops_display.get(value, value) not in mlops_section:
            errors.append(f"derived index drift from architecture.lock.yaml: mlops.{field}")

    flow_and_delivery = index.split("## AIOps", 1)[0]
    platform_display = {
        "rke2": "RKE2", "tekton": "Tekton", "harbor": "Harbor", "rancher-fleet": "Fleet",
        "argo-rollouts": "Argo Rollouts", "seaweedfs-s3": "SeaweedFS S3",
    }
    for field in ("kubernetes", "ci", "registry", "gitops", "progressive_delivery"):
        value = lock["platform"][field]
        if platform_display.get(value, value) not in flow_and_delivery:
            errors.append(f"derived index drift from architecture.lock.yaml: platform.{field}")
    if platform_display[lock["stateful"]["object_storage"]] not in flow_and_delivery:
        errors.append("derived index drift from architecture.lock.yaml: stateful.object_storage")
    return errors


def documentation_errors(text):
    """Inspect every sentence, including code blocks; no document-wide exemptions."""
    errors = []
    normalized = re.sub(r"[`*]", "", text)
    for sentence in re.split(r"\n|;|(?<=[.!?])\s+", normalized):
        # Only an explicit label on this clause qualifies it as historical.
        # An unrelated mention of migration or rejection cannot exempt a claim.
        historical = (re.match(r"\s*[-#>\s]*(?:historical|superseded|alternatives rejected)\s*:", sentence, re.I)
                      or re.search(r"\bdiagram\b.*\b(?:historical|superseded)\b", sentence, re.I))
        operational_subset = re.search(
            r"\b17\s+of\s+19\b|\b(?:healthy|deployed|available|ready|complete|remain(?:s|ing)?|unavailable|progress)\b",
            sentence, re.I,
        )
        topology_claim = (
            re.search(r"\b17\s+(?:(?:go|backend)\s+)*services?\b", sentence, re.I)
            and re.search(r"\b(?:exactly|total(?:s|ing)?|architecture|topology|platform|backend|consists?\s+of|there\s+are|has|includes?|defines?|baseline)\b", sentence, re.I)
        )
        if ((topology_claim and not operational_subset)
                or re.search(r"\b17\s+(?:(?:go|backend)\s+)*services?\s*\+|\bno\s+checkout\s+service\b", sentence, re.I)) and not historical:
            errors.append("superseded service topology: " + sentence.strip())
        dvc_retired = re.search(r"\bDVC\s+(?:(?:is|was|has been)\s+)?(?:superseded|historical|rejected|forbidden)\b", sentence, re.I)
        if re.search(r"\bdvc\b", sentence, re.I) and not (historical or dvc_retired):
            errors.append("DVC must be explicitly historical/superseded: " + sentence.strip())
        if re.search(r"next\.?js", sentence, re.I) and re.search(
                r"target|cible|prod|runtime|ATS\s*->|\buse\b|\buses\b|deploy|frontend|framework|built\s+with",
                sentence, re.I):
            migration = re.search(
                r"next\.?js(?:/React/Node(?:\.js)?)?\s+(?:is (?:only )?the migration source|est la source de migration)"
                r"|actuellement Next\.js, cible Go|Migration du runtime frontend Next\.js vers Go"
                r"|existing Next\.js implementation remains until migration", sentence, re.I
            )
            migration = migration or (re.search(r"\bmigration\b", sentence, re.I)
                                      and re.search(r"\b(?:only|source|reference|legacy|currently)\b", sentence, re.I))
            migration = migration or re.search(r"\bcurrently\s+use(?:s)?\b", sentence, re.I)
            nextjs_retired = re.search(
                r"next\.?js.{0,30}\b(?:superseded|historical|rejected|forbidden|removed|not\s+(?:the\s+)?(?:target|runtime))\b",
                sentence, re.I,
            )
            if not (historical or migration or nextjs_retired):
                errors.append("Next.js must be explicitly a migration source: " + sentence.strip())
        if re.search(r"BASELINE_V2(?:\.md)?|EXACT_TOPOLOGY_V2(?:\.md)?", sentence) and not historical:
            errors.append("removed architecture authority/index: " + sentence.strip())
        superseded = r"FluxCD|Flagger|MinIO(?: Community Edition| Operator)?|Loki|Splunk"
        active = r"(?:active|default|baseline|target|use|uses|deploy|select|GitOps(?: CD)?|progressive delivery|object stor(?:age|e)|logging|SIEM)"
        component = re.search(rf"\b(?:{superseded})\b", sentence, re.I)
        retired = component and component_is_retired(sentence, superseded)
        if component and re.search(active, sentence, re.I) and not (historical or retired):
            errors.append("superseded platform default must not be active: " + sentence.strip())
        if (re.search(r"Fluent Bit", sentence, re.I) and
                re.search(r"(?:general|application|infrastructure)?\s*(?:logging|logs|pipeline|shipper)", sentence, re.I)
                and not historical and not component_is_retired(sentence, r"Fluent Bit")):
            errors.append("Fluent Bit general logging is superseded: " + sentence.strip())
        negated = re.search(r"\b(?:no|not|never|forbid(?:den)?|superseded|historical|removed|rejected|do not|must not|only)\b", sentence, re.I)
        if (re.search(r"(?:general|application|infrastructure)\s+(?:logging|logs|log pipeline)", sentence, re.I) and
                re.search(r"Data Prepper|OpenSearch", sentence, re.I) and not (historical or negated)):
            errors.append("Data Prepper/OpenSearch general logging role is forbidden: " + sentence.strip())
        if (re.search(r"OpenSearch\s+Logs|OpenSearch.{0,20}(?:general\s+)?observability\s+source", sentence, re.I)
                and not re.search(r"security", sentence, re.I) and not historical and not negated):
            errors.append("OpenSearch general observability storage is superseded: " + sentence.strip())
        if (re.search(r"Prometheus", sentence, re.I) and
                re.search(r"(?:primary|main|authoritative)\s+(?:TSDB|metrics (?:store|storage|server))|(?:TSDB|metrics (?:store|storage|server))\s+(?:is|:)\s+Prometheus", sentence, re.I)
                and not (historical or negated)):
            errors.append("Prometheus is compatibility-only, not primary metrics storage: " + sentence.strip())
        if (re.search(r"application (?:telemetry|logs?|observability)(?:\s+and\s+logs?)?\s*(?:use|uses|->|:)\s*VictoriaLogs|VictoriaLogs\s+for\s+(?:both\s+)?(?:infrastructure\s+(?:and|/)\s+)?application", sentence, re.I)
                and not (historical or negated)):
            errors.append("application telemetry/logs must use Rotel, ClickHouse, and HyperDX: " + sentence.strip())
        if re.search(r"(?:observability/)?fluent-bit/", sentence, re.I) and not historical:
            errors.append("Fluent Bit bootstrap component is superseded: " + sentence.strip())
    return errors


def validate(root):
    root = Path(root)
    errors = []
    try:
        lock = load_yaml(root / AUTHORITY)
        if lock["version"] != 5:
            errors.append("architecture.lock.yaml must be version 5")
        if lock["topology_contracts"]["exact_index"] != INDEX:
            errors.append("exact index must be the derived V5 index")
        if lock.get("mlops") != MLOPS:
            errors.append("MLOps must match the approved V5 choices")
        if lock["observability"].get("hyperdx_metadata_store") != "mongodb-oss-self-hosted":
            errors.append("HyperDX metadata store must be self-hosted MongoDB OSS")
        if lock.get("dns", {}).get("critical_ttl_seconds") != 60:
            errors.append("critical DNS TTL must remain 60 seconds")
        if lock["superseded"].get("dvc-dataset-versioner") != "lakefs":
            errors.append("DVC supersession must select lakeFS")
        milestones = lock["build_milestones"]
        expected = ["M0-architecture-sync", "M1-monorepo-bootstrap", "M2-golden-service-product",
                    "M2-5-persistent-mgmt-bootstrap", "M3-preprod-infrastructure", "M4-platform-baseline",
                    "M5-commerce-vertical-slice", "M6-full-application", "M7-qualification",
                    "M8-preprod-certification", "M9-prod-ab"]
        prerequisites = [[], [0], [1], [1], [3], [4], [2, 5], [6], [7], [8], [9]]
        dag = {name: [expected[i] for i in parents] for name, parents in zip(expected, prerequisites)}
        actual_dag = lock.get("milestone_dependencies", {})
        if milestones != expected or set(actual_dag) != set(dag) or any(
            sorted(actual_dag.get(name, [])) != sorted(parents) for name, parents in dag.items()
        ):
            errors.append("milestone dependencies must match the approved V5 DAG")
        for key in ("resilience_governance", "security_trust_zones"):
            relative = "config/contracts/" + key.replace("_", "-") + ".yaml"
            if lock["machine_contracts"].get(key) != relative:
                errors.append(f"missing canonical machine contract: {key}")
            contract = load_yaml(root / relative)
            if contract != EXACT_CONTRACTS[key]:
                errors.append(f"{relative} must match its exact V5 invariants")
        # The Ruby architecture validator also checks all declared contract paths
        # and their cross-contract invariants. Never bypass its missing-file checks.
        for relative in lock["machine_contracts"].values():
            if not (root / relative).is_file():
                errors.append(f"missing machine contract: {relative}")
        management = lock["management_plane"]
        inventory = load_yaml(root / lock["machine_contracts"]["mgmt_inventory"])
        gateways = load_yaml(root / lock["machine_contracts"]["mgmt_access_gateways"])
        wireguard = load_yaml(root / lock["machine_contracts"]["mgmt_wireguard_access"])
        management_checks = {
            "provider": (inventory.get("provider"), gateways.get("provider"), wireguard.get("gateway", {}).get("provider")),
            "lifecycle": (inventory.get("lifecycle", {}).get("mode"), gateways.get("lifecycle", {}).get("mode"),
                          wireguard.get("gateway", {}).get("lifecycle")),
            "private_block": (inventory.get("private_block"),),
            "kubernetes": ((management.get("kubernetes") if inventory.get("vm_profiles") and all(
                name.startswith(f"{management.get('kubernetes')}-") for name in inventory["vm_profiles"]
            ) else None),),
            "forge": (inventory.get("platform_services", {}).get("forge"),),
            "ci": (inventory.get("platform_services", {}).get("ci"),),
            "registry": (inventory.get("platform_services", {}).get("registry"),),
            "gitops": (inventory.get("platform_services", {}).get("gitops"),),
        }
        for field, subordinate_values in management_checks.items():
            if any(value != management.get(field) for value in subordinate_values):
                errors.append(f"management_plane.{field} contradicts subordinate MGMT contracts")
        bootstrap = management.get("bootstrap", {})
        if (bootstrap.get("terraform_opentofu") is not True
                or inventory.get("bootstrap", {}).get("infrastructure") != "terraform-opentofu"
                or bootstrap.get("ansible") is not True
                or inventory.get("bootstrap", {}).get("configuration") != "ansible"):
            errors.append("management_plane.bootstrap contradicts the MGMT inventory")
        human_gates = (
            bootstrap.get("requires_human_apply_gate"),
            inventory.get("bootstrap", {}).get("human_apply_gate"),
            gateways.get("implementation", {}).get("human_apply_gate"),
            wireguard.get("human_gates", {}).get("provider_apply") == "required",
        )
        if any(gate is not True for gate in human_gates):
            errors.append("management_plane.bootstrap requires the locked human apply gate")
        for role, relative in lock["topology_contracts"].items():
            if not isinstance(relative, str) or not relative.strip() or Path(relative).is_absolute() or ".." in Path(relative).parts:
                errors.append(f"topology_contracts.{role} must declare a non-empty repository-relative path")
                continue
            path = root / relative
            if not path.is_file():
                errors.append(f"missing topology contract: {relative}")
                continue
            contents = path.read_text()
            status = re.search(r"^Status:\s*`([^`]*)`\s*$", contents, re.M | re.I)
            status_token = status.group(1).strip().split(maxsplit=1)[0].upper() if status else None
            if not contents.strip() or status_token != "EXACT":
                errors.append(f"topology contract must be readable and EXACT: {relative}")
        index = (root / INDEX).read_text()
        if "`architecture.lock.yaml` is the single canonical architecture authority" not in index:
            errors.append("derived index must establish the lock as root authority")
        errors.extend(derived_index_errors(index, lock))
        for relative in ("AGENTS.md", "README.md"):
            text = (root / relative).read_text()
            if not re.search(r"architecture.lock.yaml.{0,12}(?:— the single canonical architecture authority|, seule autorité canonique)", text):
                errors.append(f"{relative} must establish the lock as root authority")
        agents = (root / "AGENTS.md").read_text()
        if "M2.5 -> M3 PREPROD infra" not in agents or "M2 + M4 -> M5 vertical slice" not in agents:
            errors.append("AGENTS.md build sequence must match the approved V5 DAG")
        plan = (root / "docs/project/MASTER_EXECUTION_PLAN.md").read_text()
        if not re.search(r"\| M3 PREPROD Infrastructure .*?\| M2\.5 PROVEN;", plan):
            errors.append("MASTER_EXECUTION_PLAN.md must gate M3 on M2.5")
        readiness = (root / "docs/project/TECHNICAL_READINESS.md").read_text()
        if not re.search(r"M3: dependency-gated by M2\.5 PROVEN", readiness):
            errors.append("TECHNICAL_READINESS.md must gate M3 on M2.5 PROVEN")
        handoffs = (root / "docs/project/CODEX_HANDOFFS.md").read_text()
        handoff_match = re.search(r"^## M2\.5 prompt.*?(?=^## |\Z)", handoffs, re.M | re.S)
        handoff = handoff_match.group(0) if handoff_match else ""
        handoff_requirements = ("## M2.5 prompt", "M2-5-persistent-mgmt-bootstrap", "Entry gate: M1 PROVEN",
                                "Evidence required for M2.5 PROVEN", "Exit gate:", "That PROVEN state enables M3")
        if any(requirement not in handoff for requirement in handoff_requirements):
            errors.append("CODEX_HANDOFFS.md must define the executable M2.5 entry, evidence, and M3 exit contract")
        router = load_yaml(root / "config/context/router.yaml")
        l2_patterns = router["levels"]["L2"]["patterns"]
        l2_canonical = router["canonical"]["L2"]
        for relative in ("config/contracts/resilience-governance.yaml", "config/contracts/security-trust-zones.yaml"):
            if relative not in l2_patterns or relative not in l2_canonical:
                errors.append(f"L2 context must include exact contract: {relative}")
        for keyword in ("resilience", "recovery"):
            if keyword not in router["levels"]["L2"]["task_keywords"]:
                errors.append(f"L2 context must route {keyword} tasks")
        for old in ("BASELINE_V2.md", "EXACT_TOPOLOGY_V2.md"):
            if (root / "docs/architecture" / old).exists():
                errors.append(f"removed architecture document reintroduced: {old}")
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        errors.append(f"invalid architecture authority contract: {exc}")

    # Include new, untracked documents but exclude ignored generated dependencies.
    paths = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=root
    ).decode().split("\0")
    for relative in sorted(set(paths)):
        path = root / relative
        if path.suffix.lower() == ".md" and path.is_file():
            errors.extend(f"{relative}: {error}" for error in documentation_errors(path.read_text()))
    return errors


if __name__ == "__main__":
    failures = validate(Path(__file__).resolve().parents[1])
    print("\n".join(failures) if failures else "PASS architecture V5 root authority and documentation")
    raise SystemExit(bool(failures))
