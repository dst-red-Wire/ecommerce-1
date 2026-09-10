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


def documentation_errors(text):
    """Inspect every sentence, including code blocks; no document-wide exemptions."""
    errors = []
    normalized = re.sub(r"[`*]", "", text)
    for sentence in re.split(r"\n|;|(?<=[.!?])\s+", normalized):
        # Only an explicit label on this clause qualifies it as historical.
        # An unrelated mention of migration or rejection cannot exempt a claim.
        historical = re.match(r"\s*[-#>\s]*(?:historical|superseded|alternatives rejected)\s*:", sentence, re.I)
        topology_17 = re.search(
            r"\b(?:exactly|total(?:s|ing)?|baseline:)\s+17\s+(?:(?:go|backend)\s+)*services?\b"
            r"|\b(?:the|our)\s+(?:architecture|topology|platform|backend)\s+"
            r"(?:consists?\s+of|includes?|has|defines?)\s+17\s+(?:(?:go|backend)\s+)*services?\b"
            r"|\bthere\s+are\s+17\s+(?:(?:go|backend)\s+)*services?\s+in\s+(?:the|our)\s+(?:architecture|topology|platform|backend)\b"
            r"|\b17\s+(?:(?:go|backend)\s+)*services?\s*\+|\bno\s+checkout\s+service\b",
            sentence, re.I,
        )
        if topology_17 and not historical:
            errors.append("superseded service topology: " + sentence.strip())
        dvc_retired = re.search(r"\bDVC\s+(?:(?:is|was|has been)\s+)?(?:superseded|historical|rejected|forbidden)\b", sentence, re.I)
        if re.search(r"\bdvc\b", sentence, re.I) and not (historical or dvc_retired):
            errors.append("DVC must be explicitly historical/superseded: " + sentence.strip())
        nextjs_active = re.search(
            r"^\s*(?:use|deploy)\s+next\.?js\b"
            r"|\bfrontend\s+framework\s*:\s*next\.?js\b"
            r"|\b(?:prod(?:uction)?\s+)?frontend\s+(?:target|runtime)\s*:\s*next\.?js\b"
            r"|\b(?:admin|storefront)(?:\s+frontend)?\s+(?:uses|is\s+built\s+with)\s+next\.?js\b"
            r"|\bnext\.?js\s+is\s+the\s+(?:production|prod)\s+frontend\s+(?:framework|runtime|target)\b"
            r"|\bnext\.?js\b.*\b(?:target|cible|prod|runtime)\b|\bATS\s*->.*\bnext\.?js\b",
            sentence, re.I,
        )
        if nextjs_active:
            migration = re.search(
                r"next\.?js(?:/React/Node(?:\.js)?)?\s+(?:is (?:only )?the migration source|est la source de migration)"
                r"|actuellement Next\.js, cible Go|Migration du runtime frontend Next\.js vers Go"
                r"|existing Next\.js implementation remains until migration"
                r"|migrate from Next\.?js to Go/templ/HTMX"
                r"|legacy Next\.?js frontend remains only for migration reference"
                r"|Next\.?js is superseded as the PROD frontend target", sentence, re.I
            )
            if not (historical or migration):
                errors.append("Next.js must be explicitly a migration source: " + sentence.strip())
        if re.search(r"BASELINE_V2(?:\.md)?|EXACT_TOPOLOGY_V2(?:\.md)?", sentence) and not historical:
            errors.append("removed architecture authority/index: " + sentence.strip())
        superseded = r"FluxCD|Flagger|MinIO(?: CE| Community Edition| Operator)?|Loki|Splunk"
        active = r"(?:active|default|baseline|target|use|uses|deploy|select|GitOps(?: CD)?|progressive delivery|object stor(?:age|e)|logging|SIEM)"
        superseded_match = re.search(rf"\b(?:{superseded})\b", sentence, re.I)
        retired = superseded_match and re.search(
            rf"(?:\b(?:do not|must not|never)\s+(?:use|deploy|select)\s+{superseded_match.group(0)}\b"
            rf"|\bno\s+(?:active\s+)?{superseded_match.group(0)}\b"
            rf"|\b{superseded_match.group(0)}\b\s+(?:(?:is|was)\s+not\b|(?:is|was|has been)\s+(?:superseded|historical|removed|rejected|forbidden)\b))",
            sentence, re.I,
        )
        if superseded_match and re.search(r"\bis historical\b", sentence[superseded_match.start():], re.I):
            retired = True
        if superseded_match and re.search(active, sentence, re.I) and not (historical or retired):
            errors.append("superseded platform default must not be active: " + sentence.strip())
        if (re.search(r"Fluent Bit", sentence, re.I) and
                re.search(r"(?:general|application|infrastructure)?\s*(?:logging|logs|pipeline|shipper)", sentence, re.I)
                and not historical and not re.search(
                    r"\bFluent Bit\b\s+(?:(?:is|was)\s+not\b|(?:is|was|has been)\s+"
                    r"(?:superseded|historical|removed|rejected|forbidden)\b)"
                    r"|\b(?:do not|must not|never)\s+(?:use|deploy|select)\s+Fluent Bit\b",
                    sentence, re.I)):
            errors.append("Fluent Bit general logging is superseded: " + sentence.strip())
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
        index = (root / INDEX).read_text()
        if "`architecture.lock.yaml` is the single canonical architecture authority" not in index:
            errors.append("derived index must establish the lock as root authority")
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
