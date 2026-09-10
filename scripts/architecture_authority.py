"""Deterministic V5 authority checks. Read-only; no runtime/deployment claims."""

from pathlib import Path
import re
import subprocess

import yaml

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


def documentation_errors(text):
    """Inspect every sentence, including code blocks; no document-wide exemptions."""
    errors = []
    normalized = re.sub(r"[`*]", "", text)
    for sentence in re.split(r"\n|;|(?<=[.!?])\s+", normalized):
        # Only an explicit label on this clause qualifies it as historical.
        # An unrelated mention of migration or rejection cannot exempt a claim.
        historical = re.match(r"\s*[-#>\s]*(?:historical|superseded|alternatives rejected)\s*:", sentence, re.I)
        if re.search(r"\b(?:exactly\s+)?17\s+(?:(?:go|backend)\s+)*services?\b|\bno\s+checkout\s+service\b", sentence, re.I) and not historical:
            errors.append("superseded service topology: " + sentence.strip())
        dvc_retired = re.search(r"\bDVC\s+(?:is|was)\s+(?:superseded|historical|rejected|forbidden)\b", sentence, re.I)
        if re.search(r"\bdvc\b", sentence, re.I) and not (historical or dvc_retired):
            errors.append("DVC must be explicitly historical/superseded: " + sentence.strip())
        if re.search(r"next\.?js", sentence, re.I) and re.search(r"target|cible|prod|runtime|ATS\s*->", sentence, re.I):
            migration = re.search(
                r"next\.?js(?:/React/Node(?:\.js)?)?\s+(?:is (?:only )?the migration source|est la source de migration)"
                r"|actuellement Next\.js, cible Go|Migration du runtime frontend Next\.js vers Go"
                r"|existing Next\.js implementation remains until migration", sentence, re.I
            )
            if not (historical or migration):
                errors.append("Next.js must be explicitly a migration source: " + sentence.strip())
        if re.search(r"BASELINE_V2(?:\.md)?|EXACT_TOPOLOGY_V2(?:\.md)?", sentence) and not historical:
            errors.append("removed architecture authority/index: " + sentence.strip())
    return errors


def validate(root):
    root = Path(root)
    errors = []
    try:
        lock = yaml.safe_load((root / AUTHORITY).read_text())
        if lock["version"] != 5:
            errors.append("architecture.lock.yaml must be version 5")
        if lock["topology_contracts"]["exact_index"] != INDEX:
            errors.append("exact index must be the derived V5 index")
        if lock.get("mlops") != MLOPS:
            errors.append("MLOps must match the approved V5 choices")
        if lock["observability"].get("hyperdx_metadata_store") != "mongodb-oss-self-hosted":
            errors.append("HyperDX metadata store must be self-hosted MongoDB OSS")
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
            contract = yaml.safe_load((root / relative).read_text())
            if contract.get("architecture_authority") != AUTHORITY:
                errors.append(f"{relative} must be subordinate to {AUTHORITY}")
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
        for old in ("BASELINE_V2.md", "EXACT_TOPOLOGY_V2.md"):
            if (root / "docs/architecture" / old).exists():
                errors.append(f"removed architecture document reintroduced: {old}")
    except (OSError, KeyError, TypeError, ValueError, yaml.YAMLError) as exc:
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
