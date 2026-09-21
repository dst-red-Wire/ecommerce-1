"""Deterministic V5 authority checks. Read-only; no runtime/deployment claims."""

from pathlib import Path
import copy
import hashlib
import json
import re
import subprocess
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import qualification_cache

AUTHORITY = "architecture.lock.yaml"
LOCK_STATUS = "locked-for-build"
CANONICAL_ROOT = Path(__file__).resolve().parents[1]


def _load_canonical_yaml(relative):
    """Load canonical YAML/JSON through the content-addressed qualification cache."""
    return qualification_cache.psych_load(CANONICAL_ROOT / relative)


_CANONICAL_LOCK = _load_canonical_yaml(AUTHORITY)
INDEX = _CANONICAL_LOCK["topology_contracts"]["exact_index"]
V5_FRONTENDS = list(_CANONICAL_LOCK["business"]["frontends"])
EXPECTED_V5_FRONTEND_RUNTIME = dict(_CANONICAL_LOCK["business"]["frontend_runtime"])
V5_PROD_TOPOLOGY_KEYS = frozenset(
    {
        "physical_hosts_total",
        "physical_hosts_per_site",
        "control_planes_per_site",
        "workers_per_site",
        "data_workers_per_site",
        "general_workers_per_site",
        "sites",
    }
)
V5_PROD_SITES_KEYS = frozenset({"prod-a", "prod-b"})
V5_PROD_SITE_KEYS = frozenset({"private_block", "physical_hosts"})
V5_ROOT_KEYS = frozenset(
    {
        "version",
        "status",
        "project",
        "repository_governance",
        "business",
        "platform",
        "management_plane",
        "stateful",
        "dns",
        "observability",
        "mlops",
        "supply_chain",
        "topology_contracts",
        "machine_contracts",
        "developer_platform",
        "prod_certified_topology",
        "superseded",
        "build_milestones",
        "milestone_dependencies",
    }
)
V5_SECTION_KEYS = {
    "repository_governance": frozenset(
        {
            "scope",
            "transverse_rule_contract",
            "owner_authorization",
        }
    ),
    "repository_governance.transverse_rule_contract": frozenset(
        {
            "source_of_truth",
            "rule_definition",
            "enforcement",
            "per_file_rule_propagation",
            "consumer_changes",
        }
    ),
    "repository_governance.owner_authorization": frozenset(
        {
            "syntax",
            "decision_authority",
            "recording_agent",
            "recording_requires_explicit_owner_instruction",
            "sha_binding",
            "scope_binding",
            "head_change",
            "absence_or_mismatch",
        }
    ),
    "business": frozenset({"services", "frontends", "frontend_runtime", "forbidden_services"}),
    "business.frontend_runtime": frozenset(
        {
            "language",
            "module",
            "module_file",
            "rendering",
            "interactions",
            "runtime_nodejs",
            "migration_source",
        }
    ),
    "platform": frozenset(
        {
            "kubernetes",
            "node_os",
            "cni",
            "mesh",
            "gitops",
            "ci",
            "progressive_delivery",
            "registry",
            "secrets",
            "external_secrets",
            "workload_identity",
            "iam",
            "runtime_security",
            "infrastructure_api",
            "autoscaling",
        }
    ),
    "platform.autoscaling": frozenset(
        {
            "synchronous_pods",
            "event_driven_pods",
            "certified_nodes",
            "preprod_perf_burst",
        }
    ),
    "management_plane": frozenset(
        {
            "provider",
            "lifecycle",
            "private_block",
            "kubernetes",
            "forge",
            "ci",
            "registry",
            "gitops",
            "developer_portal",
            "bootstrap",
        }
    ),
    "management_plane.bootstrap": frozenset(
        {
            "terraform_opentofu",
            "ansible",
            "requires_human_apply_gate",
        }
    ),
    "developer_platform": frozenset(
        {
            "status",
            "scope",
            "principles",
            "runtime_boundary",
            "backstage_pr_contract",
            "git_contract",
            "pull_request_contract",
            "platform_request_api",
            "preview_environment_api",
            "execution_contract",
            "infrastructure_ownership",
            "preview_lifecycle",
            "promotion",
            "quality_cloud_engineering",
            "milestone_contract",
        }
    ),
    "developer_platform.principles": frozenset(
        {
            "portal",
            "catalog",
            "source_of_truth",
            "change_unit",
            "forge",
            "ci",
            "registry",
            "gitops",
            "infrastructure_api",
            "progressive_delivery",
            "foundation_iac",
        }
    ),
    "developer_platform.runtime_boundary": frozenset(
        {
            "commerce_runtime_nodejs",
            "backstage_management_plane_nodejs",
            "backstage_only_exception",
        }
    ),
    "developer_platform.backstage_pr_contract": frozenset(
        {
            "role",
            "allowed_operations",
            "forbidden_operations",
            "gitea_pull_request_action",
        }
    ),
    "developer_platform.git_contract": frozenset(
        {
            "default_branch",
            "request_branch_pattern",
            "request_path_pattern",
            "force_push",
            "direct_default_branch_write",
        }
    ),
    "developer_platform.pull_request_contract": frozenset(
        {
            "required",
            "exact_head_sha_required",
            "human_review_required",
            "required_context",
        }
    ),
    "developer_platform.platform_request_api": frozenset(
        {
            "api_version",
            "kind",
            "authoritative_representation",
            "path_pattern",
            "required_fields",
        }
    ),
    "developer_platform.preview_environment_api": frozenset(
        {
            "api_version",
            "kind",
            "lifecycle_owner",
            "create_on",
            "delete_on",
            "unique_url_required",
        }
    ),
    "developer_platform.execution_contract": frozenset(
        {
            "plan_before_apply",
            "mutating_platform_action_requires_git_change",
            "tekton_direct_workload_deploy",
            "tekton_outputs",
            "harbor_reference",
            "gitops_desired_state_required",
            "fleet_reconciles_git",
            "crossplane_materializes_platform_api",
        }
    ),
    "developer_platform.infrastructure_ownership": frozenset({"terraform_opentofu", "crossplane"}),
    "developer_platform.preview_lifecycle": frozenset(
        {
            "creation",
            "cleanup",
            "cleanup_trigger",
            "direct_runtime_delete",
        }
    ),
    "developer_platform.promotion": frozenset(
        {
            "strategy",
            "rebuild_between_preview_preprod_prod",
            "same_digest_required",
            "environment_change",
        }
    ),
    "developer_platform.milestone_contract": frozenset(
        {
            "M1-monorepo-bootstrap",
            "M4-platform-baseline",
            "M5-commerce-vertical-slice",
        }
    ),
    "developer_platform.milestone_contract.M1-monorepo-bootstrap": frozenset(
        {
            "outcome",
            "implementation_required",
            "requires",
            "does_not_require",
        }
    ),
    "developer_platform.milestone_contract.M4-platform-baseline": frozenset({"outcome", "components"}),
    "developer_platform.milestone_contract.M5-commerce-vertical-slice": frozenset({"outcome"}),
    "stateful": frozenset({"database", "events", "jobs", "cache", "search", "object_storage"}),
    "dns": frozenset({"critical_ttl_seconds"}),
    "observability": frozenset(
        {
            "telemetry",
            "application_gateway",
            "infrastructure_collector",
            "metrics_protocol",
            "metrics_scraper",
            "metrics",
            "infrastructure_logs",
            "application_observability_storage",
            "application_observability_ui",
            "hyperdx_metadata_store",
            "alerts",
            "notifications",
            "dashboards",
            "security_pipeline",
            "security_logs",
            "security",
        }
    ),
    "mlops": frozenset(
        {
            "dataset_versioner",
            "object_storage",
            "metadata_database",
            "experiments_lineage",
            "artifact_registry",
            "promotion_authority",
            "orchestration",
            "desired_state",
            "progressive_delivery",
            "runtime",
            "drift",
        }
    ),
    "prod_certified_topology": V5_PROD_TOPOLOGY_KEYS,
    "prod_certified_topology.sites": V5_PROD_SITES_KEYS,
    "prod_certified_topology.sites.prod-a": V5_PROD_SITE_KEYS,
    "prod_certified_topology.sites.prod-b": V5_PROD_SITE_KEYS,
}
V5_MLOPS = dict(_CANONICAL_LOCK["mlops"])
DEPLOYABLE_MLOPS = [
    V5_MLOPS["dataset_versioner"],
    V5_MLOPS["experiments_lineage"],
    V5_MLOPS["runtime"],
    V5_MLOPS["drift"],
]
V5_OBSERVABILITY = dict(_CANONICAL_LOCK["observability"])
V5_SUPERSEDED = dict(_CANONICAL_LOCK["superseded"])
SUPERSEDED_COMPONENT = r"FluxCD|Flagger|MinIO(?: Community Edition| Operator| CE)?|Loki|Splunk"
DERIVED_TOPOLOGY_ROLES = frozenset(
    {
        "architecture_boundaries",
        "service_mesh_topology",
        "service_policy_chain",
    }
)
REGISTRY_GLOBS = {
    "topology_contracts": (
        "docs/architecture/*.md",
    ),
    "machine_contracts": (
        "config/contracts/*.yaml",
        "config/contracts/*.yml",
        "config/contracts/*.json",
        "config/context/*.yaml",
        "config/context/*.yml",
        "config/context/*.json",
        "config/infrastructure/*.yaml",
        "config/infrastructure/*.yml",
        "config/infrastructure/*.json",
        "contracts/*.yaml",
        "contracts/*.yml",
        "contracts/*.json",
        "contracts/**/*.yaml",
        "contracts/**/*.yml",
        "contracts/**/*.json",
    ),
}
V5_SECTION_KEYS.update(
    {
        "superseded": frozenset(V5_SUPERSEDED),
    }
)
V5_MILESTONES = list(_CANONICAL_LOCK["build_milestones"])
V5_MILESTONE_DEPENDENCIES = {
    name: list(parents)
    for name, parents in _CANONICAL_LOCK["milestone_dependencies"].items()
}
V5_SECTION_KEYS["milestone_dependencies"] = frozenset(V5_MILESTONE_DEPENDENCIES)

V5_QCE_SECTORS = (
    "continuous_testing",
    "test_first",
    "test_strategy",
    "automation",
    "monitoring_observability",
    "release_governance_automation",
    "golden_path",
    "developer_hub",
    "measuring_engineering",
)
V5_QCE_SECTOR_FIELDS = frozenset({"owner", "input", "output", "evidence"})
V5_SECTION_KEYS["developer_platform.quality_cloud_engineering"] = frozenset(
    {
        "status",
        "scope",
        "implementation_milestone",
        "proof_milestone",
        "sector_count",
        "sectors",
        "cross_cutting",
    }
)
V5_SECTION_KEYS["developer_platform.quality_cloud_engineering.sectors"] = frozenset(V5_QCE_SECTORS)
for sector in V5_QCE_SECTORS:
    V5_SECTION_KEYS[f"developer_platform.quality_cloud_engineering.sectors.{sector}"] = V5_QCE_SECTOR_FIELDS
V5_SECTION_KEYS["developer_platform.quality_cloud_engineering.cross_cutting"] = frozenset(
    {"security", "culture", "ai_agent"}
)
V5_SECTION_KEYS["developer_platform.quality_cloud_engineering.cross_cutting.security"] = frozenset(
    {"owner", "applies_to_all_sectors", "evidence_required"}
)
V5_SECTION_KEYS["developer_platform.quality_cloud_engineering.cross_cutting.culture"] = frozenset(
    {"owner", "applies_to_all_sectors", "explicit_ownership_required", "documentation_as_code_required"}
)
V5_SECTION_KEYS["developer_platform.quality_cloud_engineering.cross_cutting.ai_agent"] = frozenset(
    {
        "owner", "applies_to_all_sectors", "role", "authoritative_gate",
        "may_bypass_required_gates", "may_merge", "may_deploy_production_directly",
    }
)

V5_REPOSITORY_GOVERNANCE = dict(_CANONICAL_LOCK["repository_governance"])
OWNER_AUTHORIZATION_PATTERN = re.compile(
    r"^/owner-authorization approve scope=(?P<scope>[A-Za-z0-9][A-Za-z0-9._:/-]*) "
    r"sha=(?P<sha>[0-9a-f]{40})$"
)

V5_DEVELOPER_PLATFORM = dict(_CANONICAL_LOCK["developer_platform"])

V5_DEPLOYMENT_WAVES = _load_canonical_yaml(
    _CANONICAL_LOCK["machine_contracts"]["deployment_waves"]
)
MIRRORED_WAVES = ("20-network-security", "30-gitops-identity", "50-observability")

EXACT_CONTRACTS = {
    key: _load_canonical_yaml(_CANONICAL_LOCK["machine_contracts"][key])
    for key in ("resilience_governance", "security_trust_zones")
}


def owner_authorization_errors(
    command,
    *,
    expected_scope,
    head_sha,
    decision_authority,
    recording_agent,
    explicit_owner_instruction,
):
    """Fail-closed evaluation for repository-owner authorization records."""
    policy = V5_REPOSITORY_GOVERNANCE["owner_authorization"]
    errors = []

    if decision_authority != policy["decision_authority"]:
        errors.append("BLOCK owner authorization decision authority mismatch")
    if recording_agent != policy["recording_agent"]:
        errors.append("BLOCK owner authorization recording agent mismatch")
    if policy["recording_requires_explicit_owner_instruction"] and not explicit_owner_instruction:
        errors.append("BLOCK owner authorization requires explicit repository-owner instruction")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]*", expected_scope or ""):
        errors.append("BLOCK owner authorization expected scope is invalid")
    if not re.fullmatch(r"[0-9a-f]{40}", head_sha or ""):
        errors.append("BLOCK owner authorization current HEAD SHA is not exact")

    if not command:
        errors.append("BLOCK owner authorization missing")
        return errors

    match = OWNER_AUTHORIZATION_PATTERN.fullmatch(command)
    if not match:
        errors.append("BLOCK owner authorization syntax mismatch")
        return errors

    if match.group("scope") != expected_scope:
        errors.append("BLOCK owner authorization scope mismatch")
    if match.group("sha") != head_sha:
        errors.append("BLOCK owner authorization SHA mismatch or authorization expired after HEAD change")
    return errors


def clear_yaml_parse_cache():
    """Clear the process-local Psych cache compatibility surface."""
    qualification_cache.clear_memory_cache("psych-yaml")


def load_yaml(path):
    """Parse YAML with Ruby/Psych through the canonical content-addressed cache."""
    return qualification_cache.psych_load(path)

def validate_exact_keys(name, actual, expected_keys):
    """Validate an exact mapping schema without allowing unknown or missing fields."""
    contract_name = "complete approved V5 registry" if name == "superseded" else "complete approved V5 schema"
    if not isinstance(actual, dict):
        return [f"{name} must be a mapping with the {contract_name}"]
    actual_keys = set(actual)
    if actual_keys == set(expected_keys):
        return []
    unknown = sorted(actual_keys - set(expected_keys))
    missing = sorted(set(expected_keys) - actual_keys)
    details = []
    if unknown:
        details.append("unknown=" + ",".join(unknown))
    if missing:
        details.append("missing=" + ",".join(missing))
    return [f"{name} keys must match the {contract_name} ({'; '.join(details)})"]


def lock_schema_errors(lock):
    """Validate the complete governed lock shape before any cross-contract lookup."""
    errors = validate_exact_keys("architecture.lock.yaml root", lock, V5_ROOT_KEYS)
    if errors:
        return errors
    for name, expected_keys in V5_SECTION_KEYS.items():
        current = lock
        for part in name.split("."):
            if not isinstance(current, dict) or part not in current:
                current = None
                break
            current = current[part]
        errors.extend(validate_exact_keys(name, current, expected_keys))
    if errors:
        return errors
    for registry_name in ("topology_contracts", "machine_contracts"):
        registry = lock.get(registry_name)
        if not isinstance(registry, dict):
            errors.append(f"{registry_name} must be a mapping")
            continue
        for role, relative in registry.items():
            if not isinstance(role, str) or not role.strip():
                errors.append(f"{registry_name} keys must be non-empty strings")
            if not isinstance(relative, str) or not relative.strip():
                errors.append(f"{registry_name}.{role} must declare a non-empty repository-relative path")
    if errors:
        return errors
    if not isinstance(lock.get("build_milestones"), list):
        errors.append("build_milestones must be a list")
    business = lock["business"]
    forbidden = business["forbidden_services"]
    if not isinstance(forbidden, list):
        errors.append("business.forbidden_services must be a list")
    elif forbidden:
        errors.append("business.forbidden_services must be empty in the approved V5 schema")

    qce = lock["developer_platform"]["quality_cloud_engineering"]
    sectors = qce["sectors"]
    if qce["sector_count"] != 9 or set(sectors) != set(V5_QCE_SECTORS):
        errors.append("quality_cloud_engineering must declare exactly the nine approved QCE sectors")
    for sector_name in V5_QCE_SECTORS:
        sector = sectors[sector_name]
        for field in V5_QCE_SECTOR_FIELDS:
            value = sector[field]
            if not isinstance(value, str) or not value.strip():
                errors.append(
                    f"quality_cloud_engineering sector {sector_name} must define non-empty owner/input/output/evidence"
                )
                break
    cross_cutting = qce["cross_cutting"]
    if not cross_cutting["security"]["applies_to_all_sectors"]:
        errors.append("quality_cloud_engineering security must apply to all sectors")
    culture = cross_cutting["culture"]
    if not (
        culture["applies_to_all_sectors"]
        and culture["explicit_ownership_required"]
        and culture["documentation_as_code_required"]
    ):
        errors.append("quality_cloud_engineering culture must preserve ownership and documentation-as-code")
    ai_agent = cross_cutting["ai_agent"]
    if (
        not ai_agent["applies_to_all_sectors"]
        or ai_agent["role"] != "assistant"
        or ai_agent["authoritative_gate"]
        or ai_agent["may_bypass_required_gates"]
        or ai_agent["may_merge"]
        or ai_agent["may_deploy_production_directly"]
    ):
        errors.append("quality_cloud_engineering AI agent must remain non-authoritative")

    prod = lock["prod_certified_topology"]
    for field in V5_PROD_TOPOLOGY_KEYS - {"sites"}:
        if not isinstance(prod[field], int) or isinstance(prod[field], bool):
            errors.append(f"prod_certified_topology.{field} must be an integer")
    for site_name in V5_PROD_SITES_KEYS:
        site = prod["sites"][site_name]
        if not isinstance(site["private_block"], str):
            errors.append(f"prod_certified_topology.sites.{site_name}.private_block must be a string")
        hosts = site["physical_hosts"]
        if not isinstance(hosts, list) or not all(isinstance(host, str) for host in hosts):
            errors.append(f"prod_certified_topology.sites.{site_name}.physical_hosts must be a list of strings")
        elif len(hosts) != len(set(hosts)):
            errors.append(f"prod_certified_topology.sites.{site_name}.physical_hosts must be unique")
    all_prod_hosts = [host for site in prod["sites"].values() for host in site["physical_hosts"]]
    if len(all_prod_hosts) != len(set(all_prod_hosts)):
        errors.append("prod_certified_topology physical hosts must be globally unique across PROD sites")
    return errors


def component_is_retired(sentence, component):
    """Return true only when retirement/negation applies to the named component."""
    direct_retirement = re.search(
        rf"(?:\b(?:remove|removes|removed|removing)\s+(?:remaining\s+)?(?:{component})\b|"
        rf"\b(?:no|never|do\s+not|must\s+not)\s+(?:(?:use|active)\s+)?(?:{component})\b|"
        rf"\b(?:{component})\b\s+(?:(?:is|was|has\s+been|remain(?:s|ed)?)\s+)?(?:both\s+)?"
        rf"(?:not\s+(?:used|selected|(?:the\s+)?(?:active|default|baseline|target|"
        rf"(?:CD|GitOps|rollout)\s+controller|(?:infrastructure\s+)?log\s+store|"
        rf"(?:object|S3)\s+(?:store|backend)|SIEM|(?:general\s+)?log\s+shipper))|forbid(?:den)?|superseded|"
        rf"historical|removed|rejected|retired)\b)",
        sentence,
        re.I,
    )
    coordinated_negation = re.search(
        rf"\b(?:no|never|do\s+not|must\s+not)\s+(?:(?:use|select|deploy)\s+)?"
        rf"(?:(?:{SUPERSEDED_COMPONENT})\b\s*(?:,|/|and|or)\s*)*(?:{component})\b",
        sentence,
        re.I,
    )
    coordinated_retirement = re.search(
        rf"(?P<components>(?:{SUPERSEDED_COMPONENT})\b(?:\s*(?:,|/|and|or)\s*"
        rf"(?:{SUPERSEDED_COMPONENT})\b)+)\s+(?:are|were|remain(?:ed)?)\s+(?:both\s+)?"
        rf"(?:superseded|historical|removed|rejected|retired)\b",
        sentence,
        re.I,
    )
    shared_retirement = coordinated_retirement and re.search(
        rf"\b(?:{component})\b", coordinated_retirement.group("components"), re.I
    )
    return bool(direct_retirement or coordinated_negation or shared_retirement)


def is_explicit_historical_clause(sentence, scoped_historical=False):
    """Recognize only local, explicit historical/superseded scope."""
    return bool(
        scoped_historical or re.match(r"\s*[-#>\s]*(?:historical|superseded|alternatives rejected)\s*:", sentence, re.I)
    )


def is_dvc_retirement_clause(sentence):
    """Accept DVC only when it is explicitly the retired/source technology."""
    return bool(
        re.search(r"\bremove(?:s|d|ing)?\s+(?:remaining\s+)?DVC\b", sentence, re.I)
        or re.search(r"\breplace(?:s|d|ing)?\s+DVC\b[^.!?;]*\bwith\s+lakeFS\b", sentence, re.I)
        or re.search(r"\bmigrat(?:e|es|ed|ing)\s+DVC(?:\s+datasets?)?\b[^.!?;]*\bto\s+lakeFS\b", sentence, re.I)
        or re.search(
            r"\bDVC\b\s+(?:(?:is|was|has\s+been|remain(?:s|ed)?)\s+)?"
            r"(?:superseded|historical|rejected|forbidden)\b",
            sentence,
            re.I,
        )
    )


def is_nextjs_active_target_clause(sentence):
    """Detect an explicit active/target assignment before migration exemptions."""
    return bool(
        re.search(
            r"(?:next\.?js\b\s+(?:is|as)\s+(?:the\s+)?target\s+runtime\b|"
            r"\btarget\s+runtime\b\s*(?:is|:)?\s*next\.?js\b|"
            r"\bproduction\s+frontend\b[^.!?;]*\b(?:use|uses|is)\b[^.!?;]*next\.?js\b|"
            r"\bdeploy\s+next\.?js\b|\bfrontend\b[^.!?;]*\b(?:use|uses)\s+next\.?js\b[^.!?;]*\bas\s+(?:its\s+|the\s+)?target\s+runtime\b)",
            sentence,
            re.I,
        )
    )


def is_nextjs_migration_source_clause(sentence):
    """Require Next.js to be identified as the source/temporary side of migration."""
    return bool(
        re.search(r"next\.?js(?:/React/Node(?:\.js)?)?\s+is\s+(?:only\s+)?the\s+migration\s+source", sentence, re.I)
        or re.search(r"\bmigration\b[^.!?;]*\bnext\.?js\b[^.!?;]*\b(?:to|vers)\s+Go\b", sentence, re.I)
        or re.search(
            r"\b(?:migrat(?:e|es|ed|ing)|migration)\b[^.!?;]*\bfrom\s+next\.?js\b[^.!?;]*\bto\s+Go\b", sentence, re.I
        )
        or re.search(
            r"\bnext\.?js\b[^.!?;]*\b(?:remains?|legacy)\b[^.!?;]*\b(?:only|until)\b[^.!?;]*\b(?:migration|Go)\b",
            sentence,
            re.I,
        )
        or re.search(r"\bnext\.?js\b[^.!?;]*\b(?:source|legacy)\b[^.!?;]*\btarget\b[^.!?;]*\bGo\b", sentence, re.I)
        or re.search(r"\b(?:currently|actuellement)\s+(?:use|uses|utilise(?:nt)?)\s+next\.?js\b", sentence, re.I)
        or re.search(r"\bactuellement\s+next\.?js\b[^.!?;]*\bcible\s+Go\b", sentence, re.I)
    )


def is_explicit_topology_claim(sentence):
    """Return true for canonical composition assertions, regardless of progress words."""
    count = re.search(r"\b17\s+(?:(?:go|backend)\s+)*services?\b", sentence, re.I)
    explicit_count = re.search(r"\bexactly\s+17\s+(?:(?:go|backend)\s+)*services?\b", sentence, re.I)
    architecture_assignment = (
        re.search(r"\b(?:canonical\s+architecture|architecture|topology|platform)\b", sentence, re.I)
        and re.search(
            r"\b(?:exactly|complete|consists?\s+of|there\s+are|has|includes?|defines?|baseline|with)\b", sentence, re.I
        )
    ) or re.search(r"\b(?:our\s+)?backend\s+(?:consists?\s+of|has|includes?|defines?)\b", sentence, re.I)
    return bool(count and (explicit_count or architecture_assignment))


def is_operational_progress_clause(sentence):
    """Recognize concrete rollout/health subsets, never generic 'complete'."""
    return bool(
        re.search(r"\b17\s+of\s+19\b[^.!?;]*\b(?:deployed|healthy|available|ready)\b", sentence, re.I)
        or re.search(
            r"\b17\s+(?:backend\s+)?services?\b[^.!?;]*\b(?:deployed|healthy|available|ready|affected|unavailable)\b",
            sentence,
            re.I,
        )
        or re.search(
            r"\b17\s+(?:backend\s+)?services?\b[^.!?;]*\b(?:have\s+completed|currently\s+have)\b", sentence, re.I
        )
        or re.search(
            r"\b17\s+(?:backend\s+)?services?\b[^.!?;]*\bcomplete\b[^.!?;]*\b(?:two|2)\s+remain\b", sentence, re.I
        )
    )


def find_superseded_role_assignment(sentence):
    """Find either direction of an active component/role assignment."""
    role = (
        r"(?:(?:CD|GitOps|rollout)\s+(?:controller|delivery)|progressive\s+delivery|"
        r"(?:object|S3)\s+(?:store|backend)|infrastructure\s+logs?|(?:infrastructure\s+)?log\s+store|"
        r"SIEM|(?:general\s+)?log\s+shipper)"
    )
    verb = r"(?:is|are|was|were|acts?\s+as|serves?\s+as|provides?|owns?|stores?|backs?|powers?|hosts?|:)"
    component_first = rf"\b(?P<component>{SUPERSEDED_COMPONENT})\b\s+{verb}\s+(?:the\s+)?{role}\b"
    role_first = rf"\b(?:the\s+)?{role}\b\s+{verb}\s+(?:the\s+)?(?P<reverse_component>{SUPERSEDED_COMPONENT})\b"
    return re.search(rf"(?:{component_first}|{role_first})", sentence, re.I)


def superseded_assignment_component(match):
    """Return the component captured in either governed assignment direction."""
    return match.group("component") or match.group("reverse_component")


def wave_ancestors(waves, wave_id):
    """Return transitive declared prerequisites without relying on YAML order."""
    prerequisites = {wave.get("id"): wave.get("requires", []) for wave in waves}
    ancestors, pending = set(), list(prerequisites.get(wave_id, []))
    while pending:
        dependency = pending.pop()
        if dependency in ancestors:
            continue
        ancestors.add(dependency)
        pending.extend(prerequisites.get(dependency, []))
    return ancestors


def security_source_errors(source, contract):
    """Cross-check the bounded explicit facts rendered by the security source."""
    errors = []
    zone_names = {
        "internet-untrusted": "Internet / untrusted",
        "public-edge-dmz": "Public Edge / DMZ",
        "kubernetes-ingress-service-mesh": "Kubernetes ingress / service mesh",
        "application-workloads": "Application workloads",
        "stateful-data": "Stateful data",
        "permanent-mgmt": "Permanent MGMT",
        "backup-evidence-dfir": "Backup / evidence / DFIR",
    }
    for zone, identity in contract["zones"].items():
        if not re.search(rf"^###\s+{re.escape(zone)}\s+—\s+{re.escape(zone_names[identity])}\s*$", source, re.M | re.I):
            errors.append(f"security source drift: zone {zone} must identify {identity}")
    facts = (
        (contract["human_iam"]["customers_realm"], r"Keycloak\s+`(?P<value>[^`]+)`\s+realm:\s*customer identities"),
        (contract["human_iam"]["workforce_realm"], r"Keycloak\s+`(?P<value>[^`]+)`\s+realm:\s*staff/operators"),
        (
            contract["human_iam"]["privileged_authentication"],
            r"privileged workforce flows require (?P<value>WebAuthn/passkeys backed by hardware keys)",
        ),
        (
            contract["human_iam"]["customer_tokens_for_mgmt"],
            r"(?P<value>no) customer token is accepted for MGMT administrative APIs",
        ),
        (
            contract["workload_identity"]["cross_environment"],
            r"Cross-environment workload identity is (?P<value>denied by default)",
        ),
        (
            contract["workload_identity"]["federation_requires"],
            r"federation requires explicit (?P<value>architecture/security review)",
        ),
        (
            contract["secrets"]["flow"],
            r"`(?P<value>OpenBao -> ESO -> Kubernetes Secret/runtime mount)` where applicable",
        ),
        (contract["egress"]["default"], r"## Egress\s+\n\s*(?P<value>Default deny)\."),
        (
            contract["egress"]["application_path"],
            r"application egress uses (?P<value>approved Istio Egress/Squid) path",
        ),
        (contract["egress"]["logging"], r"approved Istio Egress/Squid path with (?P<value>logging)"),
        (contract["egress"]["exceptions"], r"logging and (?P<value>documented) exception"),
    )
    normalizations = {
        "WebAuthn/passkeys backed by hardware keys": "hardware-backed-webauthn-passkeys",
        "no": "forbidden",
        "denied by default": "deny-by-default",
        "architecture/security review": "architecture-security-review",
        "OpenBao -> ESO -> Kubernetes Secret/runtime mount": "openbao-eso-kubernetes-secret-runtime-mount-where-applicable",
        "Default deny": "deny",
        "approved Istio Egress/Squid": "approved-istio-egress-squid",
        "logging": "required",
        "documented": "documented",
    }
    for expected, pattern in facts:
        match = re.search(pattern, source, re.I)
        rendered = normalizations.get(match.group("value"), match.group("value") if match else None) if match else None
        if rendered != expected:
            errors.append(f"security source drift: expected {expected}")
    trust_domains = re.findall(r"^- (PREPROD|PROD-A|PROD-B)\s*$", source, re.M)
    if trust_domains != contract["workload_identity"]["trust_domains"]:
        errors.append("security source drift: workload trust domains")
    forbidden_patterns = {
        "git": r"secrets in Git",
        "image-layers": r"secrets in image layers",
        "ci-logs": r"secrets in CI logs",
        "bootstrap-credentials-after-preprod-destroy": r"long-lived bootstrap credentials left active after PREPROD destroy",
        "application-access-to-openbao-admin-credentials": r"application access to OpenBao administrative credentials",
    }
    for case in contract["secrets"]["forbidden"]:
        if not re.search(rf"^- {forbidden_patterns[case]}[.;]?\s*$", source, re.M | re.I):
            errors.append(f"security source drift: forbidden secret case {case}")
    return errors


def documentation_clauses(text):
    """Yield clauses with only their explicitly labelled historical scope."""
    section_scopes = []
    labelled_block = False
    labelled_content = False
    diagram_fence = False
    marker = r"(?:historical|superseded|alternatives rejected)"

    for line in text.splitlines():
        heading = re.match(r"\s*(#{1,6})\s+(.*)", line)
        if heading:
            level = len(heading.group(1))
            section_scopes = [(parent_level, scope) for parent_level, scope in section_scopes if parent_level < level]
            parent_scope = any(scope for _, scope in section_scopes)
            explicit_scope = bool(re.match(rf"\s*{marker}\b", heading.group(2), re.I))
            section_scopes.append((level, parent_scope or explicit_scope))
            labelled_block = False
            labelled_content = False

        if re.match(rf"\s*[-#>\s]*{marker}\s*:\s*$", line, re.I):
            labelled_block = True
            labelled_content = False
        elif not line.strip():
            if labelled_content:
                labelled_block = False
                labelled_content = False
            continue
        elif labelled_block:
            labelled_content = True

        opening_diagram_fence = bool(re.match(r"\s*```(?:mermaid|plantuml|dot)\b", line, re.I))
        if opening_diagram_fence:
            diagram_fence = True
        historical = any(scope for _, scope in section_scopes) or labelled_block
        for clause in re.split(r";|(?<=[.!?])\s+", line):
            if clause.strip():
                yield clause, historical, diagram_fence
        if diagram_fence and re.match(r"\s*```\s*$", line) and not opening_diagram_fence:
            diagram_fence = False


def derived_index_errors(index, lock, network_plan):
    """Cross-check facts rendered by the derived index against their lock values."""
    errors = []

    def require(fragment, field):
        if fragment not in index:
            errors.append(f"derived index drift from architecture.lock.yaml: {field}")

    def assignments(section, pattern, mapping):
        parsed = re.findall(pattern, section, re.M)
        seen = set()
        for field, _ in parsed:
            if field in seen:
                errors.append(f"duplicate derived index assignment: {mapping}.{field}")
            seen.add(field)
        return dict(parsed)

    require(f"derived from version {lock['version']} of that lock", "version")
    require(f"TTL is locked at {lock['dns']['critical_ttl_seconds']} seconds", "dns.critical_ttl_seconds")

    prod = lock["prod_certified_topology"]
    site_count = len(prod["sites"])
    require(f"{prod['physical_hosts_per_site']} physical failure domains", "prod physical failure domains")
    if index.count(f"{prod['physical_hosts_per_site']} physical failure domains") != site_count:
        errors.append("derived index drift from architecture.lock.yaml: PROD site failure-domain counts")
    require(
        f"{prod['control_planes_per_site']} CP + {prod['workers_per_site']} workers", "PROD control-plane/worker counts"
    )
    if index.count(f"{prod['control_planes_per_site']} CP + {prod['workers_per_site']} workers") != site_count:
        errors.append("derived index drift from architecture.lock.yaml: PROD per-site control-plane/worker counts")
    require(
        f"{prod['data_workers_per_site']} data workers + {prod['general_workers_per_site']} general",
        "PROD worker roles",
    )
    network_section = index.split("## Network", 1)[-1].split("\n## ", 1)[0]
    rendered_blocks = assignments(
        network_section,
        r"^- (PREPROD|PROD-A|PROD-B|permanent MGMT) `([^`]+)`\s*$",
        "network.private_blocks",
    )
    address_domains = network_plan.get("address_domains", {})
    expected_blocks = {
        "PREPROD": address_domains.get("preprod"),
        "PROD-A": prod["sites"]["prod-a"]["private_block"],
        "PROD-B": prod["sites"]["prod-b"]["private_block"],
        "permanent MGMT": lock["management_plane"]["private_block"],
    }
    if rendered_blocks != expected_blocks:
        errors.append("derived index drift from architecture.lock.yaml: labeled private block mapping")

    services = lock["business"]["services"]
    require(f"Exactly {len(services)} backend services", "business.services count")
    service_match = re.search(
        r"^Exactly \d+ backend services, as listed in `architecture\.lock\.yaml` business\.services:\s*\n\n"
        r"(?P<list>[^\n]+)$",
        index,
        re.M,
    )
    rendered_services = re.findall(r"`([a-z0-9-]+)`", service_match.group("list")) if service_match else []
    if rendered_services != services:
        errors.append("derived index drift from architecture.lock.yaml: business.services membership/order")
    require("The canonical frontends are exactly `storefront` and `admin`.", "business.frontends")
    frontend = lock["business"]["frontend_runtime"]
    frontend_section = index.split("## Application ownership", 1)[-1].split("\n## ", 1)[0]
    rendered_frontend = assignments(frontend_section, r"^- `([a-z_]+)`: `([^`]+)`\s*$", "business.frontend_runtime")
    expected_frontend = {field: str(value).lower() for field, value in frontend.items()}
    if rendered_frontend != expected_frontend:
        errors.append("derived index drift from architecture.lock.yaml: business.frontend_runtime role assignments")
    require("Next.js/React/Node is only the migration source", "business.frontend_runtime migration source")
    require(f"M2.5 is `{lock['build_milestones'][3]}`", "M2.5 milestone identity")

    observability = lock["observability"]
    observability_section = index.split("## Observability", 1)[-1].split("\n## ", 1)[0]
    rendered_observability = assignments(observability_section, r"^- `([a-z_]+)`: `([a-z0-9-]+)`\s*$", "observability")
    if rendered_observability != observability:
        errors.append("derived index drift from architecture.lock.yaml: observability role assignments")
        for field, value in observability.items():
            if rendered_observability.get(field) != value:
                errors.append(f"derived index drift from architecture.lock.yaml: observability.{field}")

    mlops_section = index.split("## MLOps", 1)[-1].split("\n## ", 1)[0]
    rendered_mlops = assignments(mlops_section, r"^- `([a-z_]+)`: `([a-z0-9-]+)`\s*$", "mlops")
    if rendered_mlops != lock["mlops"]:
        errors.append("derived index drift from architecture.lock.yaml: mlops role assignments")

    delivery_section = index.split("## Delivery", 1)[-1].split("\n## ", 1)[0]
    rendered_delivery = re.findall(r"^- `([a-z_]+)`: `([a-z0-9-]+)`\s*$", delivery_section, re.M)
    expected_delivery = [
        ("promotion_authority", lock["mlops"]["promotion_authority"]),
        ("ci", lock["platform"]["ci"]),
        ("registry", lock["platform"]["registry"]),
        ("desired_state", lock["platform"]["gitops"]),
        ("kubernetes", lock["platform"]["kubernetes"]),
        ("progressive_delivery", lock["platform"]["progressive_delivery"]),
        ("object_storage", lock["stateful"]["object_storage"]),
    ]
    if rendered_delivery != expected_delivery:
        errors.append("derived index drift from architecture.lock.yaml: delivery role assignments")
    return errors


def documentation_errors(text):
    """Inspect every sentence, including code blocks; no document-wide exemptions."""
    errors = []
    # Preserve fenced-diagram delimiters for scoped historical validation.
    normalized = re.sub(r"[*]", "", text)
    for sentence, scoped_historical, in_diagram in documentation_clauses(normalized):
        # Only an explicit label on this clause qualifies it as historical.
        # An unrelated mention of migration or rejection cannot exempt a claim.
        historical = is_explicit_historical_clause(sentence, scoped_historical)
        topology_claim = is_explicit_topology_claim(sentence)
        if (
            topology_claim
            or re.search(r"\b17\s+(?:(?:go|backend)\s+)*services?\s*\+|\bno\s+checkout\s+service\b", sentence, re.I)
        ) and not historical:
            errors.append("superseded service topology: " + sentence.strip())
        if re.search(r"\bdvc\b", sentence, re.I) and not (historical or is_dvc_retirement_clause(sentence)):
            errors.append("DVC must be explicitly historical/superseded: " + sentence.strip())
        if re.search(r"next\.?js", sentence, re.I) and re.search(
            r"target|cible|prod|runtime|ATS\s*->|\buse\b|\buses\b|deploy|frontend|framework|built\s+with",
            sentence,
            re.I,
        ):
            active_target = is_nextjs_active_target_clause(sentence)
            migration = is_nextjs_migration_source_clause(sentence)
            nextjs_retired = re.search(
                r"next\.?js.{0,30}\b(?:superseded|historical|rejected|forbidden|removed|not\s+(?:the\s+)?(?:target|runtime))\b",
                sentence,
                re.I,
            )
            if active_target or not (historical or migration or nextjs_retired):
                errors.append("Next.js must be explicitly a migration source: " + sentence.strip())
        removed_v2_authority = re.search(
            r"BASELINE_V2(?:\.md)?|EXACT_TOPOLOGY_V2(?:\.md)?|"
            r"\b(?:baseline\s+V2|canonical\s+V2(?:\s+(?:architecture\s+)?baseline)?|V2\s+canonical\s+baseline|V2\s+baseline)\b",
            sentence,
            re.I,
        )
        if removed_v2_authority and not historical:
            errors.append("removed architecture authority/index: " + sentence.strip())
        active = r"(?:active|default|baseline|target|use|uses|deploy|select|GitOps(?: CD)?|progressive delivery|object stor(?:age|e)|logging|SIEM)"
        components = re.finditer(rf"\b(?:{SUPERSEDED_COMPONENT})\b", sentence, re.I)
        if re.search(active, sentence, re.I) and not historical:
            for component in components:
                if not component_is_retired(sentence, re.escape(component.group())):
                    errors.append("superseded platform default must not be active: " + sentence.strip())
                    break
        if in_diagram and re.search(rf"\b(?:{SUPERSEDED_COMPONENT})\b", sentence, re.I) and not historical:
            errors.append("superseded architecture diagram must be explicitly labelled: " + sentence.strip())
        active_role = find_superseded_role_assignment(sentence)
        if (
            active_role
            and not historical
            and not component_is_retired(sentence, re.escape(superseded_assignment_component(active_role)))
        ):
            errors.append("superseded platform role must not be active: " + sentence.strip())
        if (
            re.search(r"Fluent Bit", sentence, re.I)
            and re.search(
                r"(?:general|application|infrastructure)?\s*(?:logging|logs|pipeline|(?:log\s+)?shipper)",
                sentence,
                re.I,
            )
            and not historical
            and not component_is_retired(sentence, r"Fluent Bit")
        ):
            errors.append("Fluent Bit general logging is superseded: " + sentence.strip())
        negated = re.search(
            r"\b(?:no|not|never|forbid(?:den)?|superseded|historical|removed|rejected|do not|must not|only)\b",
            sentence,
            re.I,
        )
        if (
            re.search(r"(?:general|application|infrastructure)\s+(?:logging|logs|log pipeline)", sentence, re.I)
            and re.search(r"Data Prepper|OpenSearch", sentence, re.I)
            and not (historical or negated)
        ):
            errors.append("Data Prepper/OpenSearch general logging role is forbidden: " + sentence.strip())
        if (
            re.search(r"OpenSearch\s+Logs|OpenSearch.{0,20}(?:general\s+)?observability\s+source", sentence, re.I)
            and not re.search(r"security", sentence, re.I)
            and not historical
            and not negated
        ):
            errors.append("OpenSearch general observability storage is superseded: " + sentence.strip())
        if (
            re.search(r"Prometheus", sentence, re.I)
            and re.search(
                r"(?:primary|main|authoritative)\s+(?:TSDB|metrics (?:store|storage|server))|(?:TSDB|metrics (?:store|storage|server))\s+(?:is|:)\s+Prometheus",
                sentence,
                re.I,
            )
            and not (historical or negated)
        ):
            errors.append("Prometheus is compatibility-only, not primary metrics storage: " + sentence.strip())
        if re.search(
            r"application (?:telemetry|logs?|observability)(?:\s+and\s+logs?)?\s*(?:use|uses|->|:)\s*VictoriaLogs|VictoriaLogs\s+for\s+(?:both\s+)?(?:infrastructure\s+(?:and|/)\s+)?application",
            sentence,
            re.I,
        ) and not (historical or negated):
            errors.append("application telemetry/logs must use Rotel, ClickHouse, and HyperDX: " + sentence.strip())
        if re.search(r"(?:observability/)?fluent-bit/", sentence, re.I) and not historical:
            errors.append("Fluent Bit bootstrap component is superseded: " + sentence.strip())
    return errors


def registry_coverage_errors(root, lock):
    """Ensure every governed contract file is registered exactly once in the root authority."""
    errors = []
    root = Path(root)
    for registry_name, patterns in REGISTRY_GLOBS.items():
        declared = lock.get(registry_name, {})
        if not isinstance(declared, dict):
            continue
        values = list(declared.values())
        if len(values) != len(set(values)):
            errors.append(f"{registry_name} must not register the same path more than once")
        for role, relative in declared.items():
            if (
                not isinstance(relative, str)
                or not relative.strip()
                or Path(relative).is_absolute()
                or ".." in Path(relative).parts
            ):
                errors.append(f"{registry_name}.{role} must declare a non-empty repository-relative path")
                continue
            if not (root / relative).is_file():
                errors.append(f"{registry_name}.{role} declared file does not exist: {relative}")
        discovered = set()
        for pattern in patterns:
            discovered.update(
                str(path.relative_to(root))
                for path in root.glob(pattern)
                if path.is_file()
            )
        registered = {
            relative
            for relative in values
            if isinstance(relative, str) and relative.strip()
        }
        missing = sorted(discovered - registered)
        extra = sorted(registered - discovered)
        if missing:
            errors.append(f"{registry_name} has unregistered governed files: {', '.join(missing)}")
        if extra:
            errors.append(f"{registry_name} registers files outside its governed set: {', '.join(extra)}")
    return errors


def validate(root):
    root = Path(root)
    errors = []
    try:
        lock = load_yaml(root / AUTHORITY)
        structural_errors = lock_schema_errors(lock)
        if structural_errors:
            if isinstance(lock, dict) and lock.get("status") != LOCK_STATUS:
                structural_errors.append(f"architecture.lock.yaml status must be {LOCK_STATUS}")
            return structural_errors
        if lock.get("status") != LOCK_STATUS:
            errors.append(f"architecture.lock.yaml status must be {LOCK_STATUS}")
        if lock["version"] != 5:
            errors.append("architecture.lock.yaml must be version 5")
        topology_contracts = lock.get("topology_contracts")
        errors.extend(registry_coverage_errors(root, lock))
        if errors:
            return errors
        if topology_contracts["exact_index"] != INDEX:
            errors.append("exact index must be the derived V5 index")
        if lock.get("observability") != V5_OBSERVABILITY:
            errors.append("observability must match the complete approved V5 mapping")
        if lock["business"].get("frontend_runtime") != EXPECTED_V5_FRONTEND_RUNTIME:
            errors.append("business.frontend_runtime must match the approved V5 mapping")
        if lock.get("repository_governance") != V5_REPOSITORY_GOVERNANCE:
            errors.append("repository_governance must match the approved repository-wide contract")
        if lock.get("developer_platform") != V5_DEVELOPER_PLATFORM:
            errors.append("developer_platform must match the approved V5 PR-driven platform contract")
        if lock.get("platform", {}).get("infrastructure_api") != "crossplane":
            errors.append("platform.infrastructure_api must remain crossplane")
        if lock.get("management_plane", {}).get("developer_portal") != "backstage":
            errors.append("management_plane.developer_portal must remain backstage")
        if lock.get("dns", {}).get("critical_ttl_seconds") != 60:
            errors.append("critical DNS TTL must remain 60 seconds")
        if lock.get("superseded") != V5_SUPERSEDED:
            errors.append("superseded must match the complete approved V5 registry")
        mlops_path = root / topology_contracts["mlops"]
        mlops_section = mlops_path.read_text().split("## Locked role mapping", 1)[-1].split("\n## ", 1)[0]
        mlops_rows = re.findall(r"^- `([a-z_]+)`: `([a-z0-9-]+)`\s*$", mlops_section, re.M)
        seen_mlops = set()
        for field, _ in mlops_rows:
            if field in seen_mlops:
                errors.append(f"duplicate subordinate MLOps assignment: {field}")
            seen_mlops.add(field)
        subordinate_mlops = dict(mlops_rows)
        if lock.get("mlops") != V5_MLOPS or subordinate_mlops != V5_MLOPS:
            errors.append("mlops must match the complete approved V5 mapping and subordinate contract")
        if lock["business"].get("frontends") != V5_FRONTENDS:
            errors.append("business.frontends must match the complete approved V5 frontend set")
        milestones = lock["build_milestones"]
        expected = V5_MILESTONES
        dag = V5_MILESTONE_DEPENDENCIES
        actual_dag = lock.get("milestone_dependencies", {})
        if (
            milestones != expected
            or set(actual_dag) != set(dag)
            or any(sorted(actual_dag.get(name, [])) != sorted(parents) for name, parents in dag.items())
        ):
            errors.append("milestone dependencies must match the approved V5 DAG")
        for key in ("resilience_governance", "security_trust_zones"):
            relative = lock["machine_contracts"].get(key)
            if not relative:
                errors.append(f"missing canonical machine contract role: {key}")
                continue
            contract = load_yaml(root / relative)
            if contract != EXACT_CONTRACTS[key]:
                errors.append(f"{relative} must match its exact V5 invariants")
            if key == "security_trust_zones" and contract == EXACT_CONTRACTS[key]:
                source = (root / contract["source"]).read_text()
                errors.extend(security_source_errors(source, contract))
        # The Ruby architecture validator also checks all declared contract paths
        # and their cross-contract invariants. Never bypass its missing-file checks.
        for relative in lock["machine_contracts"].values():
            if not (root / relative).is_file():
                errors.append(f"missing machine contract: {relative}")

        review_policy = load_yaml(root / lock["machine_contracts"]["review_policy"])
        inherited_owner_authorization = (
            review_policy.get("pull_request_review", {}).get("owner_authorization", {})
        )
        if inherited_owner_authorization != {
            "authority_source": "architecture.lock.yaml#repository_governance.owner_authorization",
            "local_override": "forbidden",
        }:
            errors.append(
                "review policy must inherit repository_governance.owner_authorization without local override"
            )

        ai_reviewer = review_policy.get("pull_request_review", {}).get("ai_reviewer", {})
        if (
            ai_reviewer.get("enabled") is not True
            or ai_reviewer.get("provider") != "ChatGPT"
            or ai_reviewer.get("sole_code_security_authority") is not True
            or ai_reviewer.get("exact_sha_binding") != "required"
            or ai_reviewer.get("prior_sha_review") != "historical-only"
            or ai_reviewer.get("merge_readiness") != {
                "code_review_complete": "required",
                "security_review_complete": "required",
                "unresolved_blocking_findings": "forbidden",
            }
            or ai_reviewer.get("codex") != {
                "review_authority": "forbidden",
                "trigger": "forbidden",
                "polling": "forbidden",
                "merge_readiness_dependency": "forbidden",
            }
            or ai_reviewer.get("evidence") != {
                "transport": "github-pr-comment",
                "marker": "chatgpt-exact-sha-review:v1",
                "required_kinds": ["code", "security"],
                "required_status": "PASS",
                "exact_sha_required": True,
                "comment_author": "repository-owner",
            }
        ):
            errors.append(
                "review policy must make ChatGPT the sole exact-SHA CODE/SECURITY AI authority "
                "and forbid Codex review workflows"
            )

        active_review_automation = {
            "Makefile": ("CODEX_COMMAND", "--codex-command"),
            "scripts/pr_monitor.py": (
                "PR_MONITOR_CODEX_COMMAND",
                "--codex-command",
                "invoke_codex",
                "codex_prompt",
            ),
        }
        for relative, forbidden_tokens in active_review_automation.items():
            source = (root / relative).read_text(encoding="utf-8")
            if any(token.lower() in source.lower() for token in forbidden_tokens):
                errors.append(
                    "review automation must not expose Codex trigger, polling, or invocation controls"
                )
                break

        execution_fallback = review_policy.get("pull_request_review", {}).get(
            "agent_execution_fallback", {}
        )
        if execution_fallback != {
            "primary_agent": "ChatGPT",
            "fallback_agent": "Codex",
            "codex_allowed_when": "chatgpt-capability-unavailable",
            "codex_scope": "execution-only",
            "minimal_task_scope_required": True,
            "fallback_reason_must_be_recorded": True,
            "codex_output_role": "evidence-for-chatgpt",
            "code_security_review_authority": "ChatGPT-only",
            "merge_readiness_authority": "ChatGPT-only",
            "merge_decision_authority": "repository-owner",
            "codex_review_markers": "forbidden",
            "codex_merge_decision": "forbidden",
        }:
            errors.append(
                "Codex must be limited to execution fallback when ChatGPT lacks the required capability"
            )

        review_budget = load_yaml(root / lock["machine_contracts"]["review_budget"])
        if review_budget.get("review_authority_source") != (
            "config/contracts/review-policy.yaml#pull_request_review.ai_reviewer"
        ):
            errors.append("review budget must inherit the canonical ChatGPT review authority")

        management = lock["management_plane"]
        inventory = load_yaml(root / lock["machine_contracts"]["mgmt_inventory"])
        gateways = load_yaml(root / lock["machine_contracts"]["mgmt_access_gateways"])
        wireguard = load_yaml(root / lock["machine_contracts"]["mgmt_wireguard_access"])
        management_checks = {
            "provider": (
                inventory.get("provider"),
                gateways.get("provider"),
                wireguard.get("gateway", {}).get("provider"),
            ),
            "lifecycle": (
                inventory.get("lifecycle", {}).get("mode"),
                gateways.get("lifecycle", {}).get("mode"),
                wireguard.get("gateway", {}).get("lifecycle"),
            ),
            "private_block": (inventory.get("private_block"),),
            "kubernetes": (
                (
                    management.get("kubernetes")
                    if inventory.get("vm_profiles")
                    and all(name.startswith(f"{management.get('kubernetes')}-") for name in inventory["vm_profiles"])
                    else None
                ),
            ),
            "forge": (inventory.get("platform_services", {}).get("forge"),),
            "ci": (inventory.get("platform_services", {}).get("ci"),),
            "registry": (inventory.get("platform_services", {}).get("registry"),),
            "gitops": (inventory.get("platform_services", {}).get("gitops"),),
        }
        for field, subordinate_values in management_checks.items():
            if any(value != management.get(field) for value in subordinate_values):
                errors.append(f"management_plane.{field} contradicts subordinate MGMT contracts")
        bootstrap = management.get("bootstrap", {})
        if (
            bootstrap.get("terraform_opentofu") is not True
            or inventory.get("bootstrap", {}).get("infrastructure") != "terraform-opentofu"
            or bootstrap.get("ansible") is not True
            or inventory.get("bootstrap", {}).get("configuration") != "ansible"
        ):
            errors.append("management_plane.bootstrap contradicts the MGMT inventory")
        human_gates = (
            bootstrap.get("requires_human_apply_gate"),
            inventory.get("bootstrap", {}).get("human_apply_gate"),
            gateways.get("implementation", {}).get("human_apply_gate"),
            wireguard.get("human_gates", {}).get("provider_apply") == "required",
        )
        if any(gate is not True for gate in human_gates):
            errors.append("management_plane.bootstrap requires the locked human apply gate")
        for role, relative in topology_contracts.items():
            path = root / relative
            contents = path.read_text()
            status = re.search(r"^Status:\s*\`([^\`]*)\`\s*$", contents, re.M | re.I)
            status_value = status.group(1).strip().upper() if status else None
            expected_status = "ACTIVE" if role in DERIVED_TOPOLOGY_ROLES else "EXACT"
            if not contents.strip() or status_value != expected_status:
                errors.append(
                    f"topology contract {role} must be readable and {expected_status}: {relative}"
                )
            if role in DERIVED_TOPOLOGY_ROLES and "Architecture authority: `architecture.lock.yaml`" not in contents:
                errors.append(
                    f"derived architecture document must name architecture.lock.yaml as authority: {relative}"
                )
        index = (root / INDEX).read_text()
        if "`architecture.lock.yaml` is the single canonical architecture authority" not in index:
            errors.append("derived index must establish the lock as root authority")
        network_plan = load_yaml(root / lock["machine_contracts"]["network_plan"])
        errors.extend(derived_index_errors(index, lock, network_plan))
        for relative in ("AGENTS.md", "README.md"):
            text = (root / relative).read_text()
            if not re.search(
                r"architecture.lock.yaml.{0,12}(?:— the single canonical architecture authority|, seule autorité canonique)",
                text,
            ):
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
        mandatory_handoffs = handoffs.split("## Mandatory exact architecture contracts", 1)[-1].split("\n## ", 1)[0]
        for key in ("resilience_governance", "security_trust_zones"):
            relative = lock["machine_contracts"][key]
            if f"`{relative}`" not in mandatory_handoffs:
                errors.append(f"CODEX_HANDOFFS.md mandatory contracts must include {relative}")
        m5_match = re.search(r"^## M5 prompt.*?(?=^## |\Z)", handoffs, re.M | re.S)
        m5 = m5_match.group(0) if m5_match else ""
        checkout_flow = (
            "Cart -> Checkout -> Pricing/final totals -> Tax -> Fraud/Risk -> delivery-context validation -> Order"
        )
        if checkout_flow not in m5 or "Fulfillment -> Shipping" not in m5:
            errors.append("CODEX_HANDOFFS.md M5 must preserve autonomous Checkout and Fulfillment domain sequencing")
        m4_match = re.search(r"^## M4 prompt.*?(?=^## |\Z)", handoffs, re.M | re.S)
        m4 = m4_match.group(0) if m4_match else ""
        m4_order_match = re.search(r"^Order:\s*\n`([^`]+)`\.\s*$", m4, re.M)
        approved_m4_order = [
            "RKE2",
            "Cilium/Hubble",
            "Fleet",
            "Argo Rollouts",
            "Kyverno/Pod Security",
            "SPIRE",
            "Istio",
            "OpenBao/ESO",
            "Harbor",
            "Tekton",
            "observability/security logging",
            "stateful platform",
        ]
        rendered_m4_order = [item.strip() for item in m4_order_match.group(1).split("->")] if m4_order_match else []
        if rendered_m4_order != approved_m4_order:
            errors.append("CODEX_HANDOFFS.md M4 order must match the approved platform schedule")
        waves = load_yaml(root / lock["machine_contracts"]["deployment_waves"])
        if waves != V5_DEPLOYMENT_WAVES:
            errors.append("deployment-waves.yaml must match the complete approved V5 schedule")
        if waves.get("status") != "exact":
            errors.append("deployment-waves.yaml status must be exact")
        qualification_ancestors = wave_ancestors(waves.get("waves", []), "110-qualification")
        if not {"100-frontends", "95-mlops"}.issubset(qualification_ancestors):
            errors.append("deployment qualification must depend on both frontend and MLOps completion")
        deployment_dag = (root / topology_contracts["deployment_dag"]).read_text()
        prose_wave_declarations = {}
        for match in re.finditer(
            r"^Machine wave `(?P<id>[a-z0-9-]+)` scheduled components: (?P<components>.+)$",
            deployment_dag,
            re.M,
        ):
            prose_wave_declarations.setdefault(match.group("id"), []).append(match)
        if set(prose_wave_declarations) != set(MIRRORED_WAVES):
            errors.append("DEPLOYMENT_DAG.md machine wave declarations must match the approved mirrored wave set")
        for wave_id in MIRRORED_WAVES:
            matching_waves = [wave for wave in waves.get("waves", []) if wave.get("id") == wave_id]
            machine_components = matching_waves[0].get("components", []) if len(matching_waves) == 1 else []
            prose_matches = prose_wave_declarations.get(wave_id, [])
            prose_match = prose_matches[0] if len(prose_matches) == 1 else None
            prose_components = re.findall(r"`([a-z0-9-]+)`", prose_match.group("components")) if prose_match else []
            if len(matching_waves) != 1 or len(prose_matches) != 1 or prose_components != machine_components:
                errors.append(f"DEPLOYMENT_DAG.md must exactly mirror machine wave {wave_id}")
        spire_waves = []
        for wave in waves.get("waves", []):
            scheduled_components = list(wave.get("components", []))
            scheduled_components.extend(component for group in wave.get("parallel_groups", []) for component in group)
            scheduled_components.extend(wave.get("serial_after_parallel", []))
            spire_waves.extend(wave.get("id") for component in scheduled_components if component == "spire")
        spire_prose = [
            match
            for matches in prose_wave_declarations.values()
            for match in matches
            if "spire" in re.findall(r"`([a-z0-9-]+)`", match.group("components"))
        ]
        gate_w3_position = deployment_dag.find("Gate W3:")
        if (
            len(spire_waves) != 1
            or len(spire_prose) != 1
            or gate_w3_position < 0
            or spire_prose[0].start() > gate_w3_position
        ):
            errors.append("SPIRE must be scheduled exactly once before Gate W3 verifies SPIFFE issuance")
        deployed = []
        scheduled = []
        positions = {}
        for wave_number, wave in enumerate(waves.get("waves", [])):
            for component in wave.get("components", []):
                scheduled.append(component)
                positions.setdefault(component, (wave_number, 0))
            groups = wave.get("parallel_groups", [])
            for group_number, group in enumerate(groups, 1):
                for component in group:
                    scheduled.append(component)
                    positions.setdefault(component, (wave_number, group_number))
            for serial_number, component in enumerate(wave.get("serial_after_parallel", []), len(groups) + 1):
                scheduled.append(component)
                positions.setdefault(component, (wave_number, serial_number))
            deployed.extend(
                component for component in wave.get("components", []) if component in lock["business"]["services"]
            )
            for group in wave.get("parallel_groups", []):
                deployed.extend(component for component in group if component in lock["business"]["services"])
            deployed.extend(
                component
                for component in wave.get("serial_after_parallel", [])
                if component in lock["business"]["services"]
            )
        if len(deployed) != len(set(deployed)) or set(deployed) != set(lock["business"]["services"]):
            errors.append("deployment waves must schedule every canonical business service exactly once")
        frontend_waves = [wave for wave in waves.get("waves", []) if wave.get("id") == "100-frontends"]
        deployed_frontends = frontend_waves[0].get("components", []) if len(frontend_waves) == 1 else []
        scheduled_frontends = [component for component in scheduled if component in V5_FRONTENDS]
        if len(frontend_waves) != 1 or deployed_frontends != V5_FRONTENDS or scheduled_frontends != V5_FRONTENDS:
            errors.append("deployment waves must schedule every canonical V5 frontend exactly once")
        dependencies = load_yaml(root / lock["machine_contracts"]["dependency_map"])["services"]
        for service, contract in dependencies.items():
            for dependency in contract.get("sync", []):
                if service in positions and dependency in positions and positions[service] <= positions[dependency]:
                    errors.append(f"deployment ordering requires {service} after synchronous dependency {dependency}")
        mlops_deployed = [component for component in scheduled if component in DEPLOYABLE_MLOPS]
        if mlops_deployed != DEPLOYABLE_MLOPS:
            errors.append("deployment waves must schedule every canonical deployable MLOps component exactly once")
        mlops_dependencies = {
            "lakefs": ["seaweedfs"],
            "mlflow": ["lakefs", "cloudnativepg"],
            "kserve-vllm": ["mlflow", "harbor", "tekton", "rancher-fleet", "argo-rollouts"],
            "evidently-tekton-batch": ["kserve-vllm", "tekton"],
        }
        for component, required in mlops_dependencies.items():
            for dependency in required:
                if (
                    component not in positions
                    or dependency not in positions
                    or positions[component] <= positions[dependency]
                ):
                    errors.append(f"deployment ordering requires {component} after MLOps dependency {dependency}")
        m7_match = re.search(r"^## M7 prompt.*?(?=^## |\Z)", handoffs, re.M | re.S)
        m7 = m7_match.group(0) if m7_match else ""
        if not re.search(r">=\s*80%\s+global coverage", m7, re.I):
            errors.append("CODEX_HANDOFFS.md M7 must require >=80% global coverage")
        if not re.search(r">=\s*90%\s+critical-code coverage", m7, re.I):
            errors.append("CODEX_HANDOFFS.md M7 must require >=90% critical-code coverage")
        handoff_match = re.search(r"^## M2\.5 prompt.*?(?=^## |\Z)", handoffs, re.M | re.S)
        handoff = handoff_match.group(0) if handoff_match else ""
        roadmap = load_yaml(root / lock["machine_contracts"]["roadmap_policy"])
        roadmap_m25 = next(
            (
                item
                for item in roadmap.get("milestones", [])
                if isinstance(item, dict) and str(item.get("id")) == "M2.5"
            ),
            None,
        )
        roadmap_m25_tracker = roadmap_m25.get("tracker") if isinstance(roadmap_m25, dict) else None
        if type(roadmap_m25_tracker) is not int or roadmap_m25_tracker <= 0:
            errors.append("roadmap policy must declare a positive M2.5 tracker")
            roadmap_m25_tracker = -1
        handoff_requirements = (
            "## M2.5 prompt",
            "M2-5-persistent-mgmt-bootstrap",
            "Entry gate: M1 PROVEN",
            f"Tracker: `#{roadmap_m25_tracker}`",
            "Evidence required for M2.5 PROVEN",
            "Exit gate:",
            "That PROVEN state enables M3",
        )
        if any(requirement not in handoff for requirement in handoff_requirements):
            errors.append("CODEX_HANDOFFS.md must define the executable M2.5 entry, evidence, and M3 exit contract")
        router = load_yaml(root / "config/context/router.yaml")
        l2_patterns = router["levels"]["L2"]["patterns"]
        l2_canonical = router["canonical"]["L2"]
        canonical_l2_contracts = (
            INDEX,
            lock["machine_contracts"]["deployment_waves"],
            topology_contracts["aiops"],
            topology_contracts["mlops"],
        )
        for relative in canonical_l2_contracts:
            if relative not in l2_canonical:
                errors.append(f"L2 context must include exact contract: {relative}")
        for key in ("resilience_governance", "security_trust_zones"):
            relative = lock["machine_contracts"][key]
            if relative not in l2_patterns or relative not in l2_canonical:
                errors.append(f"L2 context must include exact contract: {relative}")
        for keyword in ("resilience", "recovery", "mlops", "aiops"):
            if keyword not in router["levels"]["L2"]["task_keywords"]:
                errors.append(f"L2 context must route {keyword} tasks")
        for old in ("BASELINE_V2.md", "EXACT_TOPOLOGY_V2.md"):
            if (root / "docs/architecture" / old).exists():
                errors.append(f"removed architecture document reintroduced: {old}")
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        errors.append(f"invalid architecture authority contract: {exc}")

    # Include new, untracked documents but exclude ignored generated dependencies.
    paths = (
        subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=root)
        .decode()
        .split("\0")
    )
    for relative in sorted(set(paths)):
        path = root / relative
        if path.suffix.lower() == ".md" and path.is_file():
            errors.extend(f"{relative}: {error}" for error in documentation_errors(path.read_text()))
    return errors


if __name__ == "__main__":
    failures = validate(Path(__file__).resolve().parents[1])
    print("\n".join(failures) if failures else "PASS architecture V5 root authority and documentation")
    raise SystemExit(bool(failures))
