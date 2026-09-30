#!/usr/bin/env python3
"""Pure issue hierarchy checks and proof-derived work-item state."""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = Path("config/contracts/issue-lifecycle-policy.yaml")
SHA_RE = re.compile(r"[0-9a-f]{40}")
PACKAGE_ID_RE = re.compile(r"[a-z][a-z0-9._-]{2,79}")
REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
ISSUE_MARKER = "ecommerce-work-item:v1"
PR_MARKER = "ecommerce-pr-work-item:v1"
ACCEPTANCE_AUTHORITY = "qualified-work-package-acceptance"
PREMERGE_ACCEPTANCE_AUTHORITY = "qualified-work-package-premerge-acceptance"
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
SYSTEM_TEST_RE = re.compile(r"tests/(?:delivery/)?test_[^/]+[.]py")
CATEGORIES = ("milestone-tracker", "work-item", "defect", "follow-up")
PROGRESSION = (
    "CONTRACTED", "PR_OPEN", "QUALIFIED", "REVIEWED",
    "MERGED", "VERIFIED", "CLOSED",
)
EXACT_HEAD_PROOFS = (
    "qualification", "code_review", "security_review",
    "acceptance", "evidence_bundle",
)


class IssueLifecycleError(ValueError):
    """A relation or policy has no trustworthy interpretation."""


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_mapping(loader: _UniqueKeyLoader, node: yaml.MappingNode) -> dict:
    value: dict = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        if not isinstance(key, (str, int)) or key in value:
            raise IssueLifecycleError("issue lifecycle YAML has an invalid or duplicate key")
        value[key] = loader.construct_object(value_node, deep=True)
    return value


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping
)


def load_policy(root: Path = ROOT) -> dict[str, Any]:
    """Read the contract and reject changes that weaken lifecycle boundaries."""
    path = Path(root) / POLICY_PATH
    if path.is_symlink():
        raise IssueLifecycleError("IssueLifecyclePolicy path must not be a symlink")
    try:
        value = yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueKeyLoader)
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise IssueLifecycleError(f"cannot load IssueLifecyclePolicy: {exc}") from exc
    if not isinstance(value, dict):
        raise IssueLifecycleError("IssueLifecyclePolicy must be a mapping")
    header = {
        "version": 1,
        "kind": "IssueLifecyclePolicy",
        "status": "enforced",
        "architecture_authority": "architecture.lock.yaml",
        "roadmap_authority": "config/contracts/roadmap-policy.yaml",
        "work_package_authority": "config/contracts/work-package-policy.yaml",
    }
    if set(value) != set(header) | {
        "categories", "hierarchy", "idempotency", "relations",
        "finding_disposition", "completion",
    }:
        raise IssueLifecycleError("IssueLifecyclePolicy fields are incomplete or unknown")
    if any(type(value.get(key)) is not type(expected) or value[key] != expected
           for key, expected in header.items()):
        raise IssueLifecycleError("IssueLifecyclePolicy header is invalid")
    if value["categories"] != list(CATEGORIES):
        raise IssueLifecycleError("issue categories changed")
    if value["hierarchy"] != [
        "milestone", "milestone-tracker", "work-item", "work-package", "pr"
    ]:
        raise IssueLifecycleError("issue hierarchy changed")
    if value["idempotency"] != {
        "fields": ["milestone", "work_package_id"],
        "existing_open_or_closed_issue": "reuse",
        "duplicate_key": "fail",
    }:
        raise IssueLifecycleError("issue idempotency rules changed")
    if value["relations"] != {
        "milestone_tracker": "roadmap-tracker-number",
        "work_item_parent": "exact-milestone-tracker",
        "work_package_binding": "exact-work-item-and-milestone",
        "pr_primary_work_item": "required",
        "structured_fields_required": True,
        "issue_state_is_technical_proof": False,
        "issue_label_is_technical_proof": False,
    }:
        raise IssueLifecycleError("issue relation rules changed")
    if value["finding_disposition"] != {
        "blocking_to_follow_up": "forbidden",
        "follow_up_requires": [
            "non_blocking", "outside_scope", "deferrable",
            "governance_decision", "linked_pr",
        ],
    }:
        raise IssueLifecycleError("finding disposition rules changed")
    if value["completion"] != {
        "progression": list(PROGRESSION),
        "invalid_state": "BLOCKED",
        "required_exact_head_proofs": list(EXACT_HEAD_PROOFS),
        "runtime_if_required": True,
        "recovery_if_required": True,
        "post_merge_required": True,
        "post_merge_required_checks": [
            "signature_verified", "main_contains_change",
            "qualified_tree_matches", "clean_worktree", "roadmap_sync",
        ],
        "manual_issue_close_is_proof": False,
        "tracker_close_is_proof": False,
    }:
        raise IssueLifecycleError("issue completion rules changed")
    return value


def _positive_number(value: object) -> bool:
    return type(value) is int and value > 0


def _sha(value: object) -> bool:
    return isinstance(value, str) and SHA_RE.fullmatch(value) is not None


def tracker_for_milestone(roadmap: Mapping[str, Any], milestone: str) -> int:
    """Use RoadmapPolicy as the only milestone-to-tracker authority."""
    milestones = roadmap.get("milestones")
    if not isinstance(milestones, list):
        raise IssueLifecycleError("roadmap milestones are missing")
    matches = [item for item in milestones if isinstance(item, dict)
               and item.get("id") == milestone]
    if len(matches) != 1 or not _positive_number(matches[0].get("tracker")):
        raise IssueLifecycleError(f"milestone {milestone} has no unique tracker")
    tracker = matches[0]["tracker"]
    if sum(isinstance(item, dict) and item.get("tracker") == tracker
           for item in milestones) != 1:
        raise IssueLifecycleError(f"tracker #{tracker} is assigned to multiple milestones")
    return tracker


def idempotency_key(milestone: str, work_package_id: str) -> str:
    if not isinstance(milestone, str) or not re.fullmatch(r"M[0-9]+(?:[.][0-9]+)?", milestone):
        raise IssueLifecycleError("idempotency milestone is invalid")
    if not isinstance(work_package_id, str) or PACKAGE_ID_RE.fullmatch(work_package_id) is None:
        raise IssueLifecycleError("idempotency work package ID is invalid")
    return f"{milestone}:{work_package_id}"


def validate_relations(
    roadmap: Mapping[str, Any],
    tracker_issue: object,
    work_item_issue: object,
    work_package: object,
    pr: object | None = None,
) -> list[str]:
    """Check structured links; issue state and labels never prove execution."""
    errors: list[str] = []
    if not isinstance(work_item_issue, dict):
        return ["work-item issue is missing"]
    milestone = work_item_issue.get("milestone")
    try:
        tracker_number = tracker_for_milestone(roadmap, milestone)
    except IssueLifecycleError as exc:
        return [str(exc)]
    if not isinstance(tracker_issue, dict):
        errors.append("milestone tracker issue is missing")
    elif (
        tracker_issue.get("category") != "milestone-tracker"
        or tracker_issue.get("number") != tracker_number
        or tracker_issue.get("milestone") != milestone
        or tracker_issue.get("state") not in {"open", "closed"}
    ):
        errors.append("tracker issue does not match the canonical milestone")
    issue_number = work_item_issue.get("number")
    if (
        work_item_issue.get("category") != "work-item"
        or not _positive_number(issue_number)
        or issue_number == tracker_number
        or work_item_issue.get("tracker_issue") != tracker_number
        or work_item_issue.get("state") not in {"open", "closed"}
    ):
        errors.append("work-item issue has invalid structured parent or state")
    if not isinstance(work_package, dict):
        errors.append("work-item has no work package")
    elif (
        work_package.get("id") != work_item_issue.get("work_package_id")
        or work_package.get("milestone") != milestone
        or work_package.get("tracker_issue") != tracker_number
        or work_package.get("work_item_issue") != issue_number
    ):
        errors.append("work package does not bind the exact work-item hierarchy")
    else:
        try:
            idempotency_key(milestone, work_package["id"])
        except IssueLifecycleError as exc:
            errors.append(str(exc))
    if pr is not None:
        if not isinstance(pr, dict):
            errors.append("PR relation must be structured")
        elif (
            not _positive_number(pr.get("number"))
            or pr.get("work_item_issue") != issue_number
            or pr.get("state") not in {"OPEN", "MERGED"}
            or not _sha(pr.get("base_sha"))
            or not _sha(pr.get("head_sha"))
            or (pr.get("state") == "MERGED" and not _sha(pr.get("merge_sha")))
        ):
            errors.append("PR does not bind the exact primary work item and SHA")
    return errors


def plan_missing_work_items(
    roadmap: Mapping[str, Any],
    milestone: str,
    required_work_package_ids: Sequence[str],
    existing_issues: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Read-only idempotent plan; a closed matching issue is reused."""
    errors: list[str] = []
    try:
        tracker = tracker_for_milestone(roadmap, milestone)
    except IssueLifecycleError as exc:
        return {"status": "FAIL", "missing": [], "reused": [], "errors": [str(exc)]}
    if isinstance(required_work_package_ids, (str, bytes)) or not isinstance(
        required_work_package_ids, Sequence
    ):
        return {"status": "FAIL", "missing": [], "reused": [],
                "errors": ["required work packages must be a sequence"]}
    required: list[str] = []
    for identifier in required_work_package_ids:
        try:
            key = idempotency_key(milestone, identifier)
        except IssueLifecycleError as exc:
            errors.append(str(exc))
            continue
        if key in required:
            errors.append(f"duplicate required work package: {key}")
        required.append(key)
    found: dict[str, Mapping[str, Any]] = {}
    for issue in existing_issues:
        if not isinstance(issue, Mapping) or issue.get("category") != "work-item":
            continue
        if issue.get("milestone") != milestone:
            continue
        try:
            key = idempotency_key(milestone, issue.get("work_package_id"))
        except IssueLifecycleError as exc:
            errors.append(str(exc))
            continue
        if issue.get("tracker_issue") != tracker or not _positive_number(issue.get("number")):
            errors.append(f"existing work item {key} has invalid tracker or number")
        if key in found:
            errors.append(f"duplicate work-item issue for {key}")
        else:
            found[key] = issue
    if errors:
        return {"status": "FAIL", "milestone": milestone, "tracker_issue": tracker,
                "missing": [], "reused": [], "errors": sorted(set(errors))}
    return {
        "status": "PASS",
        "milestone": milestone,
        "tracker_issue": tracker,
        "missing": [
            {"work_package_id": key.split(":", 1)[1], "idempotency_key": key}
            for key in required if key not in found
        ],
        "reused": [
            {"work_package_id": key.split(":", 1)[1], "idempotency_key": key,
             "issue": found[key]["number"], "state": found[key].get("state")}
            for key in required if key in found
        ],
        "errors": [],
    }



def _marker_payload(body: object, marker: str) -> dict[str, Any]:
    """Require one complete structured marker line, without ambiguous copies."""
    if not isinstance(body, str):
        raise IssueLifecycleError(f"{marker} body is missing")
    lines = [line for line in body.splitlines() if marker in line]
    prefix = f"<!-- {marker} "
    if len(lines) != 1 or not lines[0].startswith(prefix) or not lines[0].endswith(" -->"):
        raise IssueLifecycleError(f"{marker} requires one exact structured marker")
    try:
        payload = json.loads(lines[0][len(prefix):-4])
    except json.JSONDecodeError as exc:
        raise IssueLifecycleError(f"{marker} contains invalid JSON") from exc
    if not isinstance(payload, dict):
        raise IssueLifecycleError(f"{marker} must contain a JSON object")
    return payload


def _package_path(milestone: str, package_id: str) -> str:
    idempotency_key(milestone, package_id)
    return f"config/work-packages/{milestone}/{package_id}.yaml"


def parse_work_item_marker(body: object) -> dict[str, Any]:
    """Read the issue relation from its body; labels and closure are ignored."""
    value = _marker_payload(body, ISSUE_MARKER)
    required = {
        "category", "milestone", "tracker_issue",
        "work_package_id", "work_package_path",
    }
    if set(value) != required or value.get("category") != "work-item":
        raise IssueLifecycleError("work-item marker fields or category are invalid")
    expected = _package_path(value.get("milestone"), value.get("work_package_id"))
    if (
        not _positive_number(value.get("tracker_issue"))
        or value.get("work_package_path") != expected
    ):
        raise IssueLifecycleError("work-item marker has invalid package path or tracker")
    return value


def parse_pr_work_item_marker(body: object) -> dict[str, Any]:
    """Read the single primary work item relation declared by a PR."""
    value = _marker_payload(body, PR_MARKER)
    required = {
        "work_item_issue", "work_package_path", "milestone", "tracker_issue",
    }
    if set(value) != required:
        raise IssueLifecycleError("PR work-item marker fields are invalid")
    path = value.get("work_package_path")
    milestone = value.get("milestone")
    if not isinstance(path, str):
        raise IssueLifecycleError("PR work-item marker path is invalid")
    parts = path.split("/")
    if (
        len(parts) != 4
        or parts[:2] != ["config", "work-packages"]
        or parts[2] != milestone
        or not parts[3].endswith(".yaml")
    ):
        raise IssueLifecycleError("PR work-item marker path is invalid")
    package_id = parts[3][:-5]
    if path != _package_path(milestone, package_id):
        raise IssueLifecycleError("PR work-item marker path is invalid")
    if (
        not _positive_number(value.get("work_item_issue"))
        or not _positive_number(value.get("tracker_issue"))
        or value["work_item_issue"] == value["tracker_issue"]
    ):
        raise IssueLifecycleError("PR work-item marker issue numbers are invalid")
    return value


def format_pr_work_item_marker(work_package: Mapping[str, Any]) -> str:
    """Build the exact marker repoctl may include in a PR body."""
    if not isinstance(work_package, Mapping):
        raise IssueLifecycleError("work package is missing")
    milestone = work_package.get("milestone")
    package_id = work_package.get("id")
    path = _package_path(milestone, package_id)
    issue = work_package.get("work_item_issue")
    tracker = work_package.get("tracker_issue")
    if not _positive_number(issue) or not _positive_number(tracker) or issue == tracker:
        raise IssueLifecycleError("work package issue relation is invalid")
    payload = {
        "milestone": milestone,
        "tracker_issue": tracker,
        "work_item_issue": issue,
        "work_package_path": path,
    }
    return f"<!-- {PR_MARKER} {json.dumps(payload, sort_keys=True, separators=(',', ':'))} -->"


def validate_pr_work_item_readback(
    roadmap: Mapping[str, Any],
    pr: object,
    issue: object,
    work_package: object,
    tracker_issue: object,
) -> list[str]:
    """Validate raw GitHub PR and issue GET results against the package and roadmap."""
    if not all(isinstance(value, Mapping) for value in (pr, issue, work_package, tracker_issue)):
        return ["GitHub PR, issue, tracker, and work package must be mappings"]
    errors: list[str] = []
    try:
        milestone = work_package.get("milestone")
        canonical_tracker = tracker_for_milestone(roadmap, milestone)
        expected_path = _package_path(milestone, work_package.get("id"))
        pr_relation = parse_pr_work_item_marker(pr.get("body"))
        issue_relation = parse_work_item_marker(issue.get("body"))
    except IssueLifecycleError as exc:
        return [str(exc)]
    work_item_number = work_package.get("work_item_issue")
    if (
        pr_relation != {
            "milestone": milestone,
            "tracker_issue": canonical_tracker,
            "work_item_issue": work_item_number,
            "work_package_path": expected_path,
        }
    ):
        errors.append("PR marker does not bind the exact canonical work item")
    if (
        issue_relation != {
            "category": "work-item",
            "milestone": milestone,
            "tracker_issue": canonical_tracker,
            "work_package_id": work_package.get("id"),
            "work_package_path": expected_path,
        }
    ):
        errors.append("work-item marker does not bind the exact canonical package")
    if (
        issue.get("number") != work_item_number
        or issue.get("pull_request") is not None
        or issue.get("state") not in {"open", "closed"}
    ):
        errors.append("GitHub issue readback is not the exact work item")
    if (
        tracker_issue.get("number") != canonical_tracker
        or tracker_issue.get("pull_request") is not None
        or tracker_issue.get("state") not in {"open", "closed"}
    ):
        errors.append("GitHub tracker readback is not the canonical issue")
    merged = pr.get("merged_at") is not None
    if pr.get("state") not in {"open", "closed"} or (
        pr.get("state") == "closed" and not merged
    ) or (pr.get("state") == "open" and merged):
        errors.append("GitHub PR state is inconsistent or closed without merge")
    head = pr.get("head")
    base = pr.get("base")
    projected_pr = {
        "number": pr.get("number"),
        "work_item_issue": pr_relation["work_item_issue"],
        "state": "MERGED" if merged else "OPEN",
        "base_sha": base.get("sha") if isinstance(base, Mapping) else None,
        "head_sha": head.get("sha") if isinstance(head, Mapping) else None,
    }
    if merged:
        projected_pr["merge_sha"] = pr.get("merge_commit_sha")
    projected_issue = {
        "number": issue.get("number"), "category": "work-item",
        "milestone": issue_relation["milestone"],
        "tracker_issue": issue_relation["tracker_issue"],
        "work_package_id": issue_relation["work_package_id"],
        "state": issue.get("state"),
    }
    projected_tracker = {
        "number": tracker_issue.get("number"), "category": "milestone-tracker",
        "milestone": milestone, "state": tracker_issue.get("state"),
    }
    errors.extend(validate_relations(
        roadmap, projected_tracker, projected_issue, work_package, projected_pr
    ))
    return sorted(set(errors))


def _gh_issue_json(gh: str, repository: str, endpoint: str) -> dict[str, Any]:
    try:
        result = subprocess.run(
            [gh, "api", f"repos/{repository}/{endpoint}"],
            cwd=ROOT, text=True, capture_output=True, check=False, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise IssueLifecycleError(f"GitHub readback unavailable: {exc}") from exc
    if result.returncode:
        raise IssueLifecycleError(
            (result.stderr or result.stdout or "GitHub readback failed").strip()[:500]
        )
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise IssueLifecycleError("GitHub readback returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise IssueLifecycleError("GitHub readback must be a JSON object")
    return value


def read_pr_work_item_relation(
    gh: str,
    repository: str,
    pr_number: int,
    roadmap: Mapping[str, Any],
    work_package: Mapping[str, Any],
) -> dict[str, Any]:
    """GET the PR and both issue relations; never write or close an issue."""
    head_sha: str | None = None
    base_sha: str | None = None
    if not isinstance(work_package, Mapping):
        return {
            "status": "FAIL", "pr": pr_number, "work_item_issue": None,
            "head_sha": None, "base_sha": None,
            "errors": ["work package must be a mapping"],
        }
    try:
        if (
            not isinstance(repository, str)
            or REPOSITORY_RE.fullmatch(repository) is None
            or not _positive_number(pr_number)
        ):
            raise IssueLifecycleError("GitHub repository or PR number is invalid")
        pr = _gh_issue_json(gh, repository, f"pulls/{pr_number}")
        if pr.get("number") != pr_number:
            raise IssueLifecycleError("GitHub returned another PR number")
        marker = parse_pr_work_item_marker(pr.get("body"))
        issue = _gh_issue_json(
            gh, repository, f"issues/{marker['work_item_issue']}"
        )
        tracker = _gh_issue_json(
            gh, repository, f"issues/{marker['tracker_issue']}"
        )
        errors = validate_pr_work_item_readback(
            roadmap, pr, issue, work_package, tracker
        )
        if not errors:
            head_sha = pr["head"]["sha"]
            base_sha = pr["base"]["sha"]
    except IssueLifecycleError as exc:
        errors = [str(exc)]
    return {
        "status": "PASS" if not errors else "FAIL",
        "pr": pr_number,
        "work_item_issue": work_package.get("work_item_issue"),
        "head_sha": head_sha,
        "base_sha": base_sha,
        "errors": errors,
    }

def validate_follow_up(finding: object, issue: object) -> list[str]:
    """A blocking PR finding must be fixed in its PR, never deferred."""
    if not isinstance(finding, dict) or not isinstance(issue, dict):
        return ["finding and follow-up issue must be structured"]
    errors: list[str] = []
    if finding.get("blocking") is not False:
        errors.append("blocking or unknown finding cannot become follow-up")
    if finding.get("outside_scope") is not True:
        errors.append("follow-up finding must be outside PR scope")
    if finding.get("deferrable") is not True:
        errors.append("follow-up finding is not explicitly deferrable")
    if (
        issue.get("category") != "follow-up"
        or not _positive_number(finding.get("pr"))
        or issue.get("linked_pr") != finding.get("pr")
    ):
        errors.append("follow-up issue must link the originating PR")
    decision = issue.get("governance_decision")
    if not isinstance(decision, str) or not decision.strip():
        errors.append("follow-up requires a recorded governance decision")
    return errors


def validate_defect(finding: object, issue: object) -> list[str]:
    if not isinstance(finding, dict) or not isinstance(issue, dict):
        return ["finding and defect issue must be structured"]
    if finding.get("outside_correcting_pr") is not True:
        return ["defect issue is only for work outside the correcting PR"]
    if issue.get("category") != "defect" or not _positive_number(issue.get("number")):
        return ["defect issue category or number is invalid"]
    return []



def _git_read(root: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *arguments],
            cwd=root, text=True, capture_output=True, check=False, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise IssueLifecycleError(f"qualified Git HEAD unavailable: {exc}") from exc
    if result.returncode:
        raise IssueLifecycleError(
            (result.stderr or "qualified Git HEAD read failed").strip()[:500]
        )
    return result.stdout


def read_qualified_head_snapshot(root: Path, head_sha: str) -> dict[str, Any]:
    """Read policy and ordinary tracked file paths from the qualified Git commit."""
    if not _sha(head_sha):
        raise IssueLifecycleError("qualified head SHA is invalid")
    root = Path(root).resolve()
    if _git_read(root, "cat-file", "-t", head_sha).strip() != "commit":
        raise IssueLifecycleError("qualified head is not a Git commit")
    tree_sha = _git_read(root, "rev-parse", f"{head_sha}^{{tree}}").strip()
    if not _sha(tree_sha):
        raise IssueLifecycleError("qualified head tree SHA is invalid")
    entries = _git_read(root, "ls-tree", "-r", "-z", head_sha)
    paths: list[str] = []
    for entry in entries.split("\0"):
        if not entry:
            continue
        try:
            metadata, relative = entry.split("\t", 1)
            mode, kind, object_sha = metadata.split(" ")
        except ValueError as exc:
            raise IssueLifecycleError("qualified Git tree entry is malformed") from exc
        if not _sha(object_sha) or not relative or relative.startswith("/"):
            raise IssueLifecycleError("qualified Git tree entry is invalid")
        if kind == "blob" and mode in {"100644", "100755"}:
            paths.append(relative)
    if len(paths) != len(set(paths)):
        raise IssueLifecycleError("qualified Git tree has duplicate paths")
    policy_path = "config/contracts/qualification-execution-policy.yaml"
    if policy_path not in paths:
        raise IssueLifecycleError("qualification policy is absent from qualified HEAD")
    try:
        policy = yaml.load(
            _git_read(root, "show", f"{head_sha}:{policy_path}"),
            Loader=_UniqueKeyLoader,
        )
    except (yaml.YAMLError, IssueLifecycleError) as exc:
        raise IssueLifecycleError(f"qualified qualification policy is invalid: {exc}") from exc
    if (
        not isinstance(policy, dict)
        or policy.get("kind") != "QualificationExecutionPolicy"
        or policy.get("status") != "enforced"
        or not isinstance(policy.get("gates"), dict)
    ):
        raise IssueLifecycleError("qualified qualification policy is not enforced")
    roadmap_path = "config/contracts/roadmap-policy.yaml"
    if roadmap_path not in paths:
        raise IssueLifecycleError("RoadmapPolicy is absent from qualified HEAD")
    try:
        roadmap = yaml.load(
            _git_read(root, "show", f"{head_sha}:{roadmap_path}"),
            Loader=_UniqueKeyLoader,
        )
    except (yaml.YAMLError, IssueLifecycleError) as exc:
        raise IssueLifecycleError(f"qualified RoadmapPolicy is invalid: {exc}") from exc
    if (
        not isinstance(roadmap, dict)
        or roadmap.get("kind") != "RoadmapPolicy"
        or roadmap.get("status") != "enforced"
        or not isinstance(roadmap.get("qce_traceability"), dict)
    ):
        raise IssueLifecycleError("qualified RoadmapPolicy is not enforced")
    return {
        "authority": "git-qualified-head-snapshot",
        "head_sha": head_sha,
        "tree_sha": tree_sha,
        "paths": sorted(paths),
        "qualification_policy": policy,
        "roadmap_policy": roadmap,
    }


def _acceptance_list(value: object, label: str, errors: list[str]) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
        or len(value) != len(set(value))
    ):
        errors.append(f"{label} must be a nonempty unique string list")
        return []
    return value


def _optional_acceptance_list(
    value: object, label: str, errors: list[str]
) -> list[str]:
    if (
        not isinstance(value, list)
        or any(not isinstance(item, str) or not item for item in value)
        or len(value) != len(set(value))
    ):
        errors.append(f"{label} must be a unique string list")
        return []
    return value


def _qce_acceptance(
    capabilities: list[str],
    roadmap: object,
    registry: Mapping[str, Any],
    statuses: Mapping[str, str],
    path_set: set[str],
    gate_results: dict[str, str],
    errors: list[str],
) -> dict[str, str]:
    """Prove qualification-gate QCE capabilities from the qualified roadmap."""
    if not capabilities:
        return {}
    trace = roadmap.get("qce_traceability") if isinstance(roadmap, Mapping) else None
    groups = trace.get("capabilities") if isinstance(trace, Mapping) else None
    if (
        not isinstance(roadmap, Mapping)
        or roadmap.get("kind") != "RoadmapPolicy"
        or roadmap.get("status") != "enforced"
        or not isinstance(groups, Mapping)
    ):
        errors.append("qualified RoadmapPolicy has no QCE capability authority")
        return {capability: "FAIL" for capability in capabilities}
    catalog: dict[str, Mapping[str, Any]] = {}
    for entries in groups.values():
        if not isinstance(entries, list):
            errors.append("qualified QCE capability catalog is malformed")
            continue
        for entry in entries:
            identifier = entry.get("id") if isinstance(entry, Mapping) else None
            if not isinstance(identifier, str) or not identifier or identifier in catalog:
                errors.append("qualified QCE capability catalog has duplicate or invalid IDs")
            else:
                catalog[identifier] = entry
    results: dict[str, str] = {}
    for identifier in capabilities:
        before = len(errors)
        entry = catalog.get(identifier)
        if entry is None:
            errors.append(f"required QCE capability is absent from qualified RoadmapPolicy: {identifier}")
            results[identifier] = "FAIL"
            continue
        proof = entry.get("proof")
        if (
            not isinstance(proof, Mapping)
            or set(proof) != {"kind"}
            or proof.get("kind") != "qualification-gates"
        ):
            errors.append(
                f"QCE capability has no verifiable qualification-gates proof: {identifier}"
            )
            results[identifier] = "FAIL"
            continue
        if entry.get("activation_guard") is not None:
            errors.append(f"QCE activation guard is not verified: {identifier}")
        declared_gates = entry.get("gates")
        if (
            not isinstance(declared_gates, list)
            or not declared_gates
            or any(not isinstance(gate, str) for gate in declared_gates)
            or len(declared_gates) != len(set(declared_gates))
        ):
            errors.append(f"QCE capability gate contract is invalid: {identifier}")
            declared_gates = []
        for gate in declared_gates:
            status = statuses.get(gate, "MISSING")
            gate_results[gate] = status
            if gate not in registry or status != "PASS":
                errors.append(f"QCE capability gate is not canonical PASS: {identifier} -> {gate}")
        implementation = entry.get("implementation_paths")
        if (
            not isinstance(implementation, list)
            or not implementation
            or any(not isinstance(path, str) or not path for path in implementation)
            or len(implementation) != len(set(implementation))
        ):
            errors.append(f"QCE capability implementation paths are invalid: {identifier}")
            implementation = []
        for relative in implementation:
            if relative not in path_set:
                errors.append(
                    f"QCE implementation is absent from qualified Git HEAD: "
                    f"{identifier} -> {relative}"
                )
        results[identifier] = "PASS" if len(errors) == before else "FAIL"
    return results


def _derive_acceptance(
    work_package: object,
    qualification_input: object,
    qualified_head_snapshot: object,
    *,
    require_historical: bool,
) -> dict[str, Any]:
    """Shared pure gate, test-owner, and contract projection."""
    package = work_package if isinstance(work_package, Mapping) else {}
    qualification = (
        qualification_input
        if isinstance(qualification_input, Mapping) else {}
    )
    snapshot = (
        qualified_head_snapshot if isinstance(qualified_head_snapshot, Mapping) else {}
    )
    head_sha = qualification.get("head_sha")
    head_tree_sha = qualification.get("head_tree_sha")
    witness = qualification.get("historical_verification")
    errors: list[str] = []
    if (
        qualification.get("status") != "PASS"
        or qualification.get("evidence_kind") != "exact_commit"
        or qualification.get("exact_commit_evidence") is not True
        or not _sha(head_sha)
        or not _sha(head_tree_sha)
    ):
        errors.append("exact qualification is not validated PASS")
    if require_historical and (
        not isinstance(witness, Mapping)
        or witness.get("status") != "VERIFIED"
        or not _sha(witness.get("merge_sha"))
        or not isinstance(witness.get("evidence_sha256"), str)
        or DIGEST_RE.fullmatch(witness["evidence_sha256"]) is None
        or not isinstance(witness.get("bundle_digest"), str)
        or DIGEST_RE.fullmatch(witness["bundle_digest"]) is None
    ):
        errors.append("historical exact qualification is not verified PASS")
    if (
        snapshot.get("authority") != "git-qualified-head-snapshot"
        or snapshot.get("head_sha") != head_sha
        or snapshot.get("tree_sha") != head_tree_sha
        or not _sha(snapshot.get("head_sha"))
        or not _sha(snapshot.get("tree_sha"))
    ):
        errors.append("qualified Git HEAD snapshot does not match qualification")
    paths = snapshot.get("paths")
    if (
        not isinstance(paths, list)
        or any(not isinstance(path, str) or not path for path in paths)
        or len(paths) != len(set(paths))
    ):
        errors.append("qualified Git HEAD path inventory is invalid")
        path_set: set[str] = set()
    else:
        path_set = set(paths)
    policy = snapshot.get("qualification_policy")
    registry = policy.get("gates") if isinstance(policy, Mapping) else None
    if (
        not isinstance(policy, Mapping)
        or policy.get("kind") != "QualificationExecutionPolicy"
        or policy.get("status") != "enforced"
        or not isinstance(registry, Mapping)
    ):
        errors.append("qualified qualification gate policy is invalid")
        registry = {}
    package_id = package.get("id")
    milestone = package.get("milestone")
    try:
        package_path = _package_path(milestone, package_id)
    except IssueLifecycleError as exc:
        errors.append(str(exc))
        package_path = None
    if package_path not in path_set:
        errors.append("work package declaration is absent from qualified Git HEAD")
    acceptance = package.get("acceptance")
    if not isinstance(acceptance, Mapping):
        errors.append("work package acceptance declaration is missing")
        acceptance = {}
    required = _acceptance_list(
        acceptance.get("qualification_gates"),
        "acceptance.qualification_gates", errors,
    )
    tests = _acceptance_list(
        acceptance.get("tests"), "acceptance.tests", errors,
    )
    contracts = _acceptance_list(
        acceptance.get("contracts"), "acceptance.contracts", errors,
    )
    qce_capabilities = _optional_acceptance_list(
        acceptance.get("qce_capabilities"),
        "acceptance.qce_capabilities", errors,
    )
    gate_records = qualification.get("gates")
    statuses: dict[str, str] = {}
    if not isinstance(gate_records, list):
        errors.append("historical qualification gate records are missing")
    else:
        for row in gate_records:
            if (
                not isinstance(row, Mapping)
                or not isinstance(row.get("gate"), str)
                or row["gate"] in statuses
                or row.get("status") not in {"PASS", "FAIL", "SKIP", "BLOCKED_RUNTIME"}
            ):
                errors.append("historical qualification gate records are invalid or duplicated")
                continue
            statuses[row["gate"]] = row["status"]
    owners: dict[str, str] = {}
    for gate, definition in registry.items():
        if not isinstance(gate, str) or not isinstance(definition, Mapping):
            errors.append("qualified gate registry contains an invalid definition")
            continue
        owned = definition.get("owned_tests", [])
        if not isinstance(owned, list):
            errors.append(f"gate {gate} has invalid owned_tests")
            continue
        for relative in owned:
            if not isinstance(relative, str) or not relative.startswith("tests/"):
                errors.append(f"gate {gate} has invalid owned test path")
            elif relative in owners:
                errors.append(f"test ownership collision: {relative}")
            elif "*" in gate:
                errors.append(f"test owner must be an exact gate: {gate}")
            else:
                owners[relative] = gate
    gate_results: dict[str, str] = {}
    for gate in required:
        if gate not in registry:
            errors.append(f"required acceptance gate is not canonical: {gate}")
        status = statuses.get(gate, "MISSING")
        gate_results[gate] = status
        if status != "PASS":
            errors.append(f"required acceptance gate is not PASS: {gate}")
    test_owners: dict[str, str] = {}
    for relative in tests:
        owner = owners.get(relative)
        if owner is None and SYSTEM_TEST_RE.fullmatch(relative):
            owner = "system"
        if owner is None or owner not in registry:
            errors.append(f"required test has no canonical gate owner: {relative}")
            continue
        test_owners[relative] = owner
        if relative not in path_set:
            errors.append(f"required test is absent from qualified Git HEAD: {relative}")
        status = statuses.get(owner, "MISSING")
        gate_results[owner] = status
        if status != "PASS":
            errors.append(f"required test owner gate is not PASS: {relative} -> {owner}")
    contract_results: dict[str, str] = {}
    for relative in contracts:
        if not (
            relative == "architecture.lock.yaml"
            or relative.startswith("config/contracts/")
            or relative.startswith("config/infrastructure/")
        ) or relative.startswith("/") or "/.." in relative or chr(92) in relative:
            errors.append(f"required contract path is unsafe: {relative}")
        present = relative in path_set
        contract_results[relative] = "PRESENT" if present else "MISSING"
        if not present:
            errors.append(f"required contract is absent from qualified Git HEAD: {relative}")
    qce_results = _qce_acceptance(
        qce_capabilities, snapshot.get("roadmap_policy"), registry,
        statuses, path_set, gate_results, errors,
    )
    return {
        "status": "FAIL" if errors else "PASS",
        "authority": (
            ACCEPTANCE_AUTHORITY if require_historical
            else PREMERGE_ACCEPTANCE_AUTHORITY
        ),
        "head_sha": head_sha if _sha(head_sha) else None,
        "head_tree_sha": head_tree_sha if _sha(head_tree_sha) else None,
        "historical_verification": (
            "VERIFIED" if require_historical
            and isinstance(witness, Mapping)
            and witness.get("status") == "VERIFIED"
            else "UNVERIFIED" if require_historical else "NOT_APPLICABLE"
        ),
        "qualification_evidence_sha256": (
            witness.get("evidence_sha256") if isinstance(witness, Mapping) else None
        ),
        "work_package_id": package_id,
        "milestone": milestone,
        "work_item_issue": package.get("work_item_issue"),
        "gate_results": gate_results,
        "test_owners": test_owners,
        "contracts": contract_results,
        "qce_capabilities": qce_results,
        "errors": sorted(set(errors)),
    }


def derive_work_package_acceptance(
    work_package: object,
    historical_qualification: object,
    qualified_head_snapshot: object,
) -> dict[str, Any]:
    """Require a verified historical witness after merge."""
    return _derive_acceptance(
        work_package, historical_qualification, qualified_head_snapshot,
        require_historical=True,
    )


def derive_premerge_acceptance(
    work_package: object,
    exact_qualification: object,
    qualified_head_snapshot: object,
) -> dict[str, Any]:
    """Use an already validated exact-head qualification before merge."""
    return _derive_acceptance(
        work_package, exact_qualification, qualified_head_snapshot,
        require_historical=False,
    )


def acceptance_proof_state(
    proof: object, head_sha: str, work_package: Mapping[str, Any]
) -> str:
    """Accept only the dedicated exact-head acceptance projection."""
    state = proof_state(proof, head_sha)
    if state != "PASS":
        return state
    if (
        proof.get("authority") != ACCEPTANCE_AUTHORITY
        or proof.get("work_package_id") != work_package.get("id")
        or proof.get("milestone") != work_package.get("milestone")
        or proof.get("work_item_issue") != work_package.get("work_item_issue")
        or proof.get("historical_verification") != "VERIFIED"
        or not _sha(proof.get("head_tree_sha"))
        or not isinstance(proof.get("qualification_evidence_sha256"), str)
        or DIGEST_RE.fullmatch(proof["qualification_evidence_sha256"]) is None
        or not isinstance(proof.get("gate_results"), Mapping)
        or not proof["gate_results"]
        or any(status != "PASS" for status in proof["gate_results"].values())
        or not isinstance(proof.get("test_owners"), Mapping)
        or not proof["test_owners"]
        or not isinstance(proof.get("contracts"), Mapping)
        or not proof["contracts"]
        or any(status != "PRESENT" for status in proof["contracts"].values())
        or not isinstance(proof.get("qce_capabilities"), Mapping)
        or any(status != "PASS" for status in proof["qce_capabilities"].values())
        or proof.get("errors") != []
    ):
        return "FAIL"
    return "PASS"

def proof_state(proof: object, head_sha: str) -> str:
    """An older valid proof is historical SUPERSEDED, never current PASS."""
    if not isinstance(proof, Mapping) or not proof:
        return "MISSING"
    if proof.get("head_sha") != head_sha:
        return "SUPERSEDED"
    if proof.get("status") == "PASS":
        return "PASS"
    return "FAIL"


def post_merge_state(proof: object, head_sha: str, merge_sha: str) -> str:
    if not isinstance(proof, Mapping) or not proof:
        return "MISSING"
    if proof.get("head_sha") != head_sha:
        return "SUPERSEDED"
    if proof.get("merge_sha") != merge_sha:
        return "FAIL"
    if (
        proof.get("status") != "PASS"
        or not _sha(proof.get("base_sha"))
        or not _sha(proof.get("merge_tree_sha"))
        or proof.get("signature_verified") is not True
        or proof.get("main_contains_change") is not True
        or proof.get("qualified_tree_matches") is not True
        or proof.get("clean_worktree") is not True
        or proof.get("roadmap_sync") != "PASS"
    ):
        return "FAIL"
    return "PASS"


def project_work_item(
    roadmap: Mapping[str, Any],
    tracker_issue: object,
    work_item_issue: object,
    work_package: object,
    pr: object | None,
    *,
    work_package_validation: object,
    qualification: object = None,
    code_review: object = None,
    security_review: object = None,
    acceptance: object = None,
    evidence_bundle: object = None,
    runtime: object = None,
    recovery: object = None,
    post_merge: object = None,
) -> dict[str, Any]:
    """Derive closure from independent proofs bound to the PR's exact head."""
    errors = validate_relations(
        roadmap, tracker_issue, work_item_issue, work_package, pr
    )
    package_id = work_package.get("id") if isinstance(work_package, dict) else None
    if (
        not isinstance(work_package_validation, Mapping)
        or work_package_validation.get("status") != "VALID"
        or work_package_validation.get("id") != package_id
    ):
        errors.append("work package declaration is not VALID")
    issue_number = work_item_issue.get("number") if isinstance(work_item_issue, dict) else None
    if errors:
        return {"status": "BLOCKED", "work_item_issue": issue_number,
                "errors": sorted(set(errors)), "proofs": {}}
    if pr is None:
        status = "CONTRACTED"
        if work_item_issue["state"] == "closed":
            status = "BLOCKED"
            errors.append("closed work item has no verified PR")
        return {"status": status, "work_item_issue": issue_number,
                "errors": errors, "proofs": {}}

    head_sha = pr["head_sha"]
    proof_inputs = {
        "qualification": qualification,
        "code_review": code_review,
        "security_review": security_review,
        "acceptance": acceptance,
        "evidence_bundle": evidence_bundle,
    }
    proofs = {
        name: (
            acceptance_proof_state(value, head_sha, work_package)
            if name == "acceptance" else proof_state(value, head_sha)
        )
        for name, value in proof_inputs.items()
    }
    execution = work_package.get("execution", {})
    if not isinstance(execution, dict):
        execution = {}
    proofs["runtime"] = (
        proof_state(runtime, head_sha)
        if execution.get("runtime_required") is True else "NOT_REQUIRED"
    )
    proofs["recovery"] = (
        proof_state(recovery, head_sha)
        if execution.get("recovery_required") is True else "NOT_REQUIRED"
    )
    proofs["post_merge"] = (
        post_merge_state(post_merge, head_sha, pr["merge_sha"])
        if pr["state"] == "MERGED" else "MISSING"
    )
    if pr["state"] == "MERGED":
        status = "MERGED"
        required = (*EXACT_HEAD_PROOFS, "post_merge")
        if (
            all(proofs[name] == "PASS" for name in required)
            and proofs["runtime"] in {"PASS", "NOT_REQUIRED"}
            and proofs["recovery"] in {"PASS", "NOT_REQUIRED"}
        ):
            status = "VERIFIED"
    else:
        status = "PR_OPEN"
        if proofs["qualification"] == "PASS":
            status = "QUALIFIED"
            if proofs["code_review"] == proofs["security_review"] == "PASS":
                status = "REVIEWED"
    if work_item_issue["state"] == "closed":
        if status == "VERIFIED":
            status = "CLOSED"
        else:
            status = "BLOCKED"
            errors.append("manual issue closure has no technical proof")
    return {
        "status": status,
        "work_item_issue": issue_number,
        "pr": pr["number"],
        "head_sha": head_sha,
        "merge_sha": pr.get("merge_sha"),
        "proofs": proofs,
        "errors": errors,
    }


def main() -> int:
    """Read-only policy check; network issue planning belongs to the caller."""
    try:
        policy = load_policy()
    except IssueLifecycleError as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps({"status": "PASS", "kind": policy["kind"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
