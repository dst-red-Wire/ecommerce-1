#!/usr/bin/env python3
"""Plan milestone work-item issues from declarations and GitHub readback."""

from __future__ import annotations

import argparse
import copy
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

import issue_lifecycle
import work_package

ROOT = Path(__file__).resolve().parents[1]
MARKER = issue_lifecycle.ISSUE_MARKER
REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
ISSUES_PER_PAGE = 100
MAX_ISSUE_PAGES = 100


class MilestonePlanError(ValueError):
    """The plan cannot safely infer a unique issue relation."""


def _read_yaml(path: Path) -> dict[str, Any]:
    if path.is_symlink():
        raise MilestonePlanError(f"YAML path is a symlink: {path}")
    try:
        value = yaml.load(
            path.read_text(encoding="utf-8"),
            Loader=issue_lifecycle._UniqueKeyLoader,
        )
    except (OSError, UnicodeError, yaml.YAMLError, issue_lifecycle.IssueLifecycleError) as exc:
        raise MilestonePlanError(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise MilestonePlanError(f"{path} must contain a YAML mapping")
    return value


def load_roadmap(root: Path) -> dict[str, Any]:
    lock = _read_yaml(root / "architecture.lock.yaml")
    relative = (lock.get("machine_contracts") or {}).get("roadmap_policy")
    if relative != "config/contracts/roadmap-policy.yaml":
        raise MilestonePlanError("RoadmapPolicy is not the canonical registered contract")
    roadmap = _read_yaml(root / relative)
    if roadmap.get("kind") != "RoadmapPolicy" or roadmap.get("status") != "enforced":
        raise MilestonePlanError("RoadmapPolicy is not enforced")
    return roadmap


def _gh_json(gh: str, arguments: list[str], *, method: str = "GET") -> Any:
    command = [gh, "api"]
    if method != "GET":
        command.extend(["--method", method])
    command.extend(arguments)
    result = subprocess.run(
        command, cwd=ROOT, text=True, capture_output=True, check=False, timeout=45,
    )
    if result.returncode:
        raise MilestonePlanError(
            (result.stderr or result.stdout or "GitHub API failed").strip()[:500]
        )
    try:
        return json.loads(result.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise MilestonePlanError("GitHub returned invalid JSON") from exc


def repository_identity(gh: str) -> str:
    result = subprocess.run(
        [gh, "repo", "view", "--json", "nameWithOwner"],
        cwd=ROOT, text=True, capture_output=True, check=False, timeout=20,
    )
    if result.returncode:
        raise MilestonePlanError(
            (result.stderr or result.stdout or "GitHub repository unavailable").strip()[:500]
        )
    try:
        value = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise MilestonePlanError("GitHub repository identity is malformed") from exc
    repository = value.get("nameWithOwner")
    if not isinstance(repository, str) or REPOSITORY_RE.fullmatch(repository) is None:
        raise MilestonePlanError("GitHub repository identity is invalid")
    return repository


def tracker_readback(gh: str, repository: str, number: int) -> dict[str, Any]:
    value = _gh_json(gh, [f"repos/{repository}/issues/{number}"])
    if (
        not isinstance(value, dict)
        or value.get("number") != number
        or value.get("pull_request") is not None
        or value.get("state") not in {"open", "closed"}
    ):
        raise MilestonePlanError(f"tracker #{number} is not the exact GitHub issue")
    return {
        "number": number,
        "category": "milestone-tracker",
        "state": value["state"],
        "url": value.get("html_url"),
    }


def all_github_issues(gh: str, repository: str) -> list[dict[str, Any]]:
    """Scan every open and closed issue using bounded, checked REST pages."""
    if not isinstance(repository, str) or REPOSITORY_RE.fullmatch(repository) is None:
        raise MilestonePlanError("GitHub repository identity is invalid")
    issues: list[dict[str, Any]] = []
    seen: set[int] = set()
    for page in range(1, MAX_ISSUE_PAGES + 1):
        payload = _gh_json(
            gh,
            [
                f"repos/{repository}/issues?"
                f"state=all&per_page={ISSUES_PER_PAGE}&page={page}"
            ],
        )
        if not isinstance(payload, list) or len(payload) > ISSUES_PER_PAGE:
            raise MilestonePlanError(f"GitHub issue page {page} is malformed")
        for issue in payload:
            if not isinstance(issue, dict):
                raise MilestonePlanError(f"GitHub issue page {page} is malformed")
            number = issue.get("number")
            if type(number) is not int or number <= 0 or number in seen:
                raise MilestonePlanError(
                    f"GitHub issue pagination has invalid or repeated issue number on page {page}"
                )
            seen.add(number)
            if issue.get("pull_request") is None:
                issues.append(issue)
        if len(payload) < ISSUES_PER_PAGE:
            return issues
    raise MilestonePlanError(
        f"GitHub issue pagination exceeded {MAX_ISSUE_PAGES} pages; completeness is unknown"
    )

def _structured_issue(issue: dict[str, Any]) -> dict[str, Any] | None:
    body = str(issue.get("body") or "")
    if MARKER not in body:
        return None
    try:
        relation = issue_lifecycle.parse_work_item_marker(body)
    except issue_lifecycle.IssueLifecycleError as exc:
        raise MilestonePlanError(f"issue #{issue['number']}: {exc}") from exc
    if issue.get("state") not in {"open", "closed"}:
        raise MilestonePlanError(f"issue #{issue['number']} has invalid state")
    return {
        "number": issue["number"],
        "category": "work-item",
        "milestone": relation["milestone"],
        "tracker_issue": relation["tracker_issue"],
        "work_package_id": relation["work_package_id"],
        "work_package_path": relation["work_package_path"],
        "state": issue["state"],
        "url": issue.get("html_url"),
    }

def declared_packages(root: Path, milestone: str, tracker: int) -> list[dict[str, Any]]:
    directory = root / "config" / "work-packages" / milestone
    if directory.is_symlink():
        raise MilestonePlanError("work package directory is a symlink")
    if not directory.is_dir():
        return []
    packages: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.yaml")):
        if path.is_symlink() or not path.is_file():
            raise MilestonePlanError(f"work package path is unsafe: {path}")
        value = _read_yaml(path)
        identifier = value.get("id")
        if not isinstance(identifier, str) or path.stem != identifier:
            raise MilestonePlanError(f"work package filename does not match its ID: {path}")
        try:
            issue_lifecycle.idempotency_key(milestone, identifier)
        except issue_lifecycle.IssueLifecycleError as exc:
            raise MilestonePlanError(str(exc)) from exc
        if value.get("milestone") != milestone or value.get("tracker_issue") != tracker:
            raise MilestonePlanError(f"work package {identifier} has wrong milestone/tracker")
        binding = value.get("work_item_issue")
        if binding is None:
            checked = copy.deepcopy(value)
            checked["work_item_issue"] = tracker + 1
            relation_state = "DRAFT_RELATION_PENDING"
        elif type(binding) is int and binding > 0 and binding != tracker:
            checked = value
            relation_state = "BOUND"
        else:
            raise MilestonePlanError(f"work package {identifier} has invalid issue binding")
        violations = work_package.validate_work_package(
            checked, root=root, expected_milestone=milestone,
        )
        if violations:
            raise MilestonePlanError(
                f"work package {identifier} is invalid: {'; '.join(violations)}"
            )
        packages.append({
            "id": identifier,
            "path": path.relative_to(root).as_posix(),
            "work_item_issue": binding,
            "relation_state": relation_state,
            "declaration": value,
        })
    if len({item["id"] for item in packages}) != len(packages):
        raise MilestonePlanError("duplicate declared work package ID")
    return packages


def _issue_body(package: dict[str, Any], milestone: str, tracker: int) -> str:
    declaration = package["declaration"]
    marker = {
        "category": "work-item",
        "milestone": milestone,
        "tracker_issue": tracker,
        "work_package_id": package["id"],
        "work_package_path": package["path"],
    }
    acceptance = declaration["acceptance"]
    scope = declaration["scope"]
    sections = [
        f"<!-- {MARKER} {json.dumps(marker, sort_keys=True, separators=(',', ':'))} -->",
        "",
        f"Work package: {package['path']}",
        f"Milestone: {milestone}; tracker: #{tracker}",
        "",
        "Objective: " + declaration["objective"],
        "",
        "Allowed paths: " + ", ".join(scope["allowed_paths"]),
        "Forbidden paths: " + (", ".join(scope["forbidden_paths"]) or "none"),
        "Contracts: " + ", ".join(acceptance["contracts"]),
        "Tests: " + ", ".join(acceptance["tests"]),
        "Qualification gates: " + ", ".join(acceptance["qualification_gates"]),
        "Runtime evidence: " + (", ".join(acceptance["runtime_evidence"]) or "none"),
        "Exit criteria: " + "; ".join(declaration["exit_criteria"]),
        "",
        "This issue and its labels are relations, not technical proof.",
    ]
    return "\n".join(sections) + "\n"


def plan_milestone(
    root: Path, milestone: str, *, gh: str, repository: str,
) -> dict[str, Any]:
    """Read every open/closed issue before proposing a single new issue."""
    root = Path(root)
    try:
        if not isinstance(repository, str) or REPOSITORY_RE.fullmatch(repository) is None:
            raise MilestonePlanError("GitHub repository identity is invalid")
        roadmap = load_roadmap(root)
        tracker = issue_lifecycle.tracker_for_milestone(roadmap, milestone)
        tracker_issue = tracker_readback(gh, repository, tracker)
        packages = declared_packages(root, milestone, tracker)
        if not packages:
            return {
                "status": "BLOCKED", "reason": "NO_DECLARED_PACKAGES",
                "milestone": milestone, "tracker_issue": tracker_issue,
                "proposals": [], "reused": [], "errors": [],
            }
        raw_issues = all_github_issues(gh, repository)
        existing = [
            relation for issue in raw_issues
            if (relation := _structured_issue(issue)) is not None
        ]
        plan = issue_lifecycle.plan_missing_work_items(
            roadmap, milestone, [item["id"] for item in packages], existing,
        )
        if plan["status"] != "PASS":
            raise MilestonePlanError("; ".join(plan["errors"]))
        by_id = {item["id"]: item for item in packages}
        by_existing = {item["work_package_id"]: item for item in existing
                       if item["milestone"] == milestone}
        for identifier, package in by_id.items():
            relation = by_existing.get(identifier)
            if relation is not None and relation["work_package_path"] != package["path"]:
                raise MilestonePlanError(
                    f"work item for {identifier} points to another package path"
                )
            if relation is not None and package["work_item_issue"] not in (
                None, relation["number"],
            ):
                raise MilestonePlanError(
                    f"work package {identifier} binds another issue number"
                )
        proposals = []
        for item in plan["missing"]:
            package = by_id[item["work_package_id"]]
            if package["work_item_issue"] is not None:
                raise MilestonePlanError(
                    f"bound work package {package['id']} has no matching GitHub issue"
                )
            identifier = package["id"]
            if any(identifier in str(issue.get("title") or "")
                   or identifier in str(issue.get("body") or "")
                   for issue in raw_issues):
                raise MilestonePlanError(
                    f"ambiguous historical issue already mentions {identifier}"
                )
            declaration = package["declaration"]
            proposals.append({
                **item,
                "work_package_path": package["path"],
                "relation_state": package["relation_state"],
                "title": f"[{milestone}/{identifier}] {declaration['objective']}"[:180],
                "body": _issue_body(package, milestone, tracker),
                "required_package_update": "set work_item_issue to created issue number",
            })
        reused = []
        for item in plan["reused"]:
            package = by_id[item["work_package_id"]]
            reused.append({
                **item,
                "work_package_path": package["path"],
                "package_relation_pending": package["work_item_issue"] is None,
            })
        return {
            "status": "PASS", "milestone": milestone,
            "tracker_issue": tracker_issue,
            "proposals": proposals, "reused": reused, "errors": [],
        }
    except (MilestonePlanError, issue_lifecycle.IssueLifecycleError) as exc:
        return {
            "status": "BLOCKED", "reason": "INVALID_RELATION",
            "milestone": milestone, "proposals": [], "reused": [],
            "errors": [str(exc)],
        }


def create_missing(
    root: Path, milestone: str, *, gh: str, repository: str,
) -> dict[str, Any]:
    """Explicit mutation; refresh all GitHub relations before each POST."""
    initial = plan_milestone(root, milestone, gh=gh, repository=repository)
    if initial["status"] != "PASS":
        return initial
    created: list[dict[str, Any]] = []
    for candidate in initial["proposals"]:
        current = plan_milestone(root, milestone, gh=gh, repository=repository)
        if current["status"] != "PASS":
            return {**current, "created": created}
        matches = [
            item for item in current["proposals"]
            if item["idempotency_key"] == candidate["idempotency_key"]
        ]
        if not matches:
            continue
        proposal = matches[0]
        response = _gh_json(
            gh,
            [
                f"repos/{repository}/issues",
                "-f", f"title={proposal['title']}",
                "-f", f"body={proposal['body']}",
            ],
            method="POST",
        )
        number = response.get("number") if isinstance(response, dict) else None
        if type(number) is not int or number <= 0:
            raise MilestonePlanError(
                "GitHub issue creation outcome is unknown; rerun read-only plan"
            )
        exact = _gh_json(gh, [f"repos/{repository}/issues/{number}"])
        relation = _structured_issue(exact) if isinstance(exact, dict) else None
        if (
            relation is None
            or relation["number"] != number
            or relation["tracker_issue"] != current["tracker_issue"]["number"]
            or relation["milestone"] != milestone
            or relation["work_package_id"] != proposal["work_package_id"]
            or relation["work_package_path"] != proposal["work_package_path"]
        ):
            raise MilestonePlanError(
                f"created issue #{number} did not read back the exact relation"
            )
        created.append({
            "number": number,
            "idempotency_key": proposal["idempotency_key"],
            "work_package_path": proposal["work_package_path"],
            "required_package_update": proposal["required_package_update"],
        })
    final = plan_milestone(root, milestone, gh=gh, repository=repository)
    if final["status"] != "PASS":
        return {**final, "created": created}
    created_keys = {item["idempotency_key"] for item in created}
    pending = [
        item["idempotency_key"] for item in final["proposals"]
        if item["idempotency_key"] in created_keys
    ]
    if pending:
        return {
            **final,
            "status": "BLOCKED",
            "reason": "PENDING_INDEXING",
            "proposals": [
                item for item in final["proposals"]
                if item["idempotency_key"] not in created_keys
            ],
            "created": created,
            "pending_indexing": pending,
            "errors": [
                "created issue GET is exact, but issue-list indexing has not caught up; "
                "bind its number in the package before another creation attempt"
            ],
        }
    return {**final, "created": created}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--milestone", required=True)
    parser.add_argument("--json", action="store_true", default=True)
    parser.add_argument("--create", action="store_true")
    args = parser.parse_args(argv)
    gh = shutil.which("gh") or shutil.which("gh.exe")
    if not gh:
        print(json.dumps({"status": "BLOCKED", "reason": "GH_UNAVAILABLE"}))
        return 2
    try:
        repository = repository_identity(gh)
        result = (
            create_missing(ROOT, args.milestone, gh=gh, repository=repository)
            if args.create
            else plan_milestone(ROOT, args.milestone, gh=gh, repository=repository)
        )
    except (MilestonePlanError, OSError, subprocess.TimeoutExpired) as exc:
        result = {"status": "BLOCKED", "reason": "GITHUB_UNAVAILABLE",
                  "errors": [str(exc)]}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
