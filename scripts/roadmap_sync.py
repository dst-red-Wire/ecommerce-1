#!/usr/bin/env python3
"""Synchronize project roadmap status from the canonical policy and GitHub issue state."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Any

ROOT = Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip())

SCRIPT_DIR = ROOT / "scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import qualification_cache


def run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
    if check and result.returncode:
        detail = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(detail or f"command failed: {command}")
    return result


def load_yaml(relative: str) -> dict[str, Any]:
    value = qualification_cache.psych_load(ROOT / relative)
    if not isinstance(value, dict):
        raise RuntimeError(f"{relative} must be a YAML mapping")
    return value


def policy() -> dict[str, Any]:
    lock = load_yaml("architecture.lock.yaml")
    relative = lock.get("machine_contracts", {}).get("roadmap_policy")
    if not isinstance(relative, str) or not relative:
        raise RuntimeError("roadmap policy is not registered in architecture.lock.yaml")
    value = load_yaml(relative)
    if (
        value.get("version") != 1
        or value.get("kind") != "RoadmapPolicy"
        or value.get("status") != "enforced"
        or value.get("architecture_authority") != "architecture.lock.yaml"
        or value.get("document") != "docs/project/MASTER_EXECUTION_PLAN.md"
    ):
        raise RuntimeError("invalid roadmap policy header")

    rendering = value.get("rendering")
    milestones = value.get("milestones")
    if not isinstance(rendering, dict) or not isinstance(milestones, list) or not milestones:
        raise RuntimeError("roadmap policy must declare rendering and milestones")

    ids = [str(item.get("id") or "") for item in milestones if isinstance(item, dict)]
    if len(ids) != len(milestones) or any(not item for item in ids) or len(ids) != len(set(ids)):
        raise RuntimeError("roadmap milestone ids must be non-empty and unique")
    known = set(ids)
    seen: set[str] = set()
    for item in milestones:
        milestone_id = str(item["id"])
        requires = item.get("requires", [])
        if not isinstance(requires, list) or any(dep not in known for dep in requires):
            raise RuntimeError(f"roadmap milestone {milestone_id} has invalid dependencies")
        if any(str(dep) not in seen for dep in requires):
            raise RuntimeError(
                f"roadmap milestone {milestone_id} dependencies must appear earlier in topological order"
            )
        seen.add(milestone_id)
        if "fixed_status" not in item:
            tracker = item.get("tracker")
            if type(tracker) is not int or tracker <= 0:
                raise RuntimeError(f"roadmap milestone {item.get('id')} requires a positive tracker issue number")
    return value


def github_name_with_owner(gh: str) -> str:
    response = run([gh, "repo", "view", "--json", "nameWithOwner"], check=False)
    if response.returncode:
        detail = (response.stderr or response.stdout or "").strip()
        raise RuntimeError(detail or "unable to resolve GitHub repository")
    try:
        payload = json.loads(response.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError("invalid GitHub repository JSON") from exc
    name = str(payload.get("nameWithOwner") or "")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", name):
        raise RuntimeError("invalid GitHub nameWithOwner")
    return name


def tracker_states(gh: str, roadmap_policy: dict[str, Any]) -> dict[int, dict[str, str]]:
    repository = github_name_with_owner(gh)
    states: dict[int, dict[str, str]] = {}
    for milestone in roadmap_policy["milestones"]:
        if "fixed_status" in milestone:
            continue
        tracker = int(milestone["tracker"])
        response = run([gh, "api", f"repos/{repository}/issues/{tracker}"], check=False)
        if response.returncode:
            detail = (response.stderr or response.stdout or "").strip()
            raise RuntimeError(f"unable to read roadmap tracker #{tracker}: {detail or 'GitHub API error'}")
        try:
            issue = json.loads(response.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"invalid GitHub JSON for roadmap tracker #{tracker}") from exc
        if not isinstance(issue, dict) or issue.get("pull_request") is not None:
            raise RuntimeError(f"roadmap tracker #{tracker} must be a GitHub issue, not a pull request")
        if int(issue.get("number") or 0) != tracker:
            raise RuntimeError(f"roadmap tracker #{tracker} returned the wrong issue")
        states[tracker] = {
            "state": str(issue.get("state") or "").lower(),
            "state_reason": str(issue.get("state_reason") or "").lower(),
            "title": str(issue.get("title") or ""),
        }
    return states


def compute_statuses(
    roadmap_policy: dict[str, Any],
    states: dict[int, dict[str, str]],
) -> dict[str, str]:
    rendering = roadmap_policy["rendering"]
    terminal = set(rendering["terminal_statuses"])
    ready = str(rendering["ready_status"])
    blocked_prefix = str(rendering["blocked_prefix"])
    github = roadmap_policy["github"]
    completed_state = str(github["completed_state"]).lower()
    completed_reason = str(github["completed_state_reason"]).lower()

    statuses: dict[str, str] = {}
    for milestone in roadmap_policy["milestones"]:
        milestone_id = str(milestone["id"])
        if "fixed_status" in milestone:
            statuses[milestone_id] = str(milestone["fixed_status"])
            continue

        tracker = int(milestone["tracker"])
        state = states.get(tracker)
        if not isinstance(state, dict):
            raise RuntimeError(f"roadmap tracker state missing for #{tracker}")

        unmet = [
            str(dep)
            for dep in milestone.get("requires", [])
            if statuses.get(str(dep)) not in terminal
        ]
        if unmet:
            suffix = ""
            if state.get("state") == completed_state and state.get("state_reason") == completed_reason:
                suffix = f" (tracker #{tracker} completed before prerequisites)"
            statuses[milestone_id] = f"{blocked_prefix} {'/'.join(unmet)}{suffix}"
            continue

        if state.get("state") == completed_state and state.get("state_reason") == completed_reason:
            statuses[milestone_id] = str(milestone.get("completion_status") or "PROVEN")
            continue
        if state.get("state") == completed_state:
            reason = state.get("state_reason") or "unknown"
            statuses[milestone_id] = f"{blocked_prefix} tracker #{tracker} closed as {reason}"
            continue

        statuses[milestone_id] = ready
    return statuses


def cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ").strip()


def render_table(roadmap_policy: dict[str, Any], statuses: dict[str, str]) -> str:
    rows = [
        "| Milestone | Tracker | Primary owner | Objective | Entry gate | Exit gate | Current status |",
        "|---|---:|---|---|---|---|---|",
    ]
    for milestone in roadmap_policy["milestones"]:
        milestone_id = str(milestone["id"])
        tracker = "—" if "fixed_status" in milestone else f"#{int(milestone['tracker'])}"
        rows.append(
            "| "
            + " | ".join(
                [
                    cell(f"{milestone_id} {milestone['name']}"),
                    tracker,
                    cell(milestone["owner"]),
                    cell(milestone["objective"]),
                    cell(milestone["entry_gate"]),
                    cell(milestone["exit_gate"]),
                    cell(statuses[milestone_id]),
                ]
            )
            + " |"
        )
    return "\n".join(rows)


def replace_tracker_line(document: str, heading: str, tracker: int) -> str:
    start = document.find(heading)
    if start < 0:
        return document
    next_h3 = document.find("\n### ", start + len(heading))
    next_h2 = document.find("\n## ", start + len(heading))
    ends = [value for value in (next_h3, next_h2) if value >= 0]
    end = min(ends) if ends else len(document)
    section = document[start:end]
    pattern = r"Canonical tracker: GitHub issue `#\d+`\."
    if re.search(pattern, section):
        tick = chr(96)
        replacement = f"Canonical tracker: GitHub issue {tick}#{tracker}{tick}."
        section = re.sub(pattern, replacement, section, count=1)
        return document[:start] + section + document[end:]
    return document


def render_document(
    document: str,
    roadmap_policy: dict[str, Any],
    statuses: dict[str, str],
) -> str:
    rendering = roadmap_policy["rendering"]
    section_heading = str(rendering["milestone_section_heading"])
    next_heading = str(rendering["next_section_heading"])
    start = document.find(section_heading)
    if start < 0:
        raise RuntimeError(f"roadmap document missing section {section_heading!r}")
    end = document.find(next_heading, start + len(section_heading))
    if end < 0:
        raise RuntimeError(f"roadmap document missing section {next_heading!r}")

    generated = (
        section_heading
        + "\n\n"
        + str(rendering["begin_marker"])
        + "\n"
        + render_table(roadmap_policy, statuses)
        + "\n"
        + str(rendering["end_marker"])
        + "\n\n"
    )
    rendered = document[:start] + generated + document[end:]
    for milestone in roadmap_policy["milestones"]:
        tracker = milestone.get("tracker")
        heading = milestone.get("section_heading")
        if type(tracker) is int and isinstance(heading, str) and heading:
            rendered = replace_tracker_line(rendered, heading, tracker)
    return rendered


def expected_document(gh: str) -> tuple[Path, str, dict[str, str]]:
    roadmap_policy = policy()
    path = ROOT / str(roadmap_policy["document"])
    if not path.is_file():
        raise RuntimeError(f"roadmap document is missing: {path.relative_to(ROOT)}")
    states = tracker_states(gh, roadmap_policy)
    statuses = compute_statuses(roadmap_policy, states)
    expected = render_document(path.read_text(encoding="utf-8"), roadmap_policy, statuses)
    return path, expected, statuses


def check(gh: str, *, quiet: bool = False) -> int:
    path, expected, statuses = expected_document(gh)
    current = path.read_text(encoding="utf-8")
    if current == expected:
        if not quiet:
            print("PASS roadmap-check synchronized")
        return 0
    if not quiet:
        print("ROADMAP_DRIFT")
        for milestone_id, status in statuses.items():
            print(f"{milestone_id:4} {status}")
        print("ACTION make roadmap-sync")
    return 1


def sync(gh: str) -> int:
    status = subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=ROOT,
        text=True,
    ).strip()
    if status:
        raise RuntimeError("roadmap-sync requires a clean worktree")
    path, expected, statuses = expected_document(gh)
    current = path.read_text(encoding="utf-8")
    if current == expected:
        print("PASS roadmap-sync already synchronized")
        return 0
    path.write_text(expected, encoding="utf-8")
    print(f"PASS roadmap-sync updated {path.relative_to(ROOT)}")
    for milestone_id, state in statuses.items():
        print(f"{milestone_id:4} {state}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["check", "sync"])
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    gh = shutil.which("gh") or shutil.which("gh.exe")
    if not gh:
        print("FAIL roadmap synchronization requires GitHub CLI", file=sys.stderr)
        return 2
    try:
        if args.action == "check":
            return check(gh, quiet=args.quiet)
        return sync(gh)
    except (RuntimeError, KeyError, ValueError) as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
