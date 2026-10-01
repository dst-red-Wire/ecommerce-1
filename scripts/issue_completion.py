#!/usr/bin/env python3
"""Close one work-item issue only from an exact, verified merged PR."""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

try:
    from scripts import (
        delivery_preflight,
        evidence_bundle,
        issue_lifecycle,
        post_merge_verify,
        runtime_authority,
        work_package,
    )
except ModuleNotFoundError:
    import delivery_preflight
    import evidence_bundle
    import issue_lifecycle
    import post_merge_verify
    import runtime_authority
    import work_package


_SHA = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


class IssueCompletionError(RuntimeError):
    """A closure authority or GitHub readback was not established."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise IssueCompletionError(reason)


def _github_json(
    root: Path,
    gh: str,
    repository: str,
    endpoint: str,
    *,
    close: bool = False,
) -> dict[str, Any]:
    command = [gh, "api"]
    if close:
        command += ["-X", "PATCH"]
    command.append(f"repos/{repository}/{endpoint}")
    if close:
        command += ["-f", "state=closed"]
    try:
        result = subprocess.run(
            command,
            cwd=root,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise IssueCompletionError(
            f"GitHub issue operation unavailable: {exc}"
        ) from exc
    if result.returncode:
        raise IssueCompletionError(
            (result.stderr or result.stdout or "GitHub issue operation failed").strip()[
                :500
            ]
        )
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise IssueCompletionError(
            "GitHub issue operation returned invalid JSON"
        ) from exc
    _require(isinstance(value, dict), "GitHub issue operation returned no JSON object")
    return value


def _git_package_bytes(root: Path, head: str, relative: str) -> bytes:
    _require(
        isinstance(relative, str)
        and relative.startswith("config/work-packages/")
        and relative.endswith(".yaml")
        and ".." not in Path(relative).parts
        and "\\" not in relative,
        "work package path is not canonical",
    )
    try:
        result = subprocess.run(
            ["git", "show", f"{head}:{relative}"],
            cwd=root,
            text=False,
            capture_output=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise IssueCompletionError(
            f"qualified work package unavailable: {exc}"
        ) from exc
    _require(result.returncode == 0, "work package is absent from qualified HEAD")
    _require(isinstance(result.stdout, bytes), "Git work package bytes are unavailable")
    return result.stdout


def _git_show_package(root: Path, head: str, relative: str) -> dict[str, Any]:
    try:
        package = yaml.load(
            _git_package_bytes(root, head, relative), Loader=work_package._UniqueKeyLoader
        )
    except (yaml.YAMLError, work_package.WorkPackageError) as exc:
        raise IssueCompletionError("qualified work package YAML is invalid") from exc
    _require(isinstance(package, dict), "qualified work package must be a mapping")
    return package


def _review(proof: object, kind: str, head: str) -> dict[str, Any]:
    _require(isinstance(proof, Mapping), f"{kind} review proof is missing")
    required = {
        "provider",
        "kind",
        "head_sha",
        "status",
        "blocking_findings",
        "comment_id",
        "source",
    }
    _require(
        set(proof) == required
        and proof.get("provider") == "ChatGPT"
        and proof.get("kind") == kind
        and proof.get("head_sha") == head
        and proof.get("status") == "PASS"
        and type(proof.get("blocking_findings")) is int
        and proof["blocking_findings"] == 0
        and type(proof.get("comment_id")) is int
        and proof["comment_id"] > 0
        and proof.get("source") == "github-pr-comment",
        f"{kind} review has no exact ChatGPT GitHub authority",
    )
    return dict(proof)


def _signed_post_merge(
    root: Path, snapshot: Mapping[str, Any], supplied: object
) -> dict[str, Any]:
    _require(isinstance(supplied, Mapping), "signed post-merge proof is missing")
    pr_number = snapshot.get("number")
    head = snapshot.get("head_sha")
    base = snapshot.get("base_sha")
    merge = snapshot.get("merge_commit_sha")
    _require(
        type(pr_number) is int
        and pr_number > 0
        and all(
            isinstance(value, str) and _SHA.fullmatch(value)
            for value in (head, base, merge)
        )
        and snapshot.get("state") == "MERGED"
        and snapshot.get("merged") is True,
        "GitHub snapshot does not identify an exact merged PR",
    )
    proof = post_merge_verify.read_post_merge_proof(
        root,
        merge,
        expected_pr=pr_number,
        expected_head=head,
        snapshot=snapshot,
    )
    _require(
        proof == dict(supplied)
        and proof.get("status") == "PASS"
        and proof.get("pr") == pr_number
        and proof.get("base_sha") == base
        and proof.get("head_sha") == head
        and proof.get("merge_sha") == merge
        and proof.get("roadmap_sync") == "PASS"
        and all(
            proof.get(field) is True
            for field in (
                "signature_verified",
                "main_contains_change",
                "qualified_tree_matches",
                "clean_worktree",
            )
        ),
        "supplied post-merge proof differs from signed verified facts",
    )
    witness = proof.get("qualification_witness")
    _require(
        isinstance(witness, Mapping)
        and set(witness) == {"evidence_sha256", "manifest_sha256"}
        and all(
            isinstance(value, str) and _DIGEST.fullmatch(value)
            for value in witness.values()
        ),
        "signed qualification witness is missing",
    )
    return proof


def _relation(
    root: Path,
    gh: str,
    repository: str,
    snapshot: Mapping[str, Any],
    roadmap: Mapping[str, Any],
    package: Mapping[str, Any],
) -> tuple[
    dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]
]:
    number = snapshot["number"]
    pr = _github_json(root, gh, repository, f"pulls/{number}")
    issue_number = package["work_item_issue"]
    tracker_number = package["tracker_issue"]
    issue = _github_json(root, gh, repository, f"issues/{issue_number}")
    tracker = _github_json(root, gh, repository, f"issues/{tracker_number}")
    errors = issue_lifecycle.validate_pr_work_item_readback(
        roadmap, pr, issue, package, tracker
    )
    _require(not errors, "fresh GitHub work-item relation failed: " + "; ".join(errors))
    _require(
        pr.get("number") == number
        and pr.get("merged_at")
        and pr.get("merge_commit_sha") == snapshot["merge_commit_sha"]
        and isinstance(pr.get("head"), dict)
        and pr["head"].get("sha") == snapshot["head_sha"]
        and isinstance(pr.get("base"), dict)
        and pr["base"].get("sha") == snapshot["base_sha"],
        "fresh GitHub PR differs from verified merge snapshot",
    )
    marker = issue_lifecycle.parse_pr_work_item_marker(pr.get("body"))
    _require(
        marker["work_item_issue"] == issue_number
        and marker["tracker_issue"] == tracker_number,
        "fresh GitHub PR marker changed work-item relation",
    )
    projected_issue = {
        "number": issue_number,
        "category": "work-item",
        "milestone": package["milestone"],
        "tracker_issue": tracker_number,
        "work_package_id": package["id"],
        "state": issue["state"],
    }
    projected_tracker = {
        "number": tracker_number,
        "category": "milestone-tracker",
        "milestone": package["milestone"],
        "state": tracker["state"],
    }
    projected_pr = {
        "number": number,
        "work_item_issue": issue_number,
        "state": "MERGED",
        "base_sha": snapshot["base_sha"],
        "head_sha": snapshot["head_sha"],
        "merge_sha": snapshot["merge_commit_sha"],
    }
    return pr, issue, projected_issue, projected_tracker, projected_pr


def _complete_work_item(
    root: Path,
    gh: str,
    repository: str,
    pr_snapshot: Mapping[str, Any],
    post_merge_proof: Mapping[str, Any],
    code_review: Mapping[str, Any],
    security_review: Mapping[str, Any],
    *,
    runtime: Mapping[str, Any] | None = None,
    recovery: Mapping[str, Any] | None = None,
    close_issue: bool = True,
    dependencies_verified: bool = False,
) -> dict[str, Any]:
    """Close one issue after independent exact-head proofs and GitHub readback.

    The supplied proof and reviews must be authority-bearing, not generic PASS
    records. An attempted PATCH with uncertain readback returns UNKNOWN.
    """
    root = Path(root)
    attempted = False
    performed = False
    pr_number = pr_snapshot.get("number") if isinstance(pr_snapshot, Mapping) else None
    issue_number: int | None = None
    projection: dict[str, Any] | None = None
    try:
        _require(root.is_dir(), "repository root is unavailable")
        _require(isinstance(gh, str) and bool(gh), "GitHub CLI is unavailable")
        _require(
            isinstance(repository, str)
            and issue_lifecycle.REPOSITORY_RE.fullmatch(repository) is not None,
            "GitHub repository identity is invalid",
        )
        _require(isinstance(pr_snapshot, Mapping), "GitHub PR snapshot is missing")
        issue_lifecycle.load_policy(root)
        proof = _signed_post_merge(root, pr_snapshot, post_merge_proof)
        head = proof["head_sha"]
        base = proof["base_sha"]
        merge = proof["merge_sha"]
        witness = proof["qualification_witness"]
        snapshot = issue_lifecycle.read_qualified_head_snapshot(root, head)
        _require(
            snapshot.get("head_sha") == head
            and snapshot.get("tree_sha") == proof.get("head_tree_sha"),
            "qualified Git HEAD tree differs from signed post-merge proof",
        )
        pr = _github_json(root, gh, repository, f"pulls/{pr_number}")
        marker = issue_lifecycle.parse_pr_work_item_marker(pr.get("body"))
        relative = marker["work_package_path"]
        _require(
            relative in snapshot.get("paths", []),
            "canonical work package is absent from qualified HEAD",
        )
        package = _git_show_package(root, head, relative)
        _require(
            package.get("work_item_issue") == marker["work_item_issue"]
            and package.get("tracker_issue") == marker["tracker_issue"]
            and package.get("milestone") == marker["milestone"]
            and relative
            == (
                f"config/work-packages/{package.get('milestone')}/"
                f"{package.get('id')}.yaml"
            ),
            "qualified work package differs from PR primary work-item marker",
        )
        issue_number = package["work_item_issue"]
        roadmap_path = root / "config/contracts/roadmap-policy.yaml"
        _require(not roadmap_path.is_symlink(), "canonical roadmap policy is a symlink")
        roadmap = work_package._read_yaml(roadmap_path)
        qualification = post_merge_verify.load_historical_qualification(
            root,
            base_sha=base,
            head_sha=head,
            head_tree_sha=proof["head_tree_sha"],
            merge_sha=merge,
            qualification_identity=proof["qualification_identity"],
            evidence_sha256=witness["evidence_sha256"],
            manifest_sha256=witness["manifest_sha256"],
        )
        changed_paths = qualification.get("changed_paths")
        _require(
            isinstance(changed_paths, list),
            "historical qualification changed paths are missing",
        )
        package_validation = work_package.work_package_status(
            package,
            root=root,
            changed_paths=changed_paths,
            expected_issue=issue_number,
            expected_milestone=package["milestone"],
        )
        _require(
            package_validation.get("status") == "VALID"
            and package_validation.get("scope_status") == "VALID",
            "qualified work package declaration or scope is invalid",
        )
        acceptance = issue_lifecycle.derive_work_package_acceptance(
            package, qualification, snapshot
        )
        _require(
            acceptance.get("status") == "PASS",
            "qualified work package acceptance is not PASS",
        )
        try:
            bundle = evidence_bundle.verify_bundle(
                root,
                head,
                expected_identity={
                    "base_sha": base,
                    "head_sha": head,
                    "tree_sha": proof["head_tree_sha"],
                    "qualification_identity": proof["qualification_identity"],
                },
            )
        except evidence_bundle.EvidenceBundleError as exc:
            raise IssueCompletionError(f"exact evidence bundle invalid: {exc}") from exc
        _require(
            bundle.get("status") == "PASS"
            and bundle.get("authority") == "bundle-integrity-only"
            and bundle.get("manifest_digest") == witness["manifest_sha256"],
            "exact evidence bundle differs from signed witness",
        )
        bundle_projection = {
            **bundle,
            "head_sha": head,
        }
        code = _review(code_review, "code", head)
        security = _review(security_review, "security", head)
        execution = package.get("execution")
        _require(
            isinstance(execution, Mapping),
            "work package execution declaration is missing",
        )
        _require(
            runtime is None and recovery is None,
            "caller-supplied runtime/recovery PASS has no producer authority",
        )
        preflight_projection = _historical_preflight(
            root, package, proof, bundle["manifest_digest"], pr_snapshot
        )
        runtime_projection = _historical_runtime(
            root, package, proof, bundle["manifest_digest"]
        )
        # This projection exists only after every registered producer verifies
        # capture, restore and readback against the signed historical bundle.
        recovery_projection = (
            runtime_projection if execution["recovery_required"] is True else None
        )
        if not dependencies_verified:
            dependency_result = verify_dependencies(root, gh, repository, package)
            _require(
                dependency_result["status"] == "PASS",
                "work-package dependencies are incomplete: "
                + "; ".join(dependency_result["errors"]),
            )
        _pr, raw_issue, issue, tracker, projected_pr = _relation(
            root, gh, repository, pr_snapshot, roadmap, package
        )
        projection = issue_lifecycle.project_work_item(
            roadmap,
            tracker,
            issue,
            package,
            projected_pr,
            work_package_validation=package_validation,
            qualification=qualification,
            preflight=preflight_projection,
            code_review=code,
            security_review=security,
            acceptance=acceptance,
            evidence_bundle=bundle_projection,
            runtime=runtime_projection,
            recovery=recovery_projection,
            post_merge=proof,
        )
        required = "CLOSED" if raw_issue["state"] == "closed" else "VERIFIED"
        _require(
            projection.get("status") == required
            and all(
                value == "PASS"
                for value in projection.get("proofs", {}).values()
                if value != "NOT_REQUIRED"
            ),
            f"work-item projection is not {required}",
        )
        if raw_issue["state"] == "closed":
            return {
                "status": "CLOSED",
                "pr": pr_number,
                "issue": issue_number,
                "head_sha": head,
                "merge_sha": merge,
                "mutation_attempted": False,
                "mutation_performed": False,
                "projection": projection,
                "errors": [],
            }
        _require(
            close_issue, "dependency issue is not already CLOSED with verified proof"
        )
        attempted = True
        patched = _github_json(
            root, gh, repository, f"issues/{issue_number}", close=True
        )
        _require(
            patched.get("number") == issue_number and patched.get("state") == "closed",
            "GitHub issue PATCH did not confirm exact closure",
        )
        performed = True
        _pr, readback, issue, tracker, projected_pr = _relation(
            root, gh, repository, pr_snapshot, roadmap, package
        )
        _require(
            readback.get("state") == "closed"
            and readback.get("body") == raw_issue.get("body"),
            "GitHub issue closure readback differs from exact work item",
        )
        projection = issue_lifecycle.project_work_item(
            roadmap,
            tracker,
            issue,
            package,
            projected_pr,
            work_package_validation=package_validation,
            qualification=qualification,
            preflight=preflight_projection,
            code_review=code,
            security_review=security,
            acceptance=acceptance,
            evidence_bundle=bundle_projection,
            runtime=runtime_projection,
            recovery=recovery_projection,
            post_merge=proof,
        )
        _require(
            projection.get("status") == "CLOSED",
            "closed issue lacks verified readback projection",
        )
        return {
            "status": "CLOSED",
            "pr": pr_number,
            "issue": issue_number,
            "head_sha": head,
            "merge_sha": merge,
            "mutation_attempted": True,
            "mutation_performed": True,
            "projection": projection,
            "errors": [],
        }
    except (
        IssueCompletionError,
        issue_lifecycle.IssueLifecycleError,
        work_package.WorkPackageError,
        post_merge_verify.PostMergeError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
        yaml.YAMLError,
    ) as exc:
        return {
            "status": "UNKNOWN" if attempted else "BLOCKED",
            "pr": pr_number,
            "issue": issue_number,
            "mutation_attempted": attempted,
            "mutation_performed": performed,
            "projection": projection,
            "errors": [str(exc)],
        }


def _historical_preflight(
    root: Path,
    package: Mapping[str, Any],
    proof: Mapping[str, Any],
    manifest_digest: str,
    pr_snapshot: Mapping[str, Any],
) -> dict[str, Any] | None:
    execution = package["execution"]
    if execution.get("preflight_required") is False:
        return None
    _require(
        execution.get("preflight_required") is True,
        "preflight requirement is not a boolean",
    )
    head = proof["head_sha"]
    path = evidence_bundle._safe_file(root, f".context/evidence/{head}/manifest.json")
    encoded = post_merge_verify._record_bytes(path, label="historical preflight manifest")
    _require(
        evidence_bundle.digest_bytes(encoded) == manifest_digest,
        "historical preflight bundle manifest changed",
    )
    manifest = json.loads(encoded, object_pairs_hook=evidence_bundle._unique_object)
    _require(
        isinstance(manifest, dict)
        and manifest.get("base_sha") == proof["base_sha"]
        and manifest.get("head_sha") == head
        and manifest.get("tree_sha") == proof["head_tree_sha"],
        "historical preflight bundle identity differs",
    )
    entries = manifest.get("gate_evidence")
    _require(isinstance(entries, list), "bundle gate evidence inventory is missing")
    relative = f".context/evidence/preflight/{head}.json"
    references = [
        entry for entry in entries
        if isinstance(entry, dict) and entry.get("path") == relative
    ]
    _require(
        len(references) == 1 and set(references[0]) == {"path", "sha256"},
        "required preflight proof is absent or ambiguous in exact bundle",
    )
    digest = references[0]["sha256"]
    _require(
        isinstance(digest, str) and _DIGEST.fullmatch(digest),
        "required preflight proof digest is invalid",
    )
    package_path = f"config/work-packages/{package['milestone']}/{package['id']}.yaml"
    package_digest = evidence_bundle.digest_bytes(
        _git_package_bytes(root, head, package_path)
    )
    merge_epoch = int(post_merge_verify._git(
        root, "show", "-s", "--format=%ct", proof["merge_sha"]
    ))
    verdict = delivery_preflight.verify_historical_preflight(
        root,
        proof_path=relative,
        expected_sha256=digest,
        expected_head_sha=head,
        expected_head_tree_sha=proof["head_tree_sha"],
        expected_base_sha=proof["base_sha"],
        expected_branch=pr_snapshot.get("head_branch"),
        expected_package_id=package["id"],
        expected_package_digest=package_digest,
        expected_issue=package["work_item_issue"],
        expected_milestone=package["milestone"],
        expected_capabilities=execution.get("required_capabilities", []),
        expected_capability_parameters=execution.get("capability_parameters", {}),
        merge_epoch=merge_epoch,
    )
    _require(
        isinstance(verdict, dict)
        and verdict.get("work_package_digest") == package_digest
        and verdict.get("evidence_digest") == digest
        and issue_lifecycle.preflight_proof_state(
            verdict,
            {"state": "MERGED", "head_sha": head, "base_sha": proof["base_sha"]},
            package,
            {"head_tree_sha": proof["head_tree_sha"]},
        ) == "PASS",
        "historical preflight producer authority failed",
    )
    _require(
        post_merge_verify._record_bytes(path, label="historical preflight manifest") == encoded,
        "preflight bundle changed during validation",
    )
    return verdict


def _historical_runtime(
    root: Path,
    package: Mapping[str, Any],
    proof: Mapping[str, Any],
    manifest_digest: str,
) -> dict[str, Any] | None:
    execution = package["execution"]
    recovery_required = execution.get("recovery_required")
    _require(type(recovery_required) is bool, "recovery requirement is not a boolean")
    if execution.get("runtime_required") is False:
        _require(not recovery_required, "historical recovery producer requires runtime evidence")
        return None
    _require(
        execution.get("runtime_required") is True,
        "runtime requirement is not a boolean",
    )
    head = proof["head_sha"]
    path = evidence_bundle._safe_file(root, f".context/evidence/{head}/manifest.json")
    encoded = path.read_bytes()
    _require(
        evidence_bundle.digest_bytes(encoded) == manifest_digest,
        "historical runtime bundle manifest changed",
    )
    manifest = json.loads(encoded, object_pairs_hook=evidence_bundle._unique_object)
    _require(
        manifest.get("base_sha") == proof["base_sha"]
        and manifest.get("head_sha") == head
        and manifest.get("tree_sha") == proof["head_tree_sha"],
        "historical runtime bundle identity differs",
    )
    entries = manifest.get("runtime_evidence")
    _require(isinstance(entries, list), "bundle runtime evidence inventory is missing")
    by_path: dict[str, str] = {}
    for entry in entries:
        _require(
            isinstance(entry, dict) and set(entry) == {"path", "sha256"},
            "bundle runtime evidence reference is invalid",
        )
        relative, digest = entry["path"], entry["sha256"]
        _require(
            isinstance(relative, str)
            and relative not in by_path
            and isinstance(digest, str)
            and _DIGEST.fullmatch(digest),
            "bundle runtime evidence reference is ambiguous or invalid",
        )
        by_path[relative] = digest
    required = package["acceptance"]["runtime_evidence"]
    _require(
        isinstance(required, list) and bool(required),
        "required historical runtime evidence is missing",
    )
    verified: list[dict[str, Any]] = []
    digests: list[str] = []
    for relative in required:
        if recovery_required:
            _require(
                relative == runtime_authority._NATIVE_RECOVERY_PATH,
                "historical recovery producer path is not registered",
            )
            expected_producer = runtime_authority._NATIVE_PRODUCER
            expected_type = "native-host-recovery"
        else:
            _require(
                relative == runtime_authority._LAB_PATH,
                "historical LAB runtime producer path is not registered",
            )
            expected_producer = "scripts/m25_runtime_evidence.py:validate"
            expected_type = "lab-readiness"
        _require(
            relative in by_path, "required runtime proof is absent from exact bundle"
        )
        digest = by_path[relative]
        verdict = runtime_authority.verify_historical_runtime_proof(
            root,
            package["milestone"],
            head,
            relative,
            base_sha=proof["base_sha"],
            head_tree_sha=proof["head_tree_sha"],
            evidence_digest=digest,
            recovery_required=recovery_required,
        )
        _require(isinstance(verdict, dict), "historical runtime producer returned no verdict")
        if recovery_required:
            recovery = verdict.get("recovery")
            identity = verdict.get("runtime_identity")
            _require(
                verdict.get("environment") == "host"
                and isinstance(identity, dict)
                and set(identity) == {"kind", "id"}
                and identity.get("kind") == "virtualbox-vm"
                and isinstance(identity.get("id"), str)
                and re.fullmatch(
                    r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", identity["id"]
                ) is not None
                and isinstance(recovery, dict)
                and set(recovery) == set(runtime_authority._RECOVERY_PHASES)
                and all(recovery[phase] == "PASS" for phase in runtime_authority._RECOVERY_PHASES),
                "historical recovery producer did not verify host capture, restore and readback",
            )
        else:
            _require(
                verdict.get("recovery") == "NOT_REQUIRED",
                "historical LAB producer cannot assert recovery authority",
            )
        _require(
            verdict.get("status") == "PASS"
            and verdict.get("producer") == expected_producer
            and verdict.get("proof_type") == expected_type
            and verdict.get("head_sha") == head
            and verdict.get("head_tree_sha") == proof["head_tree_sha"]
            and verdict.get("evidence_path") == relative
            and verdict.get("evidence_digest") == digest,
            "historical runtime producer authority failed: "
            + str(verdict.get("reason", "")),
        )
        verified.append(verdict)
        digests.append(digest)
    expected_identity = evidence_bundle.digest_bytes(
        evidence_bundle.canonical_bytes({"runtime_evidence": digests})
    )
    _require(
        manifest.get("runtime_identity") == expected_identity,
        "historical runtime identity differs from exact bundle",
    )
    _require(path.read_bytes() == encoded, "runtime bundle changed during validation")
    return {
        "status": "PASS",
        "head_sha": head,
        "head_tree_sha": proof["head_tree_sha"],
        "runtime_identity": expected_identity,
        "producer_proofs": verified,
    }


def _dependency_snapshot(pr: Mapping[str, Any], repository: str) -> dict[str, Any]:
    _require(
        pr.get("state") == "closed"
        and bool(pr.get("merged_at"))
        and pr.get("draft") is False
        and isinstance(pr.get("base"), dict)
        and isinstance(pr.get("head"), dict)
        and pr["base"].get("ref") == "main"
        and isinstance(pr["base"].get("repo"), dict)
        and isinstance(pr["head"].get("repo"), dict)
        and pr["base"]["repo"].get("full_name") == repository
        and pr["head"]["repo"].get("full_name") == repository,
        "dependency PR is not a canonical merged PR",
    )
    return {
        "number": pr["number"],
        "state": "MERGED",
        "merged": True,
        "merged_at": pr["merged_at"],
        "draft": False,
        "base": "main",
        "base_sha": pr["base"]["sha"],
        "head_sha": pr["head"]["sha"],
        "head_branch": pr["head"]["ref"],
        "merge_commit_sha": pr["merge_commit_sha"],
    }


def _dependency_candidate(
    root: Path, gh: str, repository: str, package: Mapping[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Use local files only to discover candidates, then verify fresh authorities."""
    issue = _github_json(root, gh, repository, f"issues/{package['work_item_issue']}")
    _require(
        issue.get("number") == package["work_item_issue"]
        and issue.get("state") == "closed",
        "dependency issue is not CLOSED",
    )
    directory = root / post_merge_verify.OUTPUT_RELATIVE
    for ancestor in (directory, *directory.parents):
        _require(not ancestor.is_symlink(), "dependency proof directory is a symlink")
        if ancestor == root:
            break
    paths = sorted(directory.glob("*.json"))
    _require(len(paths) <= 256, "dependency proof inventory exceeds bounded size")
    candidates: list[tuple[dict[str, Any], dict[str, Any]]] = []
    seen: set[int] = set()
    canonical_path = f"config/work-packages/{package['milestone']}/{package['id']}.yaml"
    for path in paths:
        hint = post_merge_verify._strict_json(path, label="dependency proof candidate")
        number = hint.get("pr")
        if type(number) is not int or number <= 0 or number in seen:
            continue
        seen.add(number)
        pr = _github_json(root, gh, repository, f"pulls/{number}")
        _require(pr.get("number") == number, "dependency PR readback number differs")
        try:
            marker = issue_lifecycle.parse_pr_work_item_marker(pr.get("body"))
        except issue_lifecycle.IssueLifecycleError:
            continue
        if marker.get("work_item_issue") != package["work_item_issue"]:
            continue
        _require(
            marker.get("work_package_path") == canonical_path,
            "dependency PR points at another canonical package",
        )
        snapshot = _dependency_snapshot(pr, repository)
        _require(
            _git_show_package(root, snapshot["head_sha"], canonical_path)
            == dict(package),
            "dependency package differs from its qualified declaration",
        )
        proof = post_merge_verify.read_post_merge_proof(
            root,
            snapshot["merge_commit_sha"],
            expected_pr=number,
            expected_head=snapshot["head_sha"],
            snapshot=snapshot,
        )
        candidates.append((snapshot, proof))
    _require(
        len(candidates) == 1,
        "dependency has no unique signed verified closure candidate",
    )
    return candidates[0]


def _verify_dependency(
    root: Path, gh: str, repository: str, package: Mapping[str, Any]
) -> dict[str, Any]:
    try:
        from scripts import chatgpt_review_dispatcher
        from scripts.exact_pr_binding import ExactPRBinding
    except ModuleNotFoundError:
        import chatgpt_review_dispatcher
        from exact_pr_binding import ExactPRBinding

    snapshot, proof = _dependency_candidate(root, gh, repository, package)
    binding = ExactPRBinding(
        repository,
        snapshot["number"],
        snapshot["base"],
        snapshot["base_sha"],
        snapshot["head_branch"],
        snapshot["head_sha"],
    )
    reviews: dict[str, dict[str, Any]] = {}
    raw_reviews: dict[str, dict[str, Any]] = {}
    for kind in ("code", "security"):
        raw = chatgpt_review_dispatcher.github_owner_marker_lookup(binding, kind, gh=gh)
        _require(isinstance(raw, dict), "dependency exact owner review is missing")
        raw_reviews[kind] = raw
        reviews[kind] = _review(
            {
                **{
                    key: raw.get(key)
                    for key in (
                        "provider",
                        "kind",
                        "head_sha",
                        "status",
                        "blocking_findings",
                        "comment_id",
                    )
                },
                "source": "github-pr-comment",
            },
            kind,
            snapshot["head_sha"],
        )
    _require(
        (raw_reviews["security"]["created_at"], raw_reviews["security"]["comment_id"])
        > (raw_reviews["code"]["created_at"], raw_reviews["code"]["comment_id"]),
        "dependency SECURITY review predates CODE",
    )
    result = _complete_work_item(
        root,
        gh,
        repository,
        snapshot,
        proof,
        reviews["code"],
        reviews["security"],
        close_issue=False,
        dependencies_verified=True,
    )
    _require(
        result.get("status") == "CLOSED"
        and result.get("mutation_attempted") is False
        and result.get("issue") == package["work_item_issue"],
        "dependency closure has no verified technical proof: "
        + "; ".join(result.get("errors", [])),
    )
    return {
        "id": package["id"],
        "milestone": package["milestone"],
        "work_item_issue": package["work_item_issue"],
        "status": "CLOSED",
        "head_sha": result["head_sha"],
        "merge_sha": result["merge_sha"],
    }


def verify_dependencies(
    root: Path, gh: str, repository: str, package: Mapping[str, Any]
) -> dict[str, Any]:
    """Verify every canonical dependency once, with fresh read-only closure proofs."""
    verified: list[dict[str, Any]] = []
    try:
        ordered = work_package.resolve_dependencies(package, root=root)
        for dependency in ordered:
            verified.append(_verify_dependency(Path(root), gh, repository, dependency))
        return {"status": "PASS", "dependencies": verified, "errors": []}
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as exc:
        return {"status": "BLOCKED", "dependencies": verified, "errors": [str(exc)]}


def complete_work_item(
    root: Path,
    gh: str,
    repository: str,
    pr_snapshot: Mapping[str, Any],
    post_merge_proof: Mapping[str, Any],
    code_review: Mapping[str, Any],
    security_review: Mapping[str, Any],
    *,
    runtime: Mapping[str, Any] | None = None,
    recovery: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return _complete_work_item(
        root,
        gh,
        repository,
        pr_snapshot,
        post_merge_proof,
        code_review,
        security_review,
        runtime=runtime,
        recovery=recovery,
    )
