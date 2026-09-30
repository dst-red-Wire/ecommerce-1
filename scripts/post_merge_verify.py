#!/usr/bin/env python3
"""Verify a merged PR against Git and write an immutable post-merge proof."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping

import yaml


try:
    from scripts import evidence_bundle
except ModuleNotFoundError:
    import evidence_bundle


SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
BRANCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]*\Z")
OUTPUT_RELATIVE = Path(".context/evidence/post-merge")


class PostMergeError(RuntimeError):
    """A required post-merge fact could not be established."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise PostMergeError(message)


def _command(root: Path, command: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command, cwd=root, text=True, capture_output=True, check=False, timeout=60
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PostMergeError(f"command unavailable: {' '.join(command[:2])}: {exc}") from exc


def _git(root: Path, *arguments: str) -> str:
    result = _command(root, ["git", *arguments])
    if result.returncode:
        detail = (result.stderr or result.stdout or "").strip()
        raise PostMergeError(f"git {' '.join(arguments[:2])} failed: {detail}")
    return result.stdout.strip()


def _sha(value: object, name: str) -> str:
    _require(isinstance(value, str) and SHA.fullmatch(value) is not None, f"{name} must be an exact SHA")
    return value


def _branch(value: object) -> str:
    _require(
        isinstance(value, str)
        and BRANCH.fullmatch(value) is not None
        and ".." not in value
        and value not in ("main", "master"),
        "GitHub head branch is invalid",
    )
    return value


def _remote_sha(root: Path, ref: str) -> str | None:
    result = _command(root, ["git", "ls-remote", "--exit-code", "--heads", "origin", ref])
    if result.returncode == 2:
        return None
    if result.returncode:
        raise PostMergeError(f"remote branch probe failed for {ref}")
    lines = result.stdout.strip().splitlines()
    _require(len(lines) == 1, f"remote branch probe ambiguous for {ref}")
    fields = lines[0].split()
    _require(len(fields) == 2 and fields[1] == ref, f"remote branch probe malformed for {ref}")
    return _sha(fields[0], f"remote {ref}")


def _cleanup_policy(root: Path) -> tuple[str, str]:
    path = root / "config/contracts/review-policy.yaml"
    try:
        policy = yaml.safe_load(path.read_text(encoding="utf-8"))
        delivery = policy["repository_delivery"]
        cleanup = delivery["cleanup"]
        post_merge = delivery["post_merge"]
        remote = cleanup["remote_branch"]
        local = cleanup["local_branch"]
        roadmap = post_merge["roadmap"]
    except (OSError, UnicodeError, yaml.YAMLError, KeyError, TypeError) as exc:
        raise PostMergeError("review policy cleanup/post-merge rules are unavailable") from exc
    _require(remote in ("delete", "preserve") and local in ("delete", "preserve"),
             "review policy branch cleanup rules are invalid")
    _require(roadmap.get("check") == "required", "review policy roadmap check is not required")
    return remote, local


def _qualified_binding(qualification: Mapping[str, Any], base: str, head: str, root: Path) -> dict:
    _require(
        qualification.get("status") == "PASS"
        and qualification.get("evidence_kind") == "exact_commit"
        and qualification.get("exact_commit_evidence") is True
        and type(qualification.get("schema_version")) is int
        and qualification["schema_version"] >= 5,
        "validated exact-commit qualification is required",
    )
    _require(
        qualification.get("base_sha") == base and qualification.get("head_sha") == head,
        "qualification base/head does not match merged PR",
    )
    head_tree = _sha(qualification.get("head_tree_sha"), "qualified head tree")
    _require(
        head_tree == _git(root, "rev-parse", f"{head}^{{tree}}"),
        "qualified head tree differs from Git",
    )
    identity = qualification.get("qualification_identity")
    _require(
        isinstance(identity, str) and DIGEST.fullmatch(identity) is not None,
        "qualification identity is missing",
    )
    return {"head_tree_sha": head_tree, "qualification_identity": identity}


def _strict_json(path: Path, *, label: str = "historical qualification evidence") -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise PostMergeError(f"duplicate {label} JSON key: {key}")
            result[key] = value
        return result

    current = path.parent
    while current != current.parent:
        _require(not current.is_symlink(), f"{label} path contains a symlink")
        current = current.parent
    _require(path.is_file() and not path.is_symlink(), f"{label} is missing")
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PostMergeError(f"{label} is not valid JSON") from exc
    _require(isinstance(value, dict), f"{label} must be an object")
    return value


def _historical_contract(root: Path, head: str, relative: str) -> dict[str, Any]:
    text = _git(root, "show", f"{head}:{relative}")
    try:
        value = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PostMergeError(f"historical contract is invalid: {relative}") from exc
    _require(isinstance(value, dict), f"historical contract is missing: {relative}")
    return value



def _automation_signing_authority(root: Path, revision: str) -> dict[str, Any]:
    lock = _historical_contract(root, revision, "architecture.lock.yaml")
    try:
        policy = lock["repository_governance"]["automation_signing"]
        key = policy["automation_key"]
        active = key["fingerprint"]
        previous = key.get("previous_fingerprint")
    except (KeyError, TypeError) as exc:
        raise PostMergeError("trusted automation signing authority is missing") from exc
    _require(
        policy.get("version") == 1
        and policy.get("kind") == "AutomationSigningPolicy"
        and policy.get("status") == "enforced"
        and policy.get("repository") == "ecommerce-1"
        and key.get("signing_required") is True
        and key.get("algorithm") == "ed25519"
        and isinstance(active, str)
        and re.fullmatch(r"[A-F0-9]{40}", active) is not None,
        "trusted automation signing authority is invalid",
    )
    if previous is not None:
        _require(
            isinstance(previous, str)
            and re.fullmatch(r"[A-F0-9]{40}", previous) is not None
            and previous != active,
            "trusted previous automation signer is invalid",
        )
    return policy


def _authorized_proof_signer(root: Path, base: str, main: str, signer: str) -> None:
    base_policy = _automation_signing_authority(root, base)
    current = _automation_signing_authority(root, main)
    _require(
        signer == base_policy["automation_key"]["fingerprint"],
        "proof signer differs from historical signing authority",
    )
    active = current["automation_key"]["fingerprint"]
    previous = current["automation_key"].get("previous_fingerprint")
    rotation = current.get("rotation", {})
    _require(
        signer == active
        or (
            signer == previous
            and current["automation_key"].get("rotation_status") == "active_overlap"
            and isinstance(rotation, dict)
            and rotation.get("overlapping_keys_allowed") is True
        ),
        "proof signer is not authorized by current signing authority",
    )


def _detached_sign(root: Path, content_path: Path, signature_path: Path, signer: str) -> None:
    configured = _git(root, "config", "--local", "--get", "user.signingkey").upper()
    _require(configured == signer, "local Git signing key differs from trusted authority")
    program = _git(root, "config", "--local", "--get", "gpg.program")
    _require(program == "gpg", "local Git GPG program is not the trusted program")
    result = _command(root, [
        "gpg", "--batch", "--yes", "--local-user", signer,
        "--output", str(signature_path), "--detach-sign", str(content_path),
    ])
    _require(result.returncode == 0 and signature_path.is_file(),
             "trusted detached proof signing failed")


def _verify_detached_signature(
    root: Path, content_path: Path, signature_path: Path, base: str, main: str
) -> str:
    _require(
        signature_path.is_file() and not signature_path.is_symlink(),
        "detached post-merge proof signature is missing",
    )
    result = _command(root, [
        "gpg", "--batch", "--status-fd", "1", "--verify",
        str(signature_path), str(content_path),
    ])
    _require(result.returncode == 0, "detached post-merge proof signature did not verify")
    valid = re.findall(
        r"^\[GNUPG:\] VALIDSIG ([A-F0-9]{40})\b",
        result.stdout, flags=re.MULTILINE | re.IGNORECASE,
    )
    _require(len(valid) == 1, "detached post-merge proof has no unique valid signer")
    signer = valid[0].upper()
    _authorized_proof_signer(root, base, main, signer)
    return signer


def _qualification_witness(
    root: Path, *, base: str, head: str, tree: str, merge: str, identity: str
) -> dict[str, str]:
    path = root / ".context" / "evidence" / f"{head}.json"
    _strict_json(path)
    evidence_digest = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    try:
        bundle = evidence_bundle.verify_bundle(
            root, head,
            expected_identity={
                "base_sha": base,
                "head_sha": head,
                "tree_sha": tree,
                "qualification_identity": identity,
            },
        )
    except evidence_bundle.EvidenceBundleError as exc:
        raise PostMergeError(f"post-merge qualification bundle invalid: {exc}") from exc
    _require(
        bundle.get("status") == "PASS"
        and bundle.get("authority") == "bundle-integrity-only",
        "post-merge qualification bundle has no integrity proof",
    )
    manifest_digest = bundle.get("manifest_digest")
    _require(
        isinstance(manifest_digest, str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", manifest_digest) is not None,
        "post-merge qualification bundle digest is invalid",
    )
    load_historical_qualification(
        root, base_sha=base, head_sha=head, head_tree_sha=tree,
        merge_sha=merge, qualification_identity=identity,
        evidence_sha256=evidence_digest, manifest_sha256=manifest_digest,
    )
    return {
        "evidence_sha256": evidence_digest,
        "manifest_sha256": manifest_digest,
    }

def load_historical_qualification(
    root: Path,
    *,
    base_sha: str,
    head_sha: str,
    head_tree_sha: str,
    merge_sha: str,
    qualification_identity: str,
    evidence_sha256: str,
    manifest_sha256: str,
) -> dict[str, Any]:
    """Recheck retained exact evidence using a witness captured before merge.

    The witness digest and qualification identity must come from an independent
    trusted pre-merge validation. Local .context files alone cannot attest that
    gates were run.
    """
    root = Path(root)
    base = _sha(base_sha, "historical base")
    head = _sha(head_sha, "historical head")
    tree = _sha(head_tree_sha, "historical head tree")
    merge = _sha(merge_sha, "historical merge")
    _require(
        isinstance(qualification_identity, str)
        and DIGEST.fullmatch(qualification_identity) is not None,
        "trusted qualification identity is required",
    )
    _require(
        isinstance(evidence_sha256, str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", evidence_sha256) is not None,
        "trusted qualification evidence digest is required",
    )
    _require(
        isinstance(manifest_sha256, str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", manifest_sha256) is not None,
        "trusted evidence bundle digest is required",
    )
    _require(_git(root, "rev-parse", f"{head}^{{tree}}") == tree,
             "historical head tree differs from Git")
    _require(
        _git(root, "rev-list", "--parents", "-n", "1", merge).split()
        == [merge, base, head],
        "historical merge parents differ from exact base/head",
    )
    path = root / ".context" / "evidence" / f"{head}.json"
    payload = _strict_json(path)
    actual_digest = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    _require(actual_digest == evidence_sha256,
             "historical qualification bytes differ from trusted witness")
    try:
        bundle = evidence_bundle.verify_bundle(
            root,
            head,
            expected_identity={
                "base_sha": base,
                "head_sha": head,
                "tree_sha": tree,
                "qualification_identity": qualification_identity,
            },
        )
    except evidence_bundle.EvidenceBundleError as exc:
        raise PostMergeError(f"historical evidence bundle invalid: {exc}") from exc
    _require(bundle.get("status") == "PASS"
             and bundle.get("authority") == "bundle-integrity-only"
             and bundle.get("manifest_digest") == manifest_sha256,
             "historical evidence bundle integrity is unverified")

    ci = _historical_contract(root, head, "config/contracts/ci-evidence.yaml")
    policy = _historical_contract(
        root, head, "config/contracts/qualification-execution-policy.yaml"
    )
    evidence_rules = ci.get("evidence")
    _require(
        isinstance(evidence_rules, dict)
        and evidence_rules.get("schema_version") == 5
        and evidence_rules.get("exact_commit_required") is True
        and evidence_rules.get("pass_required_for_reuse") is True
        and evidence_rules.get("qualification_identity_required") is True
        and evidence_rules.get("commit_tree_required") is True,
        "historical CI evidence authority is invalid",
    )
    _require(
        type(payload.get("schema_version")) is int
        and payload["schema_version"] == evidence_rules["schema_version"]
        and payload.get("status") == "PASS"
        and payload.get("evidence_kind") == "exact_commit"
        and payload.get("exact_commit_evidence") is True
        and payload.get("base_sha") == base
        and payload.get("head_sha") == head
        and payload.get("head_tree_sha") == tree
        and payload.get("qualification_identity") == qualification_identity,
        "historical qualification lacks exact authoritative binding",
    )
    verification = payload.get("verification")
    profiles = policy.get("qualification_profiles")
    profile = (
        profiles.get(verification.get("execution_profile"))
        if isinstance(profiles, dict) and isinstance(verification, dict)
        else None
    )
    _require(
        isinstance(profile, dict)
        and profile.get("merge_authoritative") is True
        and verification.get("runtime_scope") == [],
        "historical qualification did not use a merge-authoritative profile",
    )
    gate_rules = ci.get("gate_records")
    required_fields = gate_rules.get("required") if isinstance(gate_rules, dict) else None
    execution_values = gate_rules.get("execution_values") if isinstance(gate_rules, dict) else None
    registry = policy.get("gates")
    _require(
        isinstance(required_fields, list)
        and all(isinstance(field, str) for field in required_fields)
        and isinstance(execution_values, list)
        and isinstance(registry, dict),
        "historical qualification gate authority is invalid",
    )
    records = payload.get("gates")
    _require(isinstance(records, list) and bool(records),
             "historical qualification has no gate records")
    names: set[str] = set()
    for row in records:
        _require(isinstance(row, dict) and set(required_fields) <= set(row),
                 "historical qualification gate record is incomplete")
        name = row.get("gate")
        _require(isinstance(name, str) and name not in names,
                 "historical qualification has duplicate or invalid gates")
        names.add(name)
        registered = next(
            (definition for pattern, definition in registry.items()
             if isinstance(pattern, str)
             and fnmatch.fnmatchcase(name, pattern)
             and isinstance(definition, dict)),
            None,
        )
        _require(registered is not None, f"historical qualification gate is unknown: {name}")
        _require(row.get("execution") in execution_values,
                 f"historical qualification gate execution invalid: {name}")
        duration = row.get("duration_seconds")
        _require(
            type(duration) in (int, float)
            and math.isfinite(duration)
            and duration >= 0,
            f"historical qualification gate duration invalid: {name}",
        )
        if registered.get("scope") == "global":
            _require(row.get("status") == "PASS",
                     f"historical global gate is not PASS: {name}")
        else:
            _require(row.get("status") in ("PASS", "SKIP"),
                     f"historical component gate is not PASS/SKIP: {name}")
        if row.get("status") == "PASS":
            _require(row.get("exit_code", 0) == 0
                     and row.get("execution") != "skipped",
                     f"historical PASS gate has invalid execution: {name}")
        else:
            _require(row.get("execution") == "skipped",
                     f"historical SKIP gate was not skipped: {name}")
    required_globals = {
        name for name, definition in registry.items()
        if isinstance(definition, dict) and definition.get("scope") == "global"
    }
    _require(required_globals <= names,
             "historical qualification is missing global gates")
    changed = sorted(set(_git(
        root, "diff", "--name-only", "--diff-filter=ACMRTUXB", base, head, "--"
    ).splitlines()))
    _require(payload.get("changed_paths") == changed,
             "historical qualification changed paths differ from Git")
    age = evidence_rules.get("maximum_local_age_seconds")
    created = payload.get("created_at_epoch")
    merge_epoch = int(_git(root, "show", "-s", "--format=%ct", merge))
    _require(
        type(age) is int and age > 0
        and type(created) in (int, float) and math.isfinite(created)
        and -2 <= merge_epoch - created <= age,
        "historical qualification was not fresh at merge",
    )
    return {
        **payload,
        "historical_verification": {
            "status": "VERIFIED",
            "evidence_sha256": actual_digest,
            "bundle_digest": bundle["manifest_digest"],
            "merge_sha": merge,
        },
    }


def verify_post_merge(
    root: Path,
    *,
    pr_number: int,
    snapshot: Mapping[str, Any],
    qualification: Mapping[str, Any],
    main_ref: str = "origin/main",
) -> dict[str, Any]:
    """Read independent GitHub and Git facts. PASS never follows PR state alone."""
    result: dict[str, Any] = {
        "schema_version": 1,
        "kind": "PostMergeVerification",
        "status": "FAIL",
        "pr": pr_number,
        "errors": [],
    }
    root = Path(root)
    try:
        _require(type(pr_number) is int and pr_number > 0, "PR number must be positive")
        _require(main_ref == "origin/main", "post-merge main ref must be origin/main")
        _require(isinstance(snapshot, Mapping), "GitHub snapshot must be a mapping")
        _require(isinstance(qualification, Mapping), "qualification must be a mapping")
        _require(
            snapshot.get("number") == pr_number
            and snapshot.get("state") == "MERGED"
            and snapshot.get("merged") is True
            and isinstance(snapshot.get("merged_at"), str)
            and bool(snapshot["merged_at"])
            and snapshot.get("draft") is False
            and snapshot.get("base") == "main",
            "GitHub snapshot does not prove exact merged PR identity",
        )
        base = _sha(snapshot.get("base_sha"), "GitHub base")
        head = _sha(snapshot.get("head_sha"), "GitHub head")
        merge = _sha(snapshot.get("merge_commit_sha"), "GitHub merge commit")
        branch = _branch(snapshot.get("head_branch"))
        _require(len({base, head, merge}) == 3, "base/head/merge commits must be distinct")
        qualified = _qualified_binding(qualification, base, head, root)

        _require(
            not _git(root, "status", "--porcelain", "--untracked-files=all"),
            "post-merge worktree is not clean",
        )
        main = _sha(_git(root, "rev-parse", main_ref), "local origin/main")
        _require(_git(root, "rev-parse", "HEAD") == main,
                 "post-merge checkout is not the current origin/main")
        _require(
            _remote_sha(root, "refs/heads/main") == main,
            "origin/main is stale relative to remote main",
        )
        parents = _git(root, "rev-list", "--parents", "-n", "1", merge).split()
        _require(parents == [merge, base, head],
                 "merge commit must have exact base and head parents")
        _require(
            _command(root, ["git", "merge-base", "--is-ancestor", merge, main_ref]).returncode == 0,
            "current main does not contain the merge commit",
        )
        _require(
            _command(root, ["git", "merge-base", "--is-ancestor", head, main_ref]).returncode == 0,
            "current main does not contain the PR head",
        )
        signature = _command(root, ["git", "verify-commit", merge])
        _require(signature.returncode == 0, "merge commit signature did not verify")
        signature_fields = _git(root, "log", "-1", "--format=%G?%n%GF", merge).splitlines()
        _require(
            len(signature_fields) == 2
            and signature_fields[0] in ("G", "U")
            and re.fullmatch(r"[0-9A-Fa-f]{40,64}", signature_fields[1]) is not None,
            "merge commit signature has no good signer fingerprint",
        )
        merged_tree = _sha(_git(root, "rev-parse", f"{merge}^{{tree}}"), "merge tree")
        recomposed = _git(root, "merge-tree", "--write-tree", base, head)
        expected_tree = _sha(recomposed.splitlines()[0] if recomposed else "", "recomputed merge tree")
        _require(merged_tree == expected_tree,
                 "merge commit tree differs from deterministic base/head merge")

        remote_rule, local_rule = _cleanup_policy(root)
        if remote_rule == "delete":
            _require(
                _remote_sha(root, f"refs/heads/{branch}") is None,
                "merged PR remote branch was not deleted",
            )
        if local_rule == "delete":
            local_branch = _command(
                root, ["git", "show-ref", "--verify", "--quiet", f"refs/heads/{branch}"]
            )
            _require(local_branch.returncode == 1,
                     "merged PR local branch was not deleted or probe failed")

        roadmap = root / "scripts/roadmap_sync.py"
        _require(roadmap.is_file() and not roadmap.is_symlink(),
                 "canonical roadmap checker is unavailable")
        roadmap_check = _command(
            root, [sys.executable, "scripts/roadmap_sync.py", "check", "--quiet"]
        )
        _require(roadmap_check.returncode == 0, "roadmap sync check did not PASS")
        _require(
            not _git(root, "status", "--porcelain", "--untracked-files=all")
            and _git(root, "rev-parse", main_ref) == main,
            "post-merge checkout changed during roadmap check",
        )
        result.update({
            "status": "PASS",
            "signature_verified": True,
            "main_contains_change": True,
            "qualified_tree_matches": True,
            "clean_worktree": True,
            "base_sha": base,
            "head_sha": head,
            "head_tree_sha": qualified["head_tree_sha"],
            "qualification_identity": qualified["qualification_identity"],
            "merge_sha": merge,
            "merge_tree_sha": merged_tree,
            "recomputed_tree_sha": expected_tree,
            "main_sha": main,
            "merge_signature": {
                "status": "VERIFIED",
                "fingerprint": signature_fields[1].lower(),
            },
            "branch_cleanup": {
                "local": "DELETED" if local_rule == "delete" else "PRESERVED_BY_POLICY",
                "remote": "DELETED" if remote_rule == "delete" else "PRESERVED_BY_POLICY",
            },
            "roadmap_sync": "PASS",
        })
    except (PostMergeError, IndexError, ValueError) as exc:
        result["errors"].append(str(exc))
    return result



def read_post_merge_proof(
    root: Path,
    merge_sha: str,
    *,
    expected_pr: int | None = None,
    expected_head: str | None = None,
    snapshot: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Revalidate a signed historical proof against fresh GitHub and Git facts.

    A local proof alone has no GitHub authority. The caller must supply a fresh,
    exact PR snapshot; the signed witness binds retained qualification bytes.
    """
    root = Path(root)
    merge = _sha(merge_sha, "post-merge proof merge")
    path = root / OUTPUT_RELATIVE / f"{merge}.json"
    payload = _strict_json(path, label="post-merge proof")
    signature = path.with_suffix(".json.sig")
    _require(
        path.read_bytes() == (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode(),
        "post-merge proof JSON is not canonical",
    )
    expected_fields = {
        "schema_version", "kind", "status", "pr", "errors", "base_sha",
        "head_sha", "head_tree_sha", "qualification_identity", "merge_sha",
        "merge_tree_sha", "recomputed_tree_sha", "main_sha", "merge_signature",
        "branch_cleanup", "roadmap_sync", "qualification_witness",
        "signature_verified", "main_contains_change", "qualified_tree_matches",
        "clean_worktree",
    }
    _require(set(payload) == expected_fields, "post-merge proof schema is invalid")
    _require(
        payload["schema_version"] == 2
        and payload["kind"] == "PostMergeVerification"
        and payload["status"] == "PASS"
        and payload["errors"] == []
        and type(payload["pr"]) is int
        and payload["pr"] > 0,
        "post-merge proof has no valid PASS record",
    )
    for name in (
        "base_sha", "head_sha", "head_tree_sha", "merge_sha", "merge_tree_sha",
        "recomputed_tree_sha", "main_sha",
    ):
        _sha(payload[name], f"post-merge proof {name}")
    _require(
        all(payload[name] is True for name in (
            "signature_verified", "main_contains_change",
            "qualified_tree_matches", "clean_worktree"
        )),
        "post-merge proof has no complete verified fact flags",
    )
    _require(payload["merge_sha"] == merge, "post-merge proof filename/merge differs")
    _require(payload["merge_tree_sha"] == payload["recomputed_tree_sha"],
             "post-merge proof tree fields differ")
    _require(
        isinstance(payload["qualification_identity"], str)
        and DIGEST.fullmatch(payload["qualification_identity"]) is not None,
        "post-merge proof qualification identity is invalid",
    )
    _require(
        isinstance(payload["merge_signature"], dict)
        and set(payload["merge_signature"]) == {"status", "fingerprint"}
        and payload["merge_signature"]["status"] == "VERIFIED"
        and isinstance(payload["merge_signature"]["fingerprint"], str)
        and re.fullmatch(r"[0-9a-f]{40,64}", payload["merge_signature"]["fingerprint"])
        is not None,
        "post-merge proof merge signature record is invalid",
    )
    _require(
        isinstance(payload["branch_cleanup"], dict)
        and set(payload["branch_cleanup"]) == {"local", "remote"}
        and all(value in ("DELETED", "PRESERVED_BY_POLICY")
                for value in payload["branch_cleanup"].values())
        and payload["roadmap_sync"] == "PASS",
        "post-merge proof cleanup or roadmap record is invalid",
    )
    witness = payload["qualification_witness"]
    _require(
        isinstance(witness, dict)
        and set(witness) == {"evidence_sha256", "manifest_sha256"}
        and all(isinstance(value, str)
                and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None
                for value in witness.values()),
        "post-merge proof qualification witness is invalid",
    )
    if expected_pr is not None:
        _require(type(expected_pr) is int and expected_pr == payload["pr"],
                 "post-merge proof PR differs from requested PR")
    if expected_head is not None:
        _require(_sha(expected_head, "expected PR head") == payload["head_sha"],
                 "post-merge proof head differs from requested head")
    _require(isinstance(snapshot, Mapping),
             "fresh external GitHub PR snapshot is required for proof recovery")
    _require(
        snapshot.get("number") == payload["pr"]
        and snapshot.get("head_sha") == payload["head_sha"]
        and snapshot.get("merge_commit_sha") == merge
        and snapshot.get("base_sha") == payload["base_sha"],
        "fresh GitHub PR identity differs from signed post-merge proof",
    )
    current_main = _sha(_git(root, "rev-parse", "origin/main"), "current origin/main")
    _verify_detached_signature(
        root, path, signature, payload["base_sha"], current_main
    )
    qualification = load_historical_qualification(
        root,
        base_sha=payload["base_sha"],
        head_sha=payload["head_sha"],
        head_tree_sha=payload["head_tree_sha"],
        merge_sha=merge,
        qualification_identity=payload["qualification_identity"],
        evidence_sha256=witness["evidence_sha256"],
        manifest_sha256=witness["manifest_sha256"],
    )
    fresh = verify_post_merge(
        root, pr_number=payload["pr"], snapshot=snapshot,
        qualification=qualification,
    )
    _require(fresh["status"] == "PASS",
             "current post-merge verification failed: " + "; ".join(fresh["errors"]))
    for field in (
        "base_sha", "head_sha", "head_tree_sha", "qualification_identity",
        "merge_sha", "merge_tree_sha", "recomputed_tree_sha", "merge_signature",
        "branch_cleanup", "roadmap_sync", "signature_verified",
        "main_contains_change", "qualified_tree_matches", "clean_worktree",
    ):
        _require(payload[field] == fresh[field],
                 f"current post-merge {field} differs from signed proof")
    _require(
        _command(root, ["git", "merge-base", "--is-ancestor",
                        payload["main_sha"], "origin/main"]).returncode == 0,
        "signed proof main is not an ancestor of current main",
    )
    return payload


def write_post_merge_proof(
    root: Path,
    *,
    pr_number: int,
    snapshot: Mapping[str, Any],
    qualification: Mapping[str, Any],
    main_ref: str = "origin/main",
) -> Path:
    """Write an exact, detached-signed proof once after all checks pass."""
    root = Path(root)
    result = verify_post_merge(
        root, pr_number=pr_number, snapshot=snapshot,
        qualification=qualification, main_ref=main_ref,
    )
    if result["status"] != "PASS":
        raise PostMergeError("; ".join(result["errors"]))
    signer = _automation_signing_authority(
        root, result["base_sha"]
    )["automation_key"]["fingerprint"]
    _authorized_proof_signer(root, result["base_sha"], result["main_sha"], signer)
    witness = _qualification_witness(
        root, base=result["base_sha"], head=result["head_sha"],
        tree=result["head_tree_sha"], merge=result["merge_sha"],
        identity=result["qualification_identity"],
    )
    payload = {
        **result,
        "schema_version": 2,
        "qualification_witness": witness,
    }
    directory = root
    for part in OUTPUT_RELATIVE.parts:
        directory = directory / part
        _require(not directory.is_symlink(), "post-merge proof directory is a symlink")
        directory.mkdir(exist_ok=True)
    destination = directory / f"{result['merge_sha']}.json"
    signature = destination.with_suffix(".json.sig")
    content = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    if destination.exists() or destination.is_symlink():
        _require(not destination.is_symlink(), "post-merge proof path is a symlink")
        _require(destination.read_bytes() == content,
                 "historical post-merge proof differs; overwrite forbidden")
        read_post_merge_proof(
            root, result["merge_sha"], expected_pr=pr_number,
            expected_head=result["head_sha"], snapshot=snapshot,
        )
        return destination
    with tempfile.TemporaryDirectory(prefix=".proof-", dir=directory) as temporary:
        unsigned = Path(temporary) / "proof.json"
        detached = Path(temporary) / "proof.json.sig"
        unsigned.write_bytes(content)
        _detached_sign(root, unsigned, detached, signer)
        _verify_detached_signature(
            root, unsigned, detached, result["base_sha"], result["main_sha"]
        )
        try:
            os.link(unsigned, destination)
        except FileExistsError:
            _require(
                not destination.is_symlink() and destination.read_bytes() == content,
                "historical post-merge proof differs; overwrite forbidden",
            )
        try:
            os.link(detached, signature)
        except FileExistsError:
            _require(signature.is_file() and not signature.is_symlink(),
                     "historical post-merge signature path is unsafe")
        _verify_detached_signature(
            root, destination, signature, result["base_sha"], result["main_sha"]
        )
    return destination
