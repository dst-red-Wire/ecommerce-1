#!/usr/bin/env python3
"""Content-addressed inventory of evidence for one exact Git commit.

A bundle verifies identities and bytes. It cannot issue qualification, CODE,
SECURITY, runtime, or owner verdicts.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile
from typing import Iterable


_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_CATEGORIES = ("artifacts", "runtime_evidence", "gate_evidence", "review_evidence")
_QUALIFICATION_KEYS = (
    "base_sha", "head_sha", "head_tree_sha", "qualification_identity",
)


class EvidenceBundleError(ValueError):
    """The bundle cannot establish integrity or exact identity."""


def digest_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return "sha256:" + digest.hexdigest()


def canonical_bytes(payload: dict) -> bytes:
    return (json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceBundleError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_json(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceBundleError(f"invalid JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise EvidenceBundleError(f"JSON object required: {path}")
    return payload


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=root, text=True, capture_output=True, check=False,
    )
    if result.returncode:
        raise EvidenceBundleError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def _require_sha(value: str, label: str) -> None:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise EvidenceBundleError(f"{label} must be a full lowercase SHA")


def _require_digest(value: str, label: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise EvidenceBundleError(f"{label} must be a sha256 digest")


def _safe_file(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or "\\" in relative or "\x00" in relative:
        raise EvidenceBundleError("evidence path must be a repository-relative POSIX path")
    parts = PurePosixPath(relative)
    if parts.is_absolute() or not relative or any(part in ("", ".", "..") for part in relative.split("/")):
        raise EvidenceBundleError(f"unsafe evidence path: {relative!r}")
    path = root.joinpath(*parts.parts)
    current = root
    for part in parts.parts:
        current = current / part
        if current.is_symlink():
            raise EvidenceBundleError(f"symlink evidence path forbidden: {relative}")
    if not path.is_file():
        raise EvidenceBundleError(f"missing evidence file: {relative}")
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise EvidenceBundleError(f"evidence escapes repository: {relative}") from exc
    return path


def _references(root: Path, groups: dict[str, Iterable[str]]) -> tuple[dict[str, list[dict]], dict[str, str]]:
    references: dict[str, list[dict]] = {}
    digests: dict[str, str] = {}
    for category in _CATEGORIES:
        values = list(groups.get(category, ()))
        if len(values) != len(set(values)):
            raise EvidenceBundleError(f"duplicate {category} reference")
        references[category] = []
        for relative in sorted(values):
            if relative in digests:
                raise EvidenceBundleError(f"evidence appears in multiple categories: {relative}")
            digest = digest_file(_safe_file(root, relative))
            digests[relative] = digest
            references[category].append({"path": relative, "sha256": digest})
    return references, digests


def _verify_qualification(root: Path, head_sha: str, identity: dict) -> None:
    relative = f".context/evidence/{head_sha}.json"
    evidence = _read_json(_safe_file(root, relative))
    if evidence.get("status") != "PASS" or evidence.get("exact_commit_evidence") is not True:
        raise EvidenceBundleError("exact qualification PASS evidence required")
    for key in _QUALIFICATION_KEYS:
        if evidence.get(key) != identity[key]:
            raise EvidenceBundleError(f"qualification {key} does not match bundle identity")


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".bundle-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _archive_previous(directory: Path) -> None:
    manifest = directory / "manifest.json"
    sidecar = directory / "manifest.sha256"
    if not manifest.exists() and not sidecar.exists():
        return
    if not manifest.is_file() or not sidecar.is_file() or manifest.is_symlink() or sidecar.is_symlink():
        raise EvidenceBundleError("incomplete or unsafe previous manifest")
    old_bytes = manifest.read_bytes()
    old_digest = sidecar.read_text(encoding="utf-8").strip()
    if digest_bytes(old_bytes) != old_digest:
        raise EvidenceBundleError("previous manifest digest mismatch")
    _read_json(manifest)
    history = directory / "history"
    history.mkdir(exist_ok=True)
    if history.is_symlink():
        raise EvidenceBundleError("unsafe history directory")
    archived = history / (old_digest.split(":", 1)[1] + ".json")
    if archived.exists() and archived.read_bytes() != old_bytes:
        raise EvidenceBundleError("historical manifest collision")
    if not archived.exists():
        _atomic_write(archived, old_bytes)


def create_bundle(
    root: Path,
    *,
    base_sha: str,
    head_sha: str,
    tree_sha: str,
    qualification_identity: str,
    toolchain_digest: str,
    artifacts: Iterable[str] = (),
    runtime_evidence: Iterable[str] = (),
    gate_evidence: Iterable[str] = (),
    review_evidence: Iterable[str] = (),
    runtime_identity: str = "",
) -> dict:
    """Build an inventory after an existing exact qualification PASS.

    Review references are supplied by the caller from external review records;
    this function never creates or upgrades their verdicts.
    """
    root = root.resolve()
    for label, value in (("base_sha", base_sha), ("head_sha", head_sha), ("tree_sha", tree_sha)):
        _require_sha(value, label)
    _require_digest(toolchain_digest, "toolchain_digest")
    if not isinstance(qualification_identity, str) or not qualification_identity:
        raise EvidenceBundleError("qualification_identity required")
    if not isinstance(runtime_identity, str):
        raise EvidenceBundleError("runtime_identity must be a string")
    if _git(root, "rev-parse", "HEAD") != head_sha:
        raise EvidenceBundleError("checked-out HEAD differs from bundle head_sha")
    if _git(root, "rev-parse", "HEAD^{tree}") != tree_sha:
        raise EvidenceBundleError("checked-out tree differs from bundle tree_sha")
    if _git(root, "status", "--porcelain", "--untracked-files=all"):
        raise EvidenceBundleError("exact-SHA bundle requires a clean worktree")
    _git(root, "cat-file", "-e", base_sha + "^{commit}")
    lock = _safe_file(root, "config/contracts/toolchain-lock.json")
    if digest_file(lock) != toolchain_digest:
        raise EvidenceBundleError("toolchain lock digest changed")
    qualification = f".context/evidence/{head_sha}.json"
    gates = list(gate_evidence)
    if qualification not in gates:
        gates.append(qualification)
    identity = {
        "base_sha": base_sha,
        "head_sha": head_sha,
        "head_tree_sha": tree_sha,
        "qualification_identity": qualification_identity,
    }
    _verify_qualification(root, head_sha, identity)
    references, digests = _references(
        root,
        {
            "artifacts": artifacts,
            "runtime_evidence": runtime_evidence,
            "gate_evidence": gates,
            "review_evidence": review_evidence,
        },
    )
    payload = {
        "schema_version": 1,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "tree_sha": tree_sha,
        "toolchain_digest": toolchain_digest,
        "qualification_identity": qualification_identity,
        "runtime_identity": runtime_identity,
        **references,
        "evidence_digests": digests,
        "verdict_authority": False,
    }
    encoded = canonical_bytes(payload)
    digest = digest_bytes(encoded)
    directory = root / ".context" / "evidence" / head_sha
    if directory.is_symlink():
        raise EvidenceBundleError("unsafe bundle directory")
    directory.mkdir(parents=True, exist_ok=True)
    if (directory / "manifest.json").exists():
        current = (directory / "manifest.json").read_bytes()
        if current != encoded:
            _archive_previous(directory)
    _atomic_write(directory / "manifest.json", encoded)
    _atomic_write(directory / "manifest.sha256", (digest + "\n").encode("ascii"))
    return {"status": "BUNDLED", "manifest": str((directory / "manifest.json").relative_to(root)), "manifest_digest": digest}


def verify_bundle(root: Path, head_sha: str, *, expected_identity: dict | None = None) -> dict:
    """Verify bytes and identity; PASS refers only to bundle integrity."""
    root = root.resolve()
    _require_sha(head_sha, "head_sha")
    directory = root / ".context" / "evidence" / head_sha
    manifest_path = _safe_file(root, f".context/evidence/{head_sha}/manifest.json")
    sidecar_path = _safe_file(root, f".context/evidence/{head_sha}/manifest.sha256")
    encoded = manifest_path.read_bytes()
    digest = sidecar_path.read_text(encoding="ascii").strip()
    _require_digest(digest, "manifest digest")
    if digest_bytes(encoded) != digest:
        raise EvidenceBundleError("manifest digest mismatch")
    manifest = _read_json(manifest_path)
    if manifest.get("schema_version") != 1 or manifest.get("head_sha") != head_sha:
        raise EvidenceBundleError("wrong manifest schema or head SHA")
    if encoded != canonical_bytes(manifest):
        raise EvidenceBundleError("manifest is not canonical JSON")
    for key in ("base_sha", "head_sha", "tree_sha"):
        _require_sha(manifest.get(key), key)
    _require_digest(manifest.get("toolchain_digest"), "toolchain_digest")
    if manifest.get("verdict_authority") is not False:
        raise EvidenceBundleError("bundle cannot be a verdict authority")
    all_digests: dict[str, str] = {}
    for category in _CATEGORIES:
        items = manifest.get(category)
        if not isinstance(items, list):
            raise EvidenceBundleError(f"missing {category}")
        for item in items:
            if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
                raise EvidenceBundleError(f"invalid {category} reference")
            relative, declared = item["path"], item["sha256"]
            _require_digest(declared, "evidence sha256")
            if relative in all_digests:
                raise EvidenceBundleError(f"duplicate evidence reference: {relative}")
            if digest_file(_safe_file(root, relative)) != declared:
                raise EvidenceBundleError(f"evidence digest mismatch: {relative}")
            all_digests[relative] = declared
    if manifest.get("evidence_digests") != all_digests:
        raise EvidenceBundleError("evidence digest index mismatch")
    qualification = f".context/evidence/{head_sha}.json"
    if qualification not in {item["path"] for item in manifest["gate_evidence"]}:
        raise EvidenceBundleError("exact qualification evidence missing from bundle")
    identity = {
        "base_sha": manifest["base_sha"],
        "head_sha": head_sha,
        "head_tree_sha": manifest["tree_sha"],
        "qualification_identity": manifest.get("qualification_identity"),
    }
    _verify_qualification(root, head_sha, identity)
    if expected_identity:
        keys = ("base_sha", "head_sha", "tree_sha", "toolchain_digest", "qualification_identity", "runtime_identity")
        for key in keys:
            if key in expected_identity and manifest.get(key) != expected_identity[key]:
                raise EvidenceBundleError(f"wrong {key} for requested identity")
    return {"status": "PASS", "authority": "bundle-integrity-only", "manifest_digest": digest}


def authority_state(record_identity: dict, current_identity: dict) -> str:
    """Historical evidence remains intact but loses current authority on drift."""
    keys = ("base_sha", "head_sha", "tree_sha", "toolchain_digest", "qualification_identity", "runtime_identity")
    if any(not record_identity.get(key) for key in ("base_sha", "head_sha", "tree_sha", "toolchain_digest", "qualification_identity")):
        return "FAIL"
    if any(record_identity.get(key, "") != current_identity.get(key, "") for key in keys):
        return "SUPERSEDED"
    return "CURRENT"
