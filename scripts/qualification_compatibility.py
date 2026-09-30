#!/usr/bin/env python3
"""Content-addressed bridge from exact-base qualification to PR delivery."""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
from typing import Callable

_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_MAX_PROOF_BYTES = 16 * 1024 * 1024
_MAX_ENVELOPE_BYTES = 1024 * 1024
_RELATIVE = Path(".context/evidence/controller-compatibility/v1")


class CompatibilityError(RuntimeError):
    """A qualification bridge is absent, malformed, or no longer authoritative."""


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _check_binding(
    repository: str, pr_number: int, base_sha: str, head_sha: str, tree_sha: str
) -> None:
    if not isinstance(repository, str) or _REPOSITORY.fullmatch(repository) is None:
        raise CompatibilityError("repository identity is invalid")
    if type(pr_number) is not int or pr_number < 1:
        raise CompatibilityError("PR number is invalid")
    if any(
        not isinstance(value, str) or _SHA.fullmatch(value) is None
        for value in (base_sha, head_sha, tree_sha)
    ):
        raise CompatibilityError("exact base, head, and tree SHAs are required")


def _under_root(root: Path, path: Path) -> Path:
    root = root.resolve(strict=True)
    candidate = path if path.is_absolute() else root / path
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise CompatibilityError("evidence path escapes target checkout") from exc
    if any(component in ("", ".", "..") for component in relative.parts):
        raise CompatibilityError("evidence path contains traversal")
    current = root
    for component in relative.parts:
        current = current / component
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode):
            raise CompatibilityError("evidence path contains a symlink")
    return candidate


def _read_file(root: Path, path: Path, limit: int) -> bytes:
    candidate = _under_root(root, path)
    try:
        info = candidate.lstat()
    except OSError as exc:
        raise CompatibilityError("qualification artifact is missing") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
        raise CompatibilityError("qualification artifact is unsafe")
    try:
        data = candidate.read_bytes()
        readback = candidate.read_bytes()
    except OSError as exc:
        raise CompatibilityError("qualification artifact cannot be read") from exc
    if len(data) > limit or data != readback:
        raise CompatibilityError("qualification artifact changed during read")
    return data


def _controller_bytes(controller_path: Path) -> bytes:
    controller = Path(controller_path)
    if controller.name != "repoctl.py" or controller.parent.name != "scripts":
        raise CompatibilityError("trusted controller path is invalid")
    return _read_file(controller.parent.parent, controller, _MAX_PROOF_BYTES)


def _store_once(root: Path, relative: Path, data: bytes) -> Path:
    target = _under_root(root, relative)
    target.parent.mkdir(parents=True, exist_ok=True)
    _under_root(root, target)
    if target.exists():
        if _read_file(root, target, len(data)) != data:
            raise CompatibilityError("content-addressed artifact has different bytes")
        return target
    descriptor, temporary = tempfile.mkstemp(prefix=".compat-", dir=target.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        if target.exists():
            if _read_file(root, target, len(data)) != data:
                raise CompatibilityError(
                    "content-addressed artifact has different bytes"
                )
        else:
            os.replace(temporary, target)
            temporary = ""
    finally:
        if temporary:
            os.unlink(temporary)
    return target


def _payload(
    repository: str,
    pr_number: int,
    base_sha: str,
    head_sha: str,
    tree_sha: str,
    controller_digest: str,
    raw_digest: str,
    audit_digest: str,
    raw: dict,
) -> dict:
    if (
        raw.get("status") != "PASS"
        or raw.get("schema_version") != 5
        or raw.get("evidence_kind") != "exact_commit"
        or raw.get("exact_commit_evidence") is not True
        or raw.get("base_sha") != base_sha
        or raw.get("head_sha") != head_sha
        or raw.get("head_tree_sha") != tree_sha
        or not isinstance(raw.get("qualification_identity"), str)
        or _DIGEST.fullmatch(raw_digest) is None
        or _DIGEST.fullmatch(audit_digest) is None
        or _DIGEST.fullmatch(controller_digest) is None
    ):
        raise CompatibilityError("raw proof is not an exact-base PASS qualification")
    created_at = raw.get("created_at_epoch")
    if (
        type(created_at) not in (int, float)
        or not math.isfinite(created_at)
        or created_at < 0
    ):
        raise CompatibilityError("raw proof creation time is invalid")
    records = raw.get("gates")
    if not isinstance(records, list) or not records or len(records) > 256:
        raise CompatibilityError("raw proof gate inventory is invalid")
    gates = []
    seen = set()
    for record in records:
        if not isinstance(record, dict):
            raise CompatibilityError("raw proof gate record is invalid")
        name = record.get("gate")
        status = record.get("status")
        exit_code = record.get("exit_code", 0)
        execution = record.get("execution")
        if (
            not isinstance(name, str)
            or not name
            or len(name) > 160
            or name in seen
            or not isinstance(status, str)
            or status not in {"PASS", "SKIP"}
            or type(exit_code) is not int
            or not isinstance(execution, str)
            or execution not in {"fresh", "content-cache", "parent-evidence", "skipped"}
        ):
            raise CompatibilityError("raw proof gate result is invalid")
        seen.add(name)
        gate = {
            "gate": name,
            "status": status,
            "exit_code": exit_code,
            "execution": execution,
        }
        if "log" in record:
            log = record["log"]
            if (
                not isinstance(log, str)
                or not log.startswith(".context/logs/")
                or len(log) > 512
                or "\\" in log
                or any(part in ("", ".", "..") for part in log.split("/"))
                or PurePosixPath(log).is_absolute()
            ):
                raise CompatibilityError("raw proof gate log path is invalid")
            gate["log"] = log
        if "reused_from_sha" in record:
            source_sha = record["reused_from_sha"]
            if not isinstance(source_sha, str) or _SHA.fullmatch(source_sha) is None:
                raise CompatibilityError("raw proof reuse source is invalid")
            gate["reused_from_sha"] = source_sha
        if "promoted_from_worktree" in record:
            promoted = record["promoted_from_worktree"]
            if type(promoted) is not bool:
                raise CompatibilityError("raw proof promotion flag is invalid")
            gate["promoted_from_worktree"] = promoted
        if "promotion_source_tree_sha" in record:
            source_tree = record["promotion_source_tree_sha"]
            if not isinstance(source_tree, str) or _SHA.fullmatch(source_tree) is None:
                raise CompatibilityError("raw proof promotion tree is invalid")
            gate["promotion_source_tree_sha"] = source_tree
        gates.append(gate)
    return {
        "schema_version": 1,
        "kind": "QualificationCompatibilityEnvelope",
        "binding": {
            "repository": repository,
            "pr": pr_number,
            "base_sha": base_sha,
            "head_sha": head_sha,
            "tree_sha": tree_sha,
        },
        "qualification": {
            "status": "PASS",
            "identity": raw["qualification_identity"],
            "created_at_epoch": created_at,
            "raw_proof_sha256": raw_digest,
            "performance_audit_sha256": audit_digest,
            "gate_results": sorted(gates, key=lambda item: item["gate"]),
        },
        "provenance": {
            "controller_source": "exact-pr-base-sha",
            "controller_path": "scripts/repoctl.py",
            "controller_sha256": controller_digest,
            "raw_evidence_kind": "exact_commit",
        },
    }


def _archive_path(head_sha: str, kind: str, digest: str) -> Path:
    if kind not in {"raw", "audit"} or _DIGEST.fullmatch(digest) is None:
        raise CompatibilityError("archive digest or kind is invalid")
    return _RELATIVE / kind / head_sha / (digest.removeprefix("sha256:") + ".json")


def _envelope_dir(pr_number: int, head_sha: str) -> Path:
    return _RELATIVE / "envelopes" / str(pr_number) / head_sha


def _validated_result(root: Path, envelope_path: Path, payload: dict) -> dict:
    return {
        "status": "PASS",
        "path": str(envelope_path.relative_to(root)),
        "envelope_sha256": payload["envelope_sha256"],
        "raw_proof_path": str(
            _archive_path(
                payload["binding"]["head_sha"],
                "raw",
                payload["qualification"]["raw_proof_sha256"],
            )
        ),
        "performance_audit_path": str(
            _archive_path(
                payload["binding"]["head_sha"],
                "audit",
                payload["qualification"]["performance_audit_sha256"],
            )
        ),
        "qualification_identity": payload["qualification"]["identity"],
        "gate_results": payload["qualification"]["gate_results"],
    }


def verify_envelope(
    root: Path,
    envelope_path: Path,
    *,
    repository: str,
    pr_number: int,
    base_sha: str,
    head_sha: str,
    tree_sha: str,
    controller_path: Path,
    validate_raw: Callable[[Path], bool],
    validate_audit: Callable[[Path], bool],
) -> dict:
    """Recompute every envelope claim from archived base-valid artifacts."""
    _check_binding(repository, pr_number, base_sha, head_sha, tree_sha)
    root = root.resolve(strict=True)
    envelope_path = _under_root(root, envelope_path)
    encoded = _read_file(root, envelope_path, _MAX_ENVELOPE_BYTES)
    try:
        envelope = json.loads(encoded)
    except (ValueError, UnicodeDecodeError) as exc:
        raise CompatibilityError("compatibility envelope is not JSON") from exc
    if not isinstance(envelope, dict):
        raise CompatibilityError("compatibility envelope is invalid")
    digest = envelope.get("envelope_sha256")
    if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
        raise CompatibilityError("compatibility envelope digest is invalid")
    fields = {key: value for key, value in envelope.items() if key != "envelope_sha256"}
    try:
        content_digest = _digest(_canonical(fields))
    except (TypeError, ValueError) as exc:
        raise CompatibilityError(
            "compatibility envelope is not canonical JSON"
        ) from exc
    if content_digest != digest:
        raise CompatibilityError("compatibility envelope content digest differs")
    qualification = envelope.get("qualification")
    if not isinstance(qualification, dict):
        raise CompatibilityError("compatibility qualification is invalid")
    raw_digest = qualification.get("raw_proof_sha256")
    audit_digest = qualification.get("performance_audit_sha256")
    if not isinstance(raw_digest, str) or not isinstance(audit_digest, str):
        raise CompatibilityError("compatibility artifact digests are missing")
    raw_path = _under_root(root, _archive_path(head_sha, "raw", raw_digest))
    audit_path = _under_root(root, _archive_path(head_sha, "audit", audit_digest))
    raw_bytes = _read_file(root, raw_path, _MAX_PROOF_BYTES)
    audit_bytes = _read_file(root, audit_path, _MAX_PROOF_BYTES)
    if _digest(raw_bytes) != raw_digest or _digest(audit_bytes) != audit_digest:
        raise CompatibilityError("archived qualification bytes differ")
    if not validate_raw(raw_path) or not validate_audit(audit_path):
        raise CompatibilityError("base controller rejects archived qualification")
    try:
        raw = json.loads(raw_bytes)
        audit = json.loads(audit_bytes)
    except (ValueError, UnicodeDecodeError) as exc:
        raise CompatibilityError("archived qualification is invalid JSON") from exc
    if not isinstance(raw, dict) or not isinstance(audit, dict):
        raise CompatibilityError("archived qualification is not an object")
    if audit.get("head_sha") != head_sha or audit.get("base_sha") != base_sha:
        raise CompatibilityError("archived performance audit binding differs")
    controller_digest = _digest(_controller_bytes(controller_path))
    expected = _payload(
        repository,
        pr_number,
        base_sha,
        head_sha,
        tree_sha,
        controller_digest,
        raw_digest,
        audit_digest,
        raw,
    )
    if fields != expected:
        raise CompatibilityError("compatibility envelope differs from base-valid proof")
    expected_path = _under_root(
        root,
        _envelope_dir(pr_number, head_sha) / (digest.removeprefix("sha256:") + ".json"),
    )
    if envelope_path != expected_path:
        raise CompatibilityError("compatibility envelope path is not content-addressed")
    return _validated_result(root, envelope_path, envelope)


def create_envelope(
    root: Path,
    *,
    repository: str,
    pr_number: int,
    base_sha: str,
    head_sha: str,
    tree_sha: str,
    controller_path: Path,
    raw_proof_path: Path,
    audit_path: Path,
    validate_raw: Callable[[Path], bool],
    validate_audit: Callable[[Path], bool],
) -> dict:
    """Archive and bind an already validated exact-base qualification."""
    _check_binding(repository, pr_number, base_sha, head_sha, tree_sha)
    root = root.resolve(strict=True)
    raw_proof_path = _under_root(root, raw_proof_path)
    audit_path = _under_root(root, audit_path)
    if not validate_raw(raw_proof_path) or not validate_audit(audit_path):
        raise CompatibilityError(
            "base controller has not validated exact qualification"
        )
    raw_bytes = _read_file(root, raw_proof_path, _MAX_PROOF_BYTES)
    audit_bytes = _read_file(root, audit_path, _MAX_PROOF_BYTES)
    try:
        raw = json.loads(raw_bytes)
        audit = json.loads(audit_bytes)
    except (ValueError, UnicodeDecodeError) as exc:
        raise CompatibilityError("qualification artifacts are invalid JSON") from exc
    if not isinstance(raw, dict) or not isinstance(audit, dict):
        raise CompatibilityError("qualification artifacts must be objects")
    if audit.get("head_sha") != head_sha or audit.get("base_sha") != base_sha:
        raise CompatibilityError("performance audit is not bound to exact PR")
    raw_digest = _digest(raw_bytes)
    audit_digest = _digest(audit_bytes)
    controller_digest = _digest(_controller_bytes(controller_path))
    payload = _payload(
        repository,
        pr_number,
        base_sha,
        head_sha,
        tree_sha,
        controller_digest,
        raw_digest,
        audit_digest,
        raw,
    )
    envelope_digest = _digest(_canonical(payload))
    envelope = {**payload, "envelope_sha256": envelope_digest}
    raw_archive = _store_once(
        root, _archive_path(head_sha, "raw", raw_digest), raw_bytes
    )
    audit_archive = _store_once(
        root, _archive_path(head_sha, "audit", audit_digest), audit_bytes
    )
    if not validate_raw(raw_archive) or not validate_audit(audit_archive):
        raise CompatibilityError("base controller rejects archived qualification")
    envelope_path = _store_once(
        root,
        _envelope_dir(pr_number, head_sha)
        / (envelope_digest.removeprefix("sha256:") + ".json"),
        _canonical(envelope) + b"\n",
    )
    return verify_envelope(
        root,
        envelope_path,
        repository=repository,
        pr_number=pr_number,
        base_sha=base_sha,
        head_sha=head_sha,
        tree_sha=tree_sha,
        controller_path=controller_path,
        validate_raw=validate_raw,
        validate_audit=validate_audit,
    )


def find_envelope(
    root: Path,
    *,
    repository: str,
    pr_number: int,
    base_sha: str,
    head_sha: str,
    tree_sha: str,
    controller_path: Path,
    validate_raw: Callable[[Path], bool],
    validate_audit: Callable[[Path], bool],
) -> dict | None:
    """Return a verified current envelope, never a self-declared status."""
    _check_binding(repository, pr_number, base_sha, head_sha, tree_sha)
    root = root.resolve(strict=True)
    directory = _under_root(root, _envelope_dir(pr_number, head_sha))
    if not directory.is_dir():
        return None
    try:
        candidates = sorted(directory.iterdir())
    except OSError as exc:
        raise CompatibilityError(
            "compatibility envelope inventory is unreadable"
        ) from exc
    if len(candidates) > 64:
        raise CompatibilityError("too many compatibility envelopes for exact PR")
    for path in reversed(candidates):
        try:
            return verify_envelope(
                root,
                path,
                repository=repository,
                pr_number=pr_number,
                base_sha=base_sha,
                head_sha=head_sha,
                tree_sha=tree_sha,
                controller_path=controller_path,
                validate_raw=validate_raw,
                validate_audit=validate_audit,
            )
        except CompatibilityError:
            continue
    return None


def archive_head_artifacts(
    root: Path,
    *,
    head_sha: str,
    raw_proof_path: Path,
    audit_path: Path,
    clear_originals: bool = False,
) -> dict:
    """Preserve head bytes as data, then optionally force fresh base production."""
    if not isinstance(head_sha, str) or _SHA.fullmatch(head_sha) is None:
        raise CompatibilityError("exact head SHA is required")
    root = root.resolve(strict=True)
    archived = {}
    originals: list[tuple[Path, str]] = []
    for kind, path in (("raw", raw_proof_path), ("audit", audit_path)):
        path = _under_root(root, path)
        if not path.exists():
            continue
        data = _read_file(root, path, _MAX_PROOF_BYTES)
        digest = _digest(data)
        relative = (
            _RELATIVE
            / "head"
            / kind
            / head_sha
            / (digest.removeprefix("sha256:") + ".json")
        )
        saved = _store_once(root, relative, data)
        if _digest(_read_file(root, saved, _MAX_PROOF_BYTES)) != digest:
            raise CompatibilityError("head artifact archive readback differs")
        archived[kind] = {"path": str(relative), "sha256": digest, "authority": False}
        originals.append((path, digest))
    if clear_originals:
        for path, digest in originals:
            if _digest(_read_file(root, path, _MAX_PROOF_BYTES)) != digest:
                raise CompatibilityError("head artifact changed before fresh base run")
        for path, _digest_value in originals:
            path.unlink()
    return archived
