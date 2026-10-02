#!/usr/bin/env python3
"""Validate an independently approved runner authority and exact PR binding.

This module checks identity and proof structure only. No trusted runtime
verifier is implemented here, so its public activation and qualification APIs
always fail closed. A caller-supplied callback or ActivationResult cannot
authorize a PR workload.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

CANONICAL_REPOSITORY = "dst-red-Wire/ecommerce-1"
DEFAULT_HARBOR_REGISTRY = "harbor.ecommerce.local"
REQUIRED_PROOFS = (
    "runner-image-digest-pullable",
    "bounded-execution-budget-proven",
    "least-privilege-rbac-proven",
)

_SHA = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IMAGE_SEGMENT = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*\Z")
_REGISTRY = re.compile(r"[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[0-9]{1,5})?\Z")
_CAMPAIGN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")


class RunnerAuthorityError(ValueError):
    """An identity, proof, or exact target binding is invalid."""


def _require_pattern(value: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise RunnerAuthorityError(f"{label} is invalid")
    return value


def _canonical_bytes(value: Mapping[str, object]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _image_digest(reference: str, registry: str) -> str:
    _require_pattern(registry, _REGISTRY, "Harbor registry")
    if not isinstance(reference, str) or reference.count("@") != 1:
        raise RunnerAuthorityError("runner image must use one immutable digest")
    repository, digest = reference.split("@", 1)
    _require_pattern(digest, _DIGEST, "runner image digest")
    prefix = registry + "/"
    if not repository.startswith(prefix):
        raise RunnerAuthorityError(
            "runner image is outside the trusted Harbor registry"
        )
    segments = repository[len(prefix) :].split("/")
    if len(segments) < 2 or any(_IMAGE_SEGMENT.fullmatch(s) is None for s in segments):
        raise RunnerAuthorityError(
            "runner image requires a Harbor project and name without a tag"
        )
    return digest


@dataclass(frozen=True, slots=True)
class AuthorityIdentity:
    authority_source_sha: str
    runner_image: str
    policy_digest: str
    validator_digest: str
    toolchain_digest: str | None = None
    harbor_registry: str = DEFAULT_HARBOR_REGISTRY
    runner_image_digest: str = field(init=False)
    authority_id: str = field(init=False)

    def __post_init__(self) -> None:
        _require_pattern(self.authority_source_sha, _SHA, "authority source SHA")
        _require_pattern(self.policy_digest, _DIGEST, "policy digest")
        _require_pattern(self.validator_digest, _DIGEST, "validator digest")
        if self.toolchain_digest is not None:
            _require_pattern(self.toolchain_digest, _DIGEST, "toolchain digest")
        if self.harbor_registry != DEFAULT_HARBOR_REGISTRY:
            raise RunnerAuthorityError("runner image must use canonical Harbor")
        image_digest = _image_digest(self.runner_image, self.harbor_registry)
        payload = {
            "schema_version": 1,
            "authority_source_sha": self.authority_source_sha,
            "runner_image": self.runner_image,
            "runner_image_digest": image_digest,
            "policy_digest": self.policy_digest,
            "validator_digest": self.validator_digest,
            "toolchain_digest": self.toolchain_digest,
        }
        authority_id = (
            "sha256:"
            + hashlib.sha256(
                b"ecommerce-1-runner-authority-v1\n" + _canonical_bytes(payload)
            ).hexdigest()
        )
        object.__setattr__(self, "runner_image_digest", image_digest)
        object.__setattr__(self, "authority_id", authority_id)

    def as_dict(self) -> dict[str, str | None]:
        return {
            "authority_source_sha": self.authority_source_sha,
            "runner_image": self.runner_image,
            "runner_image_digest": self.runner_image_digest,
            "policy_digest": self.policy_digest,
            "validator_digest": self.validator_digest,
            "toolchain_digest": self.toolchain_digest,
            "authority_id": self.authority_id,
        }


@dataclass(frozen=True, slots=True)
class ProofBinding:
    target_repository: str
    target_pr: int
    target_sha: str
    campaign_id: str

    def __post_init__(self) -> None:
        if self.target_repository != CANONICAL_REPOSITORY:
            raise RunnerAuthorityError("target repository is not canonical")
        if type(self.target_pr) is not int or self.target_pr < 1:
            raise RunnerAuthorityError("target PR is invalid")
        _require_pattern(self.target_sha, _SHA, "target SHA")
        _require_pattern(self.campaign_id, _CAMPAIGN, "campaign ID")


@dataclass(frozen=True, slots=True)
class ExactTargetBinding:
    repository: str
    pr: int
    expected_sha: str
    github_pr_head_sha: str
    checked_out_sha: str

    def __post_init__(self) -> None:
        if (
            self.repository != CANONICAL_REPOSITORY
            or type(self.pr) is not int
            or self.pr < 1
        ):
            raise RunnerAuthorityError("exact PR target is invalid")
        for label, value in (
            ("expected SHA", self.expected_sha),
            ("GitHub PR head SHA", self.github_pr_head_sha),
            ("checked-out SHA", self.checked_out_sha),
        ):
            _require_pattern(value, _SHA, label)
        if (
            self.expected_sha != self.github_pr_head_sha
            or self.expected_sha != self.checked_out_sha
        ):
            raise RunnerAuthorityError(
                "FAIL_CLOSED: expected, GitHub, and checked-out SHAs differ"
            )


@dataclass(frozen=True, slots=True)
class ActivationResult:
    runner_authority: str
    authority_id: str
    proof_statuses: dict[str, str]
    blockers: tuple[str, ...]


# This callback must authenticate the COMPLETE proof and its evidence references
# from trusted control-plane storage or live runtime observations.
EvidenceVerifier = Callable[[Mapping[str, Any], AuthorityIdentity, ProofBinding], bool]


def _proof_errors(
    proof: object,
    name: str,
    identity: AuthorityIdentity,
    binding: ProofBinding,
) -> list[str]:
    if not isinstance(proof, Mapping):
        return [f"{name}: proof is missing or malformed"]
    expected = {
        "proof_name": name,
        "verdict": "PASS",
        "authority_id": identity.authority_id,
        "authority_source_sha": identity.authority_source_sha,
        "target_repository": binding.target_repository,
        "target_pr": binding.target_pr,
        "target_sha": binding.target_sha,
        "runner_image": identity.runner_image,
        "runner_image_digest": identity.runner_image_digest,
        "policy_digest": identity.policy_digest,
        "campaign_id": binding.campaign_id,
        "validator_identity": identity.validator_digest,
        "toolchain_digest": identity.toolchain_digest,
    }
    errors = [
        f"{name}: {key} differs from the exact authority or target"
        for key, value in expected.items()
        if proof.get(key) != value
        or (key == "target_pr" and type(proof.get(key)) is not int)
    ]
    timestamp = proof.get("timestamp")
    if not isinstance(timestamp, str):
        errors.append(f"{name}: timestamp is missing")
    else:
        try:
            observed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            if observed.tzinfo is None or observed.utcoffset() is None:
                raise ValueError("timezone required")
            if observed > datetime.now(timezone.utc):
                errors.append(f"{name}: timestamp is in the future")
        except ValueError:
            errors.append(f"{name}: timestamp must include a timezone")
    references = proof.get("evidence_references")
    if not isinstance(references, list) or not references:
        errors.append(f"{name}: evidence references are missing")
    else:
        seen: set[str] = set()
        for reference in references:
            if not isinstance(reference, Mapping) or set(reference) != {
                "path",
                "sha256",
            }:
                errors.append(f"{name}: malformed evidence reference")
                continue
            path = reference["path"]
            digest = reference["sha256"]
            if not isinstance(path, str) or not path or "\\" in path or "\x00" in path:
                errors.append(f"{name}: unsafe evidence path")
                continue
            parsed = PurePosixPath(path)
            if parsed.is_absolute() or any(
                part in {"", ".", ".."} for part in path.split("/")
            ):
                errors.append(f"{name}: unsafe evidence path")
            if path in seen:
                errors.append(f"{name}: duplicate evidence path")
            seen.add(path)
            if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
                errors.append(f"{name}: invalid evidence digest")
    return errors


def verify_activation(
    identity: AuthorityIdentity,
    binding: ProofBinding,
    proofs: Mapping[str, object],
    *,
    approved_main_sha: str,
    evidence_verifier: EvidenceVerifier | None,
) -> ActivationResult:
    """Check declared bindings; never activate without a concrete runtime verifier.

    Caller-supplied callbacks are intentionally ignored. A future control-plane
    integration must authenticate evidence from independently protected storage
    and verify live Harbor pull, aggregate cgroup limits, PID namespace,
    descendant cleanup, and least-privilege RBAC before adding an ACTIVE path.
    """
    _require_pattern(approved_main_sha, _SHA, "approved main SHA")
    blockers = ["independent runtime proof verification is not implemented"]
    statuses = {name: "NOT_PROVEN" for name in REQUIRED_PROOFS}
    if approved_main_sha != identity.authority_source_sha:
        blockers.append(
            "authority source SHA is not the independently approved main SHA"
        )
    if not isinstance(proofs, Mapping) or set(proofs) != set(REQUIRED_PROOFS):
        blockers.append(
            "runtime proof inventory differs from the three required proofs"
        )
        proofs = proofs if isinstance(proofs, Mapping) else {}
    if evidence_verifier is not None:
        blockers.append(
            "caller-supplied evidence verifier cannot establish runtime proof"
        )
    for name in REQUIRED_PROOFS:
        blockers.extend(_proof_errors(proofs.get(name), name, identity, binding))
    return ActivationResult(
        "NOT_ACTIVE", identity.authority_id, statuses, tuple(blockers)
    )


def verify_qualification_proof(
    identity: AuthorityIdentity,
    binding: ProofBinding,
    proof: Mapping[str, object],
    *,
    activation: ActivationResult,
    exact_target: ExactTargetBinding,
    evidence_verifier: EvidenceVerifier | None,
) -> None:
    """Validate declared target bindings, then fail closed pending runtime proof.

    An ActivationResult is caller-constructible and cannot establish authority.
    The callback is not invoked; this API has no success path until a trusted
    control-plane verifier of independent runtime artifacts is implemented.
    """
    if (
        not isinstance(activation, ActivationResult)
        or activation.runner_authority != "ACTIVE"
        or activation.authority_id != identity.authority_id
        or activation.blockers
        or set(activation.proof_statuses) != set(REQUIRED_PROOFS)
        or any(activation.proof_statuses[name] != "PASS" for name in REQUIRED_PROOFS)
    ):
        raise RunnerAuthorityError("runner authority is NOT_ACTIVE")
    if (
        not isinstance(exact_target, ExactTargetBinding)
        or exact_target.repository != binding.target_repository
        or exact_target.pr != binding.target_pr
        or exact_target.expected_sha != binding.target_sha
    ):
        raise RunnerAuthorityError(
            "FAIL_CLOSED: qualification target is not the exact PR HEAD"
        )
    if binding.target_sha == identity.authority_source_sha:
        raise RunnerAuthorityError(
            "FAIL_CLOSED: PR workload cannot validate its own authority"
        )
    errors = _proof_errors(proof, "exact-sha-qualification", identity, binding)
    if errors:
        raise RunnerAuthorityError("; ".join(errors))
    raise RunnerAuthorityError(
        "NOT_ACTIVE: independent runtime proof verification is not implemented"
    )


def _control_plane_git_bytes(root: Path, *args: str) -> bytes:
    environment = os.environ.copy()
    for key in (
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_COMMON_DIR",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    ):
        environment.pop(key, None)
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    try:
        result = subprocess.run(
            [
                "git",
                "--no-optional-locks",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.hooksPath=/dev/null",
                "-C",
                str(root),
                *args,
            ],
            cwd="/",
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RunnerAuthorityError("cannot inspect exact target checkout") from exc
    if result.returncode:
        raise RunnerAuthorityError("cannot inspect exact target checkout")
    return result.stdout


def _control_plane_git(root: Path, *args: str) -> str:
    return _control_plane_git_bytes(root, *args).decode("utf-8", "replace").strip()


def _reject_hidden_index_flags(root: Path) -> None:
    """Reject index flags that make Git status omit changed worktree bytes."""
    entries = _control_plane_git_bytes(root, "ls-files", "-v", "-z")
    if entries and not entries.endswith(b"\x00"):
        raise RunnerAuthorityError("Git index inventory is malformed")
    for entry in entries.split(b"\x00"):
        if entry and not entry.startswith(b"H "):
            raise RunnerAuthorityError(
                "checkout has assume-unchanged, skip-worktree, or unmerged index entries"
            )


def _github_pr_snapshot(
    repository: str, pr: int, gh_binary: str
) -> Mapping[str, object]:
    if not isinstance(gh_binary, str) or not Path(gh_binary).is_absolute():
        raise RunnerAuthorityError("trusted absolute GitHub CLI path is required")
    try:
        result = subprocess.run(
            [gh_binary, "api", f"repos/{repository}/pulls/{pr}"],
            cwd="/",
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RunnerAuthorityError("GitHub PR HEAD is unavailable") from exc
    if result.returncode or len(result.stdout) > 1_000_000:
        raise RunnerAuthorityError("GitHub PR HEAD is unavailable")
    try:
        value = json.loads(result.stdout)
    except (TypeError, ValueError) as exc:
        raise RunnerAuthorityError("GitHub PR metadata is invalid") from exc
    if not isinstance(value, dict):
        raise RunnerAuthorityError("GitHub PR metadata is invalid")
    return value


def resolve_exact_target(
    repository: str,
    pr: int,
    expected_sha: str,
    checkout_root: Path,
    authority_source_sha: str,
    *,
    gh_binary: str | None = None,
    github_reader: Callable[[str, int], Mapping[str, object]] | None = None,
) -> ExactTargetBinding:
    """Read GitHub twice and the clean checkout; reject drift and self-validation.

    Production callers pass a pinned absolute gh_binary from the trusted base.
    github_reader exists for isolated tests and must never be PR-controlled.
    """
    if repository != CANONICAL_REPOSITORY or type(pr) is not int or pr < 1:
        raise RunnerAuthorityError("target repository or PR is invalid")
    _require_pattern(expected_sha, _SHA, "expected SHA")
    _require_pattern(authority_source_sha, _SHA, "authority source SHA")
    if expected_sha == authority_source_sha:
        raise RunnerAuthorityError(
            "FAIL_CLOSED: PR workload cannot validate its own authority"
        )
    root = Path(checkout_root)
    if not root.is_absolute() or root.is_symlink():
        raise RunnerAuthorityError(
            "target checkout must be a canonical absolute directory"
        )
    try:
        resolved = root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise RunnerAuthorityError("target checkout is unavailable") from exc
    if resolved != root or not root.is_dir():
        raise RunnerAuthorityError("target checkout is redirected")
    if github_reader is None:
        if gh_binary is None:
            raise RunnerAuthorityError("trusted GitHub reader is unavailable")
        github_reader = lambda repo, number: _github_pr_snapshot(
            repo, number, gh_binary
        )

    def github_head() -> str:
        try:
            snapshot = github_reader(repository, pr)
        except Exception as exc:
            raise RunnerAuthorityError("GitHub PR HEAD is unavailable") from exc
        if not isinstance(snapshot, Mapping):
            raise RunnerAuthorityError("GitHub PR metadata is invalid")
        head = snapshot.get("head")
        base = snapshot.get("base")
        if (
            type(snapshot.get("number")) is not int
            or snapshot.get("number") != pr
            or snapshot.get("state") != "open"
            or snapshot.get("draft") is not False
            or not isinstance(head, Mapping)
            or not isinstance(base, Mapping)
            or not isinstance(head.get("repo"), Mapping)
            or not isinstance(base.get("repo"), Mapping)
            or head["repo"].get("full_name") != repository
            or base["repo"].get("full_name") != repository
            or base.get("ref") != "main"
        ):
            raise RunnerAuthorityError("GitHub PR identity or state is invalid")
        return _require_pattern(head.get("sha"), _SHA, "GitHub PR head SHA")

    first = github_head()
    if _control_plane_git(root, "rev-parse", "--show-toplevel") != str(root):
        raise RunnerAuthorityError("target checkout root differs")
    checked = _control_plane_git(root, "rev-parse", "HEAD")
    _reject_hidden_index_flags(root)
    if _control_plane_git(root, "status", "--porcelain", "--untracked-files=all"):
        raise RunnerAuthorityError("target checkout is dirty")
    second = github_head()
    if first != second:
        raise RunnerAuthorityError("STALE_SHA: GitHub PR HEAD changed during binding")
    if _control_plane_git(root, "rev-parse", "HEAD") != checked:
        raise RunnerAuthorityError("STALE_SHA: checkout HEAD changed during binding")
    _reject_hidden_index_flags(root)
    if _control_plane_git(root, "status", "--porcelain", "--untracked-files=all"):
        raise RunnerAuthorityError("target checkout changed during binding")
    return ExactTargetBinding(repository, pr, expected_sha, second, checked)


def identity_from_trusted_checkout(
    trusted_root: Path,
    authority_source_sha: str,
    runner_image: str,
    *,
    harbor_registry: str = DEFAULT_HARBOR_REGISTRY,
) -> AuthorityIdentity:
    """Hash committed authority inputs from a clean exact-source checkout.

    This checks byte identity, not approval. Activation separately requires the
    independently observed approved main SHA to match authority_source_sha.
    """
    _require_pattern(authority_source_sha, _SHA, "authority source SHA")
    root = Path(trusted_root)
    if not root.is_absolute() or root.is_symlink():
        raise RunnerAuthorityError(
            "trusted checkout must be a canonical absolute directory"
        )
    try:
        resolved = root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise RunnerAuthorityError("trusted checkout is unavailable") from exc
    if resolved != root or not root.is_dir():
        raise RunnerAuthorityError("trusted checkout is redirected")
    if _control_plane_git(root, "rev-parse", "--show-toplevel") != str(root):
        raise RunnerAuthorityError("trusted checkout root differs")
    if _control_plane_git(root, "rev-parse", "HEAD") != authority_source_sha:
        raise RunnerAuthorityError("trusted checkout differs from authority source SHA")
    _reject_hidden_index_flags(root)
    if _control_plane_git(root, "status", "--porcelain", "--untracked-files=all"):
        raise RunnerAuthorityError("trusted checkout is dirty")

    def committed_digest(relative: str, *, optional: bool = False) -> str | None:
        path = root
        for part in relative.split("/"):
            path = path / part
            if path.is_symlink():
                raise RunnerAuthorityError(f"authority input is a symlink: {relative}")
        if optional and not _control_plane_git(
            root, "ls-tree", "--full-tree", "HEAD", "--", relative
        ):
            return None
        if not path.is_file() or path.stat().st_size > 2_000_000:
            raise RunnerAuthorityError(
                f"authority input is missing or oversized: {relative}"
            )
        _control_plane_git(root, "ls-files", "--error-unmatch", "--", relative)
        blob = _control_plane_git(root, "rev-parse", f"HEAD:{relative}")
        if not re.fullmatch(r"[0-9a-f]{40,64}", blob):
            raise RunnerAuthorityError(f"authority input is not committed: {relative}")
        size_text = _control_plane_git(root, "cat-file", "-s", f"HEAD:{relative}")
        try:
            committed_size = int(size_text)
        except ValueError as exc:
            raise RunnerAuthorityError(
                f"authority input has invalid committed size: {relative}"
            ) from exc
        if committed_size < 0 or committed_size > 2_000_000:
            raise RunnerAuthorityError(f"authority input is oversized: {relative}")
        committed_bytes = _control_plane_git_bytes(
            root, "cat-file", "blob", f"HEAD:{relative}"
        )
        worktree_bytes = path.read_bytes()
        if len(committed_bytes) != committed_size or committed_bytes != worktree_bytes:
            raise RunnerAuthorityError(
                f"authority input bytes differ from committed HEAD: {relative}"
            )
        return "sha256:" + hashlib.sha256(committed_bytes).hexdigest()

    policy = committed_digest("config/contracts/qualification-execution-policy.yaml")
    validator = committed_digest("scripts/runner_authority.py")
    toolchain = committed_digest("config/contracts/toolchain-lock.json", optional=True)
    if _control_plane_git(root, "rev-parse", "HEAD") != authority_source_sha:
        raise RunnerAuthorityError(
            "authority source changed during identity construction"
        )
    return AuthorityIdentity(
        authority_source_sha,
        runner_image,
        policy,
        validator,
        toolchain,
        harbor_registry,
    )


def validate_authority_contract(policy: Mapping[str, object]) -> None:
    """Require the complete canonical runner-authority control contract.

    Equality is recursive and type-strict: integer 1 cannot impersonate true,
    reordered proof names cannot change the activation rule, and unknown keys
    cannot silently add an alternate authority path.
    """
    expected = {
        "runner_image": {
            "registry_authority": "harbor",
            "immutable_digest_required": True,
            "live_pull_proof_required": True,
        },
        "activation": {
            "required_proofs": list(REQUIRED_PROOFS),
            "pass_rule": "all",
            "missing": "NOT_ACTIVE",
        },
        "source": {
            "branch": "main",
            "merged_only": True,
            "self_validation": "forbidden",
        },
        "execution_budget": {
            "global_timeout_required": True,
            "subprocess_timeout_required": True,
            "cpu_limit_required": True,
            "memory_limit_required": True,
            "concurrency_limit_required": True,
            "descendants_cleanup_required": True,
            "aggregate_cgroup_limits_required": True,
            "pid_namespace_required": True,
        },
        "workload_secrets": "forbidden",
    }

    def exact(actual: object, required: object) -> bool:
        if type(actual) is not type(required):
            return False
        if isinstance(required, dict):
            return set(actual) == set(required) and all(
                exact(actual[key], value) for key, value in required.items()
            )
        if isinstance(required, list):
            return len(actual) == len(required) and all(
                exact(item, value) for item, value in zip(actual, required)
            )
        return actual == required

    if not isinstance(policy, Mapping) or not exact(
        policy.get("runner_authority"), expected
    ):
        raise RunnerAuthorityError("canonical runner authority contract is invalid")


def revalidate_exact_target(
    binding: ExactTargetBinding,
    checkout_root: Path,
    authority_source_sha: str,
    *,
    gh_binary: str | None = None,
    github_reader: Callable[[str, int], Mapping[str, object]] | None = None,
) -> ExactTargetBinding:
    """Re-read GitHub and checkout after a campaign before accepting its proof."""
    if not isinstance(binding, ExactTargetBinding):
        raise RunnerAuthorityError("exact PR binding is missing")
    current = resolve_exact_target(
        binding.repository,
        binding.pr,
        binding.expected_sha,
        checkout_root,
        authority_source_sha,
        gh_binary=gh_binary,
        github_reader=github_reader,
    )
    if current != binding:
        raise RunnerAuthorityError("STALE_SHA: exact PR binding changed")
    return current
