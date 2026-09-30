#!/usr/bin/env python3
"""Non-authoritative outbox for exact-PR ChatGPT review requests.

The transport can submit work and return text. Only a fresh, unedited GitHub
marker from the repository owner can establish a CODE or SECURITY result.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import subprocess
import tempfile
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

import yaml

if __package__:
    from .exact_pr_binding import (
        ExactPRBinding,
        ExactPRBindingChanged,
        revalidate_exact_open_pr,
    )
else:
    from exact_pr_binding import (
        ExactPRBinding,
        ExactPRBindingChanged,
        revalidate_exact_open_pr,
    )


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "config/contracts/chatgpt-review-dispatch-policy.yaml"
OUTBOX_ROOT = ROOT / ".context/review-dispatch"
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_LEGACY_BOOTSTRAP_SCOPE = (
    "dst-red-Wire/ecommerce-1",
    172,
    "main",
    "ced96d663c1dca1c885d450104f344c10431738d",
    "feat/controller-compat-bootstrap",
)
_REQUEST_KEYS = frozenset(
    {
        "schema_version",
        "event",
        "state",
        "provider",
        "review_kind",
        "repository",
        "pr",
        "base",
        "base_sha",
        "head_sha",
        "head_branch",
        "handoff",
        "handoff_bytes",
        "handoff_sha256",
        "expected_marker",
        "verdict_authority",
        "rerun",
    }
)
_STRUCTURED_HANDOFF_KEYS = frozenset(
    {
        "schema_version",
        "event",
        "provider",
        "verdict_authority",
        "repository",
        "pr",
        "review_kind",
        "base_sha",
        "head_sha",
        "tree_sha",
        "exact_head_verified",
        "changed_files",
        "qualification",
        "previous_validated_verdict",
        "previous_head",
        "delta",
        "handoff_sha256",
    }
)
_DELTA_COUNT_KEYS = frozenset(
    {
        "changed_file_count",
        "open_finding_count",
        "new_finding_count",
        "resolved_finding_count",
        "superseded_finding_count",
    }
)
_POLICY = {
    "version": 1,
    "provider": "ChatGPT",
    "event": "CHATGPT_REVIEW_REQUIRED",
    "handoff_max_bytes": 8192,
    "review_order": ["CODE", "SECURITY"],
    "verdict_authority": False,
    "transport_missing_state": "BLOCKED_EXTERNAL_REVIEW_TRANSPORT",
    "require_owner_unedited_marker": True,
}
_HANDOFF_END = (
    "Read only changed_files plus finding paths in delta and issue findings "
    "bound to current_head. Return the compact UX summary as five lines: "
    "PR #<number>; HEAD : <old> → <new or unchanged>; CHANGEMENT : <delta>; "
    "VERDICT : READY | BLOCKED | WAITING; ACTION : <one next action>.\n"
)


class ReviewDispatchError(ValueError):
    """The request, policy, binding, or saved outbox cannot be trusted."""


class ReviewResultError(ReviewDispatchError):
    """A fetched transport result failed its exact request binding."""


class ReviewTransport(Protocol):
    def submit(
        self, request: Mapping[str, Any], *, idempotency_key: str
    ) -> Mapping[str, Any]: ...
    def status(self, submission_id: str) -> Mapping[str, Any]: ...
    def fetch_result(self, submission_id: str) -> Mapping[str, Any]: ...


OwnerMarkerLookup = Callable[[ExactPRBinding, str], Mapping[str, Any] | None]
BindingRevalidator = Callable[[ExactPRBinding], ExactPRBinding]


def _sha(value: Any) -> bool:
    return isinstance(value, str) and _SHA.fullmatch(value) is not None


def _digest(value: Any) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def validate_legacy_bootstrap_binding(
    value: str | None, binding: ExactPRBinding
) -> None:
    """Validate explicit transport-only consent for this exact bootstrap PR."""
    if (
        not isinstance(binding, ExactPRBinding)
        or (
            binding.repository,
            binding.pr_number,
            binding.base,
            binding.base_sha,
            binding.head_branch,
        )
        != _LEGACY_BOOTSTRAP_SCOPE
        or not _sha(binding.head_sha)
        or type(value) is not str
        or value != f"{binding.base_sha}:{binding.head_sha}"
    ):
        raise ReviewDispatchError(
            "legacy handoff requires the explicit exact bootstrap base:head binding"
        )


def _handoff_protocol(
    request: Mapping[str, Any],
    binding: ExactPRBinding,
    legacy_bootstrap_binding: str | None,
) -> str:
    """Require invocation consent independently of any saved outbox record."""
    if legacy_bootstrap_binding is not None:
        validate_legacy_bootstrap_binding(legacy_bootstrap_binding, binding)
    if request["handoff"].startswith("{"):
        return "structured-v1"
    validate_legacy_bootstrap_binding(legacy_bootstrap_binding, binding)
    return "legacy-bootstrap"


def _load_policy(path: Path) -> dict[str, Any]:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ReviewDispatchError(
            "review dispatch policy is unavailable or malformed"
        ) from exc
    if not isinstance(value, dict) or value != _POLICY:
        raise ReviewDispatchError(
            "review dispatch policy violates required authority invariants"
        )
    return value


def _canonical_json(value: Mapping[str, Any]) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ReviewDispatchError("structured handoff is not canonical JSON") from exc


def _structured_handoff(
    payload: Any,
    binding: ExactPRBinding,
    budget: int,
    *,
    qualification_digest: str | None = None,
) -> str:
    """Validate v1 metadata independently of its producer and serialize it."""
    if type(payload) is not dict or set(payload) != _STRUCTURED_HANDOFF_KEYS:
        raise ReviewDispatchError("structured handoff v1 has invalid fields")
    qualification = payload["qualification"]
    evidence_digest = (
        qualification.get("evidence_digest") if type(qualification) is dict else None
    )
    if (
        type(payload["schema_version"]) is not int
        or payload["schema_version"] != 1
        or payload["event"] != "CHATGPT_REVIEW_REQUIRED"
        or payload["provider"] != "ChatGPT"
        or payload["verdict_authority"] is not False
        or payload["repository"] != binding.repository
        or type(payload["pr"]) is not int
        or payload["pr"] != binding.pr_number
        or type(payload["review_kind"]) is not str
        or payload["review_kind"] not in {"CODE", "SECURITY"}
        or payload["base_sha"] != binding.base_sha
        or payload["head_sha"] != binding.head_sha
        or not _sha(payload["tree_sha"])
        or payload["base_sha"] == payload["head_sha"]
        or payload["exact_head_verified"] is not True
        or type(qualification) is not dict
        or set(qualification) != {"status", "evidence_digest"}
        or qualification["status"] != "PASS"
        or not isinstance(evidence_digest, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", evidence_digest) is None
        or (
            qualification_digest is not None and evidence_digest != qualification_digest
        )
    ):
        raise ReviewDispatchError("structured handoff v1 is not bound to the exact PR")
    paths = payload["changed_files"]
    if type(paths) is not list or not 1 <= len(paths) <= 256:
        raise ReviewDispatchError("structured handoff changed_files is invalid")
    for path in paths:
        if type(path) is not str:
            raise ReviewDispatchError("structured handoff has an unsafe path")
        try:
            path_bytes = path.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise ReviewDispatchError("structured handoff has an unsafe path") from exc
        if (
            not path
            or path != path.strip()
            or len(path_bytes) > 512
            or path.startswith("/")
            or "\\" in path
            or ":" in path
            or any(ord(character) < 32 or ord(character) == 127 for character in path)
            or any(part in {"", ".", ".."} for part in path.split("/"))
            or str(PurePosixPath(path)) != path
        ):
            raise ReviewDispatchError("structured handoff has an unsafe path")
    if paths != sorted(set(paths)):
        raise ReviewDispatchError("structured handoff changed_files is not canonical")
    delta = payload["delta"]
    if (
        type(delta) is not dict
        or not set(delta) <= _DELTA_COUNT_KEYS
        or delta.get("changed_file_count") != len(paths)
        or any(
            type(count) is not int or not 0 <= count <= 1_000_000
            for count in delta.values()
        )
    ):
        raise ReviewDispatchError("structured handoff delta counts are invalid")
    prior = payload["previous_validated_verdict"]
    previous_head = payload["previous_head"]
    if (
        (
            prior is not None
            and (
                type(prior) is not str
                or prior not in {"CODE_PASS", "SECURITY_PASS", "READY"}
            )
        )
        or (previous_head is not None and not _sha(previous_head))
        or (prior is not None and previous_head is None)
        or (
            payload["review_kind"] == "SECURITY"
            and (prior != "CODE_PASS" or previous_head != binding.head_sha)
        )
    ):
        raise ReviewDispatchError("structured handoff lacks valid prior review context")
    internal_digest = payload["handoff_sha256"]
    unsigned = {key: value for key, value in payload.items() if key != "handoff_sha256"}
    if (
        not _digest(internal_digest)
        or hashlib.sha256(_canonical_json(unsigned).encode("ascii")).hexdigest()
        != internal_digest
    ):
        raise ReviewDispatchError("structured handoff internal digest mismatch")
    text = _canonical_json(payload)
    if not 0 < len(text.encode("ascii")) <= budget:
        raise ReviewDispatchError("structured handoff exceeds its byte budget")
    return text


def canonical_structured_handoff(
    payload: Any,
    binding: ExactPRBinding,
    *,
    qualification_digest: str,
) -> str:
    """Prepare v1 transport text from the exact-base controller result."""
    if not isinstance(qualification_digest, str):
        raise ReviewDispatchError("exact qualification digest is required")
    policy = _load_policy(POLICY_PATH)
    return _structured_handoff(
        payload,
        binding,
        int(policy["handoff_max_bytes"]),
        qualification_digest=qualification_digest,
    )


def _canonical_handoff(
    request: Mapping[str, Any], binding: ExactPRBinding, budget: int
) -> None:
    handoff = request["handoff"]
    if not isinstance(handoff, str) or not handoff:
        raise ReviewDispatchError("handoff must be nonempty UTF-8 text")
    try:
        encoded = handoff.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ReviewDispatchError("handoff is not valid UTF-8") from exc
    if not (0 < len(encoded) <= budget):
        raise ReviewDispatchError("handoff exceeds its configured byte budget")
    if type(request["handoff_bytes"]) is not int or request["handoff_bytes"] != len(
        encoded
    ):
        raise ReviewDispatchError("handoff byte count mismatch")
    if (
        not _digest(request["handoff_sha256"])
        or request["handoff_sha256"] != hashlib.sha256(encoded).hexdigest()
    ):
        raise ReviewDispatchError("handoff digest mismatch")
    if handoff.startswith("{"):
        try:
            payload = json.loads(handoff)
        except json.JSONDecodeError as exc:
            raise ReviewDispatchError("structured handoff JSON is malformed") from exc
        if _structured_handoff(payload, binding, budget) != handoff:
            raise ReviewDispatchError("structured handoff JSON is not canonical")
        if payload["review_kind"] != request["review_kind"]:
            raise ReviewDispatchError("structured handoff review kind differs")
        return
    instruction, separator, payload_text = handoff.rpartition("\n")
    if not separator or not payload_text:
        raise ReviewDispatchError("canonical handoff payload is missing")
    try:
        payload = json.loads(payload_text)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ReviewDispatchError("canonical handoff JSON is malformed") from exc
    expected_keys = {
        "pr",
        "review_kind",
        "previous_validated_verdict",
        "delta",
        "previous_head",
        "current_head",
        "changed_files",
        "exact_head_verified",
    }
    if (
        not isinstance(payload, dict)
        or not expected_keys.issubset(payload)
        or set(payload) - expected_keys not in (set(), {"truncated"})
        or payload.get("truncated", True) is not True
        or json.dumps(payload, separators=(",", ":"), sort_keys=True) != payload_text
        or type(payload["pr"]) is not int
        or payload["pr"] != request["pr"]
        or payload["review_kind"] != request["review_kind"]
        or payload["current_head"] != request["head_sha"]
        or not _sha(payload["previous_head"])
        or payload["exact_head_verified"] is not True
        or not isinstance(payload["previous_validated_verdict"], str)
        or not isinstance(payload["delta"], dict)
        or not isinstance(payload["changed_files"], list)
        or any(
            not isinstance(item, str) or not item or "\x00" in item
            for item in payload["changed_files"]
        )
    ):
        raise ReviewDispatchError("canonical handoff does not bind the exact request")
    prior = bool(payload["previous_validated_verdict"])
    reuse = (
        "Reuse the previous validated ChatGPT verdict and adjust only what this delta invalidates."
        if prior
        else "No previous validated ChatGPT verdict is available; review only this bounded delta."
    )
    kind = request["review_kind"]
    review_instruction = (
        "Perform only the requested CODE review. "
        if kind == "CODE"
        else "Perform only the requested SECURITY review; exact-SHA CODE is already PASS. "
    )
    expected_instruction = (
        "ChatGPT incremental exact-SHA PR review handoff. "
        "Do not reload PR history or repeat proven gates. "
        + reuse
        + " "
        + review_instruction
        + _HANDOFF_END
    )
    if instruction + "\n" != expected_instruction:
        raise ReviewDispatchError(
            "handoff instruction is not the canonical controller instruction"
        )
    if kind == "SECURITY" and (
        payload["previous_validated_verdict"] != "CODE_PASS"
        or payload["previous_head"] != request["head_sha"]
    ):
        raise ReviewDispatchError("SECURITY handoff lacks exact-SHA CODE context")


def _validate_request(
    request: Mapping[str, Any], binding: ExactPRBinding, policy: Mapping[str, Any]
) -> None:
    if not isinstance(request, dict) or set(request) != _REQUEST_KEYS:
        raise ReviewDispatchError("review_request v1 has unexpected or missing fields")
    if (
        type(request["schema_version"]) is not int
        or request["schema_version"] != 1
        or request["event"] != policy["event"]
        or request["state"] != policy["event"]
        or request["provider"] != policy["provider"]
        or request["review_kind"] not in policy["review_order"]
        or request["verdict_authority"] is not False
        or type(request["pr"]) is not int
        or request["pr"] <= 0
        or not isinstance(request["repository"], str)
        or _REPOSITORY.fullmatch(request["repository"]) is None
        or not _sha(request["base_sha"])
        or not _sha(request["head_sha"])
        or not isinstance(request["base"], str)
        or not request["base"]
        or not isinstance(request["head_branch"], str)
        or not request["head_branch"]
    ):
        raise ReviewDispatchError("review_request v1 metadata is invalid")
    for request_key, binding_key in (
        ("repository", "repository"),
        ("pr", "pr_number"),
        ("base", "base"),
        ("base_sha", "base_sha"),
        ("head_branch", "head_branch"),
        ("head_sha", "head_sha"),
    ):
        if request[request_key] != getattr(binding, binding_key):
            raise ReviewDispatchError(
                f"review_request does not match exact PR binding: {request_key}"
            )
    expected = request["expected_marker"]
    if (
        not isinstance(expected, dict)
        or type(expected.get("blocking_findings")) is not int
        or expected
        != {
            "provider": "ChatGPT",
            "kind": request["review_kind"].lower(),
            "head_sha": request["head_sha"],
            "status": "PASS",
            "blocking_findings": 0,
        }
    ):
        raise ReviewDispatchError(
            "expected marker is not the exact owner review contract"
        )
    rerun = request["rerun"]
    if (
        not isinstance(rerun, dict)
        or set(rerun) != {"argv", "command", "controller_source", "after_valid_marker"}
        or rerun["controller_source"] != "exact-pr-base-sha"
        or rerun["after_valid_marker"] is not True
        or not isinstance(rerun["argv"], list)
        or not rerun["argv"]
        or len(rerun["argv"]) > 32
        or any(
            not isinstance(arg, str) or not arg or "\x00" in arg
            for arg in rerun["argv"]
        )
        or not isinstance(rerun["command"], str)
        or not rerun["command"]
        or len(rerun["command"]) > 4096
    ):
        raise ReviewDispatchError("controller rerun metadata is malformed")
    _canonical_handoff(request, binding, int(policy["handoff_max_bytes"]))


def dispatch_identity(request: Mapping[str, Any]) -> str:
    """SHA-256 of repository, decimal PR, head, kind, handoff SHA joined by NUL."""
    return hashlib.sha256(
        "\x00".join(
            (
                request["repository"],
                str(request["pr"]),
                request["head_sha"],
                request["review_kind"],
                request["handoff_sha256"],
            )
        ).encode("utf-8")
    ).hexdigest()


def _assert_no_symlink(path: Path) -> None:
    for component in (path, *path.parents):
        if component.is_symlink():
            raise ReviewDispatchError("review dispatch path contains a symlink")


def _safe_dir(path: Path) -> None:
    _assert_no_symlink(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    _assert_no_symlink(path)
    if not path.is_dir():
        raise ReviewDispatchError("review dispatch outbox path is unsafe")


@contextmanager
def _pr_lock(pr_root: Path):
    _safe_dir(pr_root)
    lock_path = pr_root / ".dispatch.lock"
    if lock_path.is_symlink():
        raise ReviewDispatchError("review dispatch lock is a symlink")
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _write(path: Path, record: Mapping[str, Any]) -> None:
    _safe_dir(path.parent)
    data = (
        json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    )
    descriptor, temporary = tempfile.mkstemp(prefix=".dispatch-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        if path.is_symlink():
            raise ReviewDispatchError("review dispatch record is a symlink")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _read(path: Path, identity: str) -> dict[str, Any]:
    if path.is_symlink():
        raise ReviewDispatchError("review dispatch record is a symlink")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReviewDispatchError("review dispatch record is malformed") from exc
    if (
        not isinstance(value, dict)
        or value.get("identity") != identity
        or value.get("verdict_authority") is not False
        or type(value.get("schema_version")) is not int
        or value["schema_version"] != 1
        or not isinstance(value.get("request"), dict)
        or set(value["request"]) != _REQUEST_KEYS
    ):
        raise ReviewDispatchError("review dispatch record identity is invalid")
    request = value["request"]
    try:
        binding = ExactPRBinding.from_dict(
            {
                "repository": request["repository"],
                "pr_number": request["pr"],
                "base": request["base"],
                "base_sha": request["base_sha"],
                "head_branch": request["head_branch"],
                "head_sha": request["head_sha"],
            }
        )
        _validate_request(request, binding, _POLICY)
        structured = request["handoff"].startswith("{")
        if "handoff_protocol" not in value and "legacy_bootstrap_binding" not in value:
            # Historical data can be read or superseded without invocation consent.
            value["handoff_protocol"] = (
                "structured-v1" if structured else "legacy-historical"
            )
            value["legacy_bootstrap_binding"] = None
        protocol = value.get("handoff_protocol")
        if "legacy_bootstrap_binding" not in value:
            raise ReviewDispatchError("review dispatch protocol trace is incomplete")
        if structured:
            if (
                protocol != "structured-v1"
                or value["legacy_bootstrap_binding"] is not None
            ):
                raise ReviewDispatchError("review dispatch protocol trace was changed")
        elif protocol == "legacy-historical":
            if value["legacy_bootstrap_binding"] is not None:
                raise ReviewDispatchError(
                    "historical legacy record claims an exception"
                )
        elif protocol == "legacy-bootstrap":
            validate_legacy_bootstrap_binding(
                value["legacy_bootstrap_binding"], binding
            )
        else:
            raise ReviewDispatchError("review dispatch protocol trace was changed")
        if dispatch_identity(request) != identity or any(
            value.get(key) != request[key]
            for key in ("repository", "pr", "head_sha", "review_kind", "handoff_sha256")
        ):
            raise ReviewDispatchError("review dispatch request or metadata was changed")
    except (RuntimeError, TypeError, ValueError, KeyError) as exc:
        raise ReviewDispatchError(
            "review dispatch record request is malformed"
        ) from exc
    return value


def _revalidated_binding(
    binding: ExactPRBinding, revalidate: BindingRevalidator
) -> tuple[ExactPRBinding | None, str | None]:
    try:
        current = revalidate(binding)
    except ExactPRBindingChanged as exc:
        if exc.reason == "HEAD_CHANGED" and _sha(exc.current_head_sha):
            return None, exc.current_head_sha
        raise ReviewDispatchError("exact PR binding changed before dispatch") from exc
    if not isinstance(current, ExactPRBinding) or current != binding:
        raise ReviewDispatchError("exact PR binding changed before dispatch")
    return current, None


def _superseded_request(
    path: Path,
    identity: str,
    head_sha: str,
    current_head_sha: str,
    record: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if record is not None:
        record["state"] = "SUPERSEDED"
        record["reason"] = "HEAD_CHANGED"
        record["superseded_by_head_sha"] = current_head_sha
        _write(path, record)
    return {
        "schema_version": 1,
        "identity": identity,
        "state": "SUPERSEDED",
        "reason": "HEAD_CHANGED",
        "verdict_authority": False,
        "head_sha": head_sha,
        "superseded_by_head_sha": current_head_sha,
        "outbox_path": str(path) if record is not None else "",
    }


def _supersede_old_heads(pr_root: Path, head_sha: str) -> None:
    for head_dir in pr_root.iterdir():
        if head_dir.name == head_sha or head_dir.name.startswith("."):
            continue
        if head_dir.is_symlink():
            raise ReviewDispatchError("review dispatch prior head path is a symlink")
        if not head_dir.is_dir() or not _sha(head_dir.name):
            raise ReviewDispatchError("review dispatch prior head path is invalid")
        for kind_dir in head_dir.iterdir():
            if (
                kind_dir.is_symlink()
                or kind_dir.name not in {"CODE", "SECURITY"}
                or not kind_dir.is_dir()
            ):
                raise ReviewDispatchError("review dispatch prior kind path is invalid")
            for item in kind_dir.iterdir():
                if (
                    item.is_symlink()
                    or item.suffix != ".json"
                    or not _digest(item.stem)
                ):
                    raise ReviewDispatchError(
                        "review dispatch prior record path is invalid"
                    )
                record = _read(item, item.stem)
                if record.get("state") != "SUPERSEDED":
                    record["state"] = "SUPERSEDED"
                    record["superseded_by_head_sha"] = head_sha
                    _write(item, record)


def _unique_marker_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    marker: dict[str, Any] = {}
    for key, value in pairs:
        if key in marker:
            raise ValueError("duplicate owner marker field")
        marker[key] = value
    return marker


def github_owner_marker_lookup(
    binding: ExactPRBinding,
    kind: str,
    *,
    gh: str = "gh",
) -> dict[str, Any] | None:
    """Read latest exact-SHA owner marker from paginated PR conversation comments.

    This observes GitHub evidence. The trusted base controller rechecks review
    authority independently before any merge or privileged operation.
    """
    if not isinstance(binding, ExactPRBinding) or kind not in {"code", "security"}:
        raise ReviewDispatchError("owner marker lookup requires exact PR and kind")
    try:
        response = subprocess.run(
            [
                gh,
                "api",
                "--paginate",
                "--slurp",
                f"repos/{binding.repository}/issues/{binding.pr_number}/comments?per_page=100",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReviewDispatchError("GitHub owner marker lookup is unavailable") from exc
    if response.returncode != 0 or len(response.stdout) > 2_000_000:
        raise ReviewDispatchError(
            "GitHub owner marker lookup failed or exceeded its budget"
        )
    try:
        pages = json.loads(response.stdout)
    except json.JSONDecodeError as exc:
        raise ReviewDispatchError("GitHub owner marker comments are malformed") from exc
    if not isinstance(pages, list) or any(not isinstance(page, list) for page in pages):
        raise ReviewDispatchError("GitHub owner marker pagination is malformed")
    owner = binding.repository.split("/", 1)[0]
    candidates: list[tuple[str, int, dict[str, Any]]] = []
    prefix = "<!-- chatgpt-exact-sha-review:v1 "
    for page in pages:
        for comment in page:
            if not isinstance(comment, dict):
                raise ReviewDispatchError("GitHub owner marker comment is malformed")
            author = comment.get("user")
            if not isinstance(author, dict) or author.get("login") != owner:
                continue
            body = comment.get("body")
            if not isinstance(body, str):
                raise ReviewDispatchError("GitHub owner marker body is malformed")
            marker_lines = [
                line
                for line in body.splitlines()
                if re.search(r"<!--\s*chatgpt-exact-sha-review:v1", line)
            ]
            if not marker_lines:
                continue
            if len(marker_lines) != 1:
                raise ReviewDispatchError(
                    "owner comment contains multiple review markers"
                )
            line = marker_lines[0]
            if (
                not line.startswith(prefix)
                or not line.endswith(" -->")
                or line.count(prefix) != 1
            ):
                raise ReviewDispatchError("owner review marker line is malformed")
            try:
                marker_text = line[len(prefix) : -len(" -->")]
                marker = json.loads(
                    marker_text, object_pairs_hook=_unique_marker_fields
                )
            except (json.JSONDecodeError, ValueError) as exc:
                raise ReviewDispatchError(
                    "owner review marker JSON is malformed"
                ) from exc
            if not isinstance(marker, dict) or set(marker) != {
                "provider",
                "kind",
                "head_sha",
                "status",
                "blocking_findings",
            }:
                raise ReviewDispatchError("owner review marker schema is malformed")
            if (
                marker["provider"] != "ChatGPT"
                or marker["kind"] not in {"code", "security"}
                or not _sha(marker["head_sha"])
                or type(marker["blocking_findings"]) is not int
                or not (
                    (marker["status"] == "PASS" and marker["blocking_findings"] == 0)
                    or (
                        marker["status"] in {"BLOCKED", "FAIL"}
                        and marker["blocking_findings"] > 0
                    )
                )
            ):
                raise ReviewDispatchError("owner review marker values are malformed")
            if marker["kind"] != kind or marker["head_sha"] != binding.head_sha:
                continue
            comment_id = comment.get("id")
            created = comment.get("created_at")
            updated = comment.get("updated_at")
            if (
                type(comment_id) is not int
                or comment_id <= 0
                or not isinstance(created, str)
                or re.fullmatch(
                    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", created
                )
                is None
                or not isinstance(updated, str)
            ):
                raise ReviewDispatchError("owner review marker metadata is malformed")
            candidates.append(
                (
                    created,
                    comment_id,
                    {
                        **marker,
                        "pr": binding.pr_number,
                        "repository": binding.repository,
                        "owner_login": owner,
                        "author_login": owner,
                        "comment_id": comment_id,
                        "created_at": created,
                        "updated_at": updated,
                        "is_latest_for_kind": True,
                    },
                )
            )
    if not candidates:
        return None
    proof = max(candidates, key=lambda item: (item[0], item[1]))[2]
    if proof["updated_at"] != proof["created_at"]:
        raise ReviewDispatchError("latest owner review marker was edited")
    return proof


def _owner_proof(
    lookup: OwnerMarkerLookup | None,
    binding: ExactPRBinding,
    kind: str,
) -> dict[str, Any] | None:
    if lookup is None:
        return None
    proof = lookup(binding, kind.lower())
    if proof is None:
        return None
    owner = binding.repository.split("/", 1)[0]
    if (
        not isinstance(proof, dict)
        or proof.get("provider") != "ChatGPT"
        or proof.get("kind") != kind.lower()
        or proof.get("head_sha") != binding.head_sha
        or proof.get("pr") != binding.pr_number
        or proof.get("repository") != binding.repository
        or proof.get("owner_login") != owner
        or proof.get("author_login") != owner
        or type(proof.get("comment_id")) is not int
        or proof["comment_id"] <= 0
        or not isinstance(proof.get("created_at"), str)
        or re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
            proof["created_at"],
        )
        is None
        or proof.get("updated_at") != proof["created_at"]
        or proof.get("is_latest_for_kind") is not True
        or type(proof.get("blocking_findings")) is not int
        or not (
            (proof.get("status") == "PASS" and proof["blocking_findings"] == 0)
            or (
                proof.get("status") in {"BLOCKED", "FAIL"}
                and proof["blocking_findings"] > 0
            )
        )
    ):
        raise ReviewDispatchError(
            "owner marker adapter returned invalid exact-SHA proof"
        )
    return proof


def _transport_result(result: Any, record: Mapping[str, Any]) -> str:
    if (
        not isinstance(result, dict)
        or set(result)
        != {
            "submission_id",
            "identity",
            "provider",
            "kind",
            "pr",
            "head_sha",
            "status",
            "blocking_findings",
            "output",
        }
        or result["submission_id"] != record["submission_id"]
        or result["identity"] != record["identity"]
        or result["provider"] != "ChatGPT"
        or result["kind"] != record["review_kind"].lower()
        or type(result["pr"]) is not int
        or result["pr"] != record["pr"]
        or result["head_sha"] != record["head_sha"]
        or type(result["blocking_findings"]) is not int
        or not (
            (result["status"] == "PASS" and result["blocking_findings"] == 0)
            or (result["status"] == "FAIL" and result["blocking_findings"] > 0)
        )
        or not isinstance(result["output"], str)
        or not result["output"]
    ):
        raise ReviewResultError("external review result is malformed or misbound")
    try:
        encoded = result["output"].encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ReviewResultError("external review result is not valid UTF-8") from exc
    if len(encoded) > 65536:
        raise ReviewResultError("external review result exceeds the byte limit")
    return hashlib.sha256(encoded).hexdigest()


def _advance_transport(
    request: Mapping[str, Any],
    record: dict[str, Any],
    transport: ReviewTransport,
) -> None:
    submission_id = record.get("submission_id")
    if not submission_id:
        submitted = transport.submit(request, idempotency_key=record["identity"])
        if (
            not isinstance(submitted, dict)
            or set(submitted) != {"submission_id"}
            or not isinstance(submitted["submission_id"], str)
            or not (0 < len(submitted["submission_id"]) <= 200)
            or "\x00" in submitted["submission_id"]
        ):
            raise ReviewDispatchError("external transport submission is malformed")
        submission_id = submitted["submission_id"]
        record["submission_id"] = submission_id
        record["state"] = "REQUESTED"
        record["reason"] = "TRANSPORT_SUBMITTED"
        return
    status = transport.status(submission_id)
    if (
        not isinstance(status, dict)
        or set(status) != {"submission_id", "state"}
        or status["submission_id"] != submission_id
        or status["state"] not in {"QUEUED", "RUNNING", "COMPLETED", "FAILED"}
    ):
        raise ReviewDispatchError("external transport status is malformed")
    state = status["state"]
    if state == "FAILED":
        record["state"] = "BLOCKED"
        record["reason"] = "EXTERNAL_REVIEW_FAILED"
    elif state in {"QUEUED", "RUNNING"}:
        record["state"] = "REQUESTED" if state == "QUEUED" else "RUNNING"
        record["reason"] = "TRANSPORT_" + state
    else:
        try:
            record["result_sha256"] = _transport_result(
                transport.fetch_result(submission_id), record
            )
        except ReviewResultError:
            record["state"] = "BLOCKED"
            record["reason"] = "BLOCKED_EXTERNAL_REVIEW_RESULT"
            return
        record["state"] = "BLOCKED"
        record["reason"] = "AWAITING_OWNER_MARKER"


def dispatch_review_request(
    request: Mapping[str, Any],
    *,
    binding: ExactPRBinding,
    legacy_bootstrap_binding: str | None = None,
    transport: ReviewTransport | None = None,
    outbox_root: Path = OUTBOX_ROOT,
    policy_path: Path = POLICY_PATH,
    owner_marker_lookup: OwnerMarkerLookup | None = None,
    binding_revalidator: BindingRevalidator | None = None,
    gh: str = "gh",
) -> dict[str, Any]:
    """Validate, dispatch at most once per identity, and return non-authoritative state.

    The caller must supply an independently resolved exact PR binding. The
    revalidator rereads GitHub immediately before any outbox or transport work.
    `owner_marker_lookup` must return latest owner-authored, unedited PR proof;
    a transport result and an outbox record can never authorize a review.
    """
    policy = _load_policy(Path(policy_path))
    if not isinstance(binding, ExactPRBinding):
        raise ReviewDispatchError("exact PR binding is required")
    _validate_request(request, binding, policy)
    protocol = _handoff_protocol(request, binding, legacy_bootstrap_binding)
    trace_binding = legacy_bootstrap_binding if protocol == "legacy-bootstrap" else None
    identity = dispatch_identity(request)
    root = Path(outbox_root).absolute()
    _assert_no_symlink(root)
    pr_root = root / str(request["pr"])
    path = pr_root / request["head_sha"] / request["review_kind"] / f"{identity}.json"
    revalidate = binding_revalidator or (
        lambda value: revalidate_exact_open_pr(value, gh=gh)
    )
    current, changed_head = _revalidated_binding(binding, revalidate)
    if changed_head is not None:
        if path.exists():
            with _pr_lock(pr_root):
                record = _read(path, identity)
                return _superseded_request(
                    path, identity, request["head_sha"], changed_head, record
                )
        return _superseded_request(path, identity, request["head_sha"], changed_head)
    with _pr_lock(pr_root):
        current, changed_head = _revalidated_binding(binding, revalidate)
        if changed_head is not None:
            record = _read(path, identity) if path.exists() else None
            return _superseded_request(
                path, identity, request["head_sha"], changed_head, record
            )
        _supersede_old_heads(pr_root, request["head_sha"])
        if path.exists():
            record = _read(path, identity)
            if (
                record.get("request") == request
                and record.get("handoff_protocol") == "legacy-historical"
                and protocol == "legacy-bootstrap"
            ):
                # Fresh explicit consent was validated before any outbox read.
                # Preserve submission metadata to avoid submitting the same work twice.
                record["handoff_protocol"] = protocol
                record["legacy_bootstrap_binding"] = trace_binding
            if (
                record.get("request") != request
                or record.get("handoff_protocol") != protocol
                or record.get("legacy_bootstrap_binding") != trace_binding
            ):
                raise ReviewDispatchError(
                    "review dispatch record does not match request"
                )
        else:
            record = {
                "schema_version": 1,
                "identity": identity,
                "repository": request["repository"],
                "pr": request["pr"],
                "head_sha": request["head_sha"],
                "review_kind": request["review_kind"],
                "handoff_sha256": request["handoff_sha256"],
                "request": dict(request),
                "handoff_protocol": protocol,
                "legacy_bootstrap_binding": trace_binding,
                "state": "NOT_REQUESTED",
                "reason": "",
                "submission_id": "",
                "result_sha256": "",
                "verdict_authority": False,
            }
        kind = request["review_kind"]
        if kind == "SECURITY":
            code = _owner_proof(owner_marker_lookup, current, "CODE")
            if code is None:
                record["state"] = "BLOCKED"
                record["reason"] = "WAITING_CODE_REVIEW"
                _write(path, record)
                return {**record, "outbox_path": str(path)}
            if code["status"] != "PASS":
                record["state"] = "BLOCKED"
                record["reason"] = "CODE_REVIEW_FAILED"
                _write(path, record)
                return {**record, "outbox_path": str(path)}
            record["code_comment_id"] = code["comment_id"]
        proof = _owner_proof(owner_marker_lookup, current, kind)
        if proof is not None:
            _, changed_head = _revalidated_binding(binding, revalidate)
            if changed_head is not None:
                return _superseded_request(
                    path, identity, request["head_sha"], changed_head, record
                )
            if kind == "SECURITY" and (proof["created_at"], proof["comment_id"]) <= (
                code["created_at"],
                code["comment_id"],
            ):
                record.pop("owner_comment_id", None)
                record["state"] = "BLOCKED"
                record["reason"] = "SECURITY_REVIEW_PREDATES_CODE"
                _write(path, record)
                return {**record, "outbox_path": str(path)}
            record["state"] = "PASS" if proof["status"] == "PASS" else "FAIL"
            record["reason"] = "OWNER_MARKER_VERIFIED"
            record["owner_comment_id"] = proof["comment_id"]
            _write(path, record)
            return {**record, "outbox_path": str(path)}
        record.pop("owner_comment_id", None)
        if record.get("result_sha256"):
            record["state"] = "BLOCKED"
            record["reason"] = "AWAITING_OWNER_MARKER"
        elif transport is None:
            record["state"] = "BLOCKED"
            record["reason"] = policy["transport_missing_state"]
        else:
            if not record.get("submission_id"):
                _, changed_head = _revalidated_binding(binding, revalidate)
                if changed_head is not None:
                    return _superseded_request(
                        path, identity, request["head_sha"], changed_head, record
                    )
            try:
                _advance_transport(request, record, transport)
            except (OSError, RuntimeError, TypeError, ValueError, KeyError):
                record["state"] = "BLOCKED"
                record["reason"] = "BLOCKED_EXTERNAL_REVIEW_TRANSPORT"
        _write(path, record)
        return {**record, "outbox_path": str(path)}


def dispatch_status(
    binding: ExactPRBinding,
    kind: str,
    *,
    outbox_root: Path = OUTBOX_ROOT,
    binding_revalidator: BindingRevalidator | None = None,
    gh: str = "gh",
) -> dict[str, Any]:
    """Read local dispatch records; never infer a review verdict from them."""
    _load_policy(POLICY_PATH)
    if not isinstance(binding, ExactPRBinding) or kind not in {"CODE", "SECURITY"}:
        raise ReviewDispatchError("dispatch status requires exact PR and review kind")
    revalidate = binding_revalidator or (
        lambda value: revalidate_exact_open_pr(value, gh=gh)
    )
    try:
        current = revalidate(binding)
    except ExactPRBindingChanged as exc:
        if exc.reason == "HEAD_CHANGED" and _sha(exc.current_head_sha):
            return {
                "state": "SUPERSEDED",
                "reason": "HEAD_CHANGED",
                "repository": binding.repository,
                "pr": binding.pr_number,
                "head_sha": binding.head_sha,
                "review_kind": kind,
                "current_head_sha": exc.current_head_sha,
                "records": [],
                "verdict_authority": False,
            }
        raise ReviewDispatchError(
            "exact PR binding changed before status read"
        ) from exc
    if current != binding:
        raise ReviewDispatchError("exact PR binding changed before status read")
    root = Path(outbox_root).absolute()
    kind_root = root / str(binding.pr_number) / binding.head_sha / kind
    _assert_no_symlink(kind_root)
    records: list[tuple[int, dict[str, Any]]] = []
    if kind_root.exists():
        if not kind_root.is_dir():
            raise ReviewDispatchError("review dispatch status path is not a directory")
        for path in kind_root.iterdir():
            if path.is_symlink() or path.suffix != ".json" or not _digest(path.stem):
                raise ReviewDispatchError(
                    "review dispatch status record path is invalid"
                )
            record = _read(path, path.stem)
            if (
                record.get("repository") != binding.repository
                or record.get("pr") != binding.pr_number
                or record.get("head_sha") != binding.head_sha
                or record.get("review_kind") != kind
            ):
                raise ReviewDispatchError("review dispatch status record is misbound")
            records.append(
                (path.stat().st_mtime_ns, {**record, "outbox_path": str(path)})
            )
            if len(records) > 1000:
                raise ReviewDispatchError(
                    "review dispatch status exceeds record budget"
                )
    records.sort(key=lambda item: (-item[0], item[1]["identity"]))
    visible = [record for _, record in records]
    return {
        "state": visible[0]["state"] if visible else "NOT_REQUESTED",
        "reason": visible[0].get("reason", "") if visible else "",
        "repository": binding.repository,
        "pr": binding.pr_number,
        "head_sha": binding.head_sha,
        "review_kind": kind,
        "records": visible,
        "verdict_authority": False,
    }
