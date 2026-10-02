"""Resolve one open pull request for the canonical repository and exact source commit.

This is a read-only GitHub REST authority. Call revalidate_exact_open_pr immediately
before an operation whose authorization depends on the binding.
"""

from __future__ import annotations

import json
import os
import pwd
import re
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

CANONICAL_REPOSITORY = "dst-red-Wire/ecommerce-1"
CANONICAL_BASE = "main"
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_PAGE_SIZE = 100
_MAX_PAGES = 100


class ExactPRBindingError(RuntimeError):
    """The exact open pull request could not be established."""


class ExactPRBindingChanged(ExactPRBindingError):
    """A previously bound PR changed while waiting for authorization."""

    def __init__(self, reason: str, *, current_head_sha: str | None = None):
        self.reason = reason
        self.current_head_sha = current_head_sha
        super().__init__(f"exact PR binding changed: {reason}")


@dataclass(frozen=True, slots=True)
class ExactPRBinding:
    repository: str
    pr_number: int
    base: str
    base_sha: str
    head_branch: str
    head_sha: str

    def as_dict(self) -> dict[str, str | int]:
        """Return a JSON-compatible copy of this immutable binding."""
        return {
            "repository": self.repository,
            "pr_number": self.pr_number,
            "base": self.base,
            "base_sha": self.base_sha,
            "head_branch": self.head_branch,
            "head_sha": self.head_sha,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> ExactPRBinding:
        """Decode persisted JSON without accepting missing or extra authority fields."""
        fields = {
            "repository",
            "pr_number",
            "base",
            "base_sha",
            "head_branch",
            "head_sha",
        }
        if not isinstance(value, Mapping) or set(value) != fields:
            raise ExactPRBindingError("invalid exact PR binding fields")
        repository = value["repository"]
        number = value["pr_number"]
        base = value["base"]
        base_sha = value["base_sha"]
        branch = value["head_branch"]
        head_sha = value["head_sha"]
        _validate_inputs(repository, head_sha, branch, base, base_sha)
        if type(number) is not int or number < 1:
            raise ExactPRBindingError("invalid exact PR number")
        return cls(repository, number, base, base_sha, branch, head_sha)


def _validate_inputs(
    repository: object,
    source_sha: object,
    branch: object,
    base: object,
    base_sha: object,
) -> None:
    if repository != CANONICAL_REPOSITORY:
        raise ExactPRBindingError("repository is not the canonical repository")
    if base != CANONICAL_BASE:
        raise ExactPRBindingError("base is not canonical main")
    if not isinstance(source_sha, str) or _SHA.fullmatch(source_sha) is None:
        raise ExactPRBindingError("source SHA must be a full lowercase commit SHA")
    if (
        not isinstance(branch, str)
        or not branch
        or branch != branch.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in branch)
    ):
        raise ExactPRBindingError("head branch is invalid")
    if base_sha is not None and (
        not isinstance(base_sha, str) or _SHA.fullmatch(base_sha) is None
    ):
        raise ExactPRBindingError(
            "expected base SHA must be a full lowercase commit SHA"
        )


def _safe_gh_environment(source: Mapping[str, str] | None = None) -> dict[str, str]:
    """Keep owner auth available to pinned gh without inheriting Git execution knobs."""
    source = os.environ if source is None else source
    home = pwd.getpwuid(os.getuid()).pw_dir
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": home,
        "XDG_CONFIG_HOME": str(Path(home) / ".config"),
        "GH_CONFIG_DIR": str(Path(home) / ".config/gh"),
        "GH_PROMPT_DISABLED": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_COUNT": "5",
        "GIT_CONFIG_KEY_0": "core.fsmonitor",
        "GIT_CONFIG_VALUE_0": "false",
        "GIT_CONFIG_KEY_1": "core.hooksPath",
        "GIT_CONFIG_VALUE_1": "/dev/null",
        "GIT_CONFIG_KEY_2": "credential.helper",
        "GIT_CONFIG_VALUE_2": "",
        "GIT_CONFIG_KEY_3": "protocol.ext.allow",
        "GIT_CONFIG_VALUE_3": "never",
        "GIT_CONFIG_KEY_4": "core.sshCommand",
        "GIT_CONFIG_VALUE_4": "/bin/false",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/false",
    }
    for name in (
        "GH_TOKEN", "GITHUB_TOKEN", "GH_HOST", "LANG", "LC_ALL",
        "LC_CTYPE", "TZ", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY",
        "https_proxy", "http_proxy", "no_proxy",
    ):
        value = source.get(name)
        if value:
            environment[name] = value
    return environment


def _api(
    gh: str, endpoint: str, *, env: Mapping[str, str] | None = None
) -> object:
    try:
        result = subprocess.run(
            [gh, "api", endpoint],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
            env=_safe_gh_environment(env),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ExactPRBindingError(f"GitHub API request failed: {endpoint}") from exc
    if result.returncode != 0:
        raise ExactPRBindingError(f"GitHub API request failed: {endpoint}")
    try:
        return json.loads(result.stdout)
    except (TypeError, ValueError) as exc:
        raise ExactPRBindingError(
            f"GitHub API returned invalid JSON: {endpoint}"
        ) from exc


def _object(value: object, label: str) -> dict:
    if not isinstance(value, dict):
        raise ExactPRBindingError(f"GitHub API returned invalid {label}")
    return value


def _current_base_sha(gh: str, repository: str, base: str) -> str:
    payload = _object(_api(gh, f"repos/{repository}/branches/{base}"), "base branch")
    if payload.get("name") != base:
        raise ExactPRBindingError("GitHub API returned the wrong base branch")
    commit = _object(payload.get("commit"), "base branch commit")
    sha = commit.get("sha")
    if not isinstance(sha, str) or _SHA.fullmatch(sha) is None:
        raise ExactPRBindingError("GitHub API returned an invalid base branch SHA")
    return sha


def _matching_open_pr_numbers(
    gh: str, repository: str, source_sha: str, branch: str, base: str
) -> list[int]:
    matches: list[int] = []
    for page in range(1, _MAX_PAGES + 1):
        endpoint = (
            f"repos/{repository}/pulls?state=open&per_page={_PAGE_SIZE}&page={page}"
        )
        payload = _api(gh, endpoint)
        if not isinstance(payload, list) or len(payload) > _PAGE_SIZE:
            raise ExactPRBindingError("GitHub API returned an invalid open PR page")
        for item in payload:
            pr = _object(item, "open PR list item")
            head = _object(pr.get("head"), "open PR head")
            pr_base = _object(pr.get("base"), "open PR base")
            if (
                head.get("ref") == branch
                and head.get("sha") == source_sha
                and pr_base.get("ref") == base
            ):
                number = pr.get("number")
                if type(number) is not int or number < 1:
                    raise ExactPRBindingError(
                        "GitHub API returned an invalid PR number"
                    )
                matches.append(number)
        if len(payload) < _PAGE_SIZE:
            return matches
    raise ExactPRBindingError("open PR pagination exceeded its safety limit")


def _binding_from_pr(
    payload: object,
    repository: str,
    number: int,
    source_sha: str,
    branch: str,
    base: str,
    base_sha: str,
) -> ExactPRBinding:
    pr = _object(payload, "PR detail")
    pr_base = _object(pr.get("base"), "PR base")
    head = _object(pr.get("head"), "PR head")
    base_repo = _object(pr_base.get("repo"), "PR base repository")
    head_repo = _object(head.get("repo"), "PR head repository")
    if type(pr.get("number")) is not int or pr["number"] != number:
        raise ExactPRBindingError("PR detail number differs from the open PR list")
    if (
        pr.get("state") != "open"
        or pr.get("draft") is not False
        or "merged_at" not in pr
        or pr.get("merged_at") is not None
        or pr.get("merged") is not False
    ):
        raise ExactPRBindingError("exact PR is closed, merged, or draft")
    if (
        base_repo.get("full_name") != repository
        or head_repo.get("full_name") != repository
    ):
        raise ExactPRBindingError("exact PR is not within the canonical repository")
    if pr_base.get("ref") != base or pr_base.get("sha") != base_sha:
        raise ExactPRBindingError("exact PR base branch or SHA changed")
    if head.get("ref") != branch or head.get("sha") != source_sha:
        raise ExactPRBindingError("exact PR head branch or SHA changed")
    return ExactPRBinding(repository, number, base, base_sha, branch, source_sha)


def resolve_exact_open_pr(
    repository: str,
    source_sha: str,
    branch: str,
    base: str,
    base_sha: str | None = None,
    *,
    gh: str = "gh",
) -> ExactPRBinding:
    """Find the unique non-draft, same-repository open PR for the exact source.

    An omitted base_sha is read from the current GitHub base branch. If given,
    it must still match that current branch. Any API, schema, cardinality, or
    identity mismatch raises ExactPRBindingError.
    """
    _validate_inputs(repository, source_sha, branch, base, base_sha)
    if not isinstance(gh, str) or not gh:
        raise ExactPRBindingError("GitHub CLI executable is invalid")
    current_base_sha = _current_base_sha(gh, repository, base)
    if base_sha is not None and base_sha != current_base_sha:
        raise ExactPRBindingError("expected base SHA differs from current main")
    numbers = _matching_open_pr_numbers(gh, repository, source_sha, branch, base)
    if len(numbers) != 1:
        raise ExactPRBindingError(
            f"expected exactly one open PR for the exact source; found {len(numbers)}"
        )
    number = numbers[0]
    detail = _api(gh, f"repos/{repository}/pulls/{number}")
    binding = _binding_from_pr(
        detail, repository, number, source_sha, branch, base, current_base_sha
    )
    if _current_base_sha(gh, repository, base) != current_base_sha:
        raise ExactPRBindingError("base branch changed while resolving exact PR")
    return binding


def revalidate_exact_open_pr(
    binding: ExactPRBinding | Mapping[str, object], *, gh: str = "gh"
) -> ExactPRBinding:
    """Re-read GitHub and require the same unique PR and every bound field."""
    expected = ExactPRBinding.from_dict(
        binding.as_dict() if isinstance(binding, ExactPRBinding) else binding
    )
    snapshot = _object(
        _api(gh, f"repos/{expected.repository}/pulls/{expected.pr_number}"),
        "bound PR detail",
    )
    if (
        type(snapshot.get("number")) is not int
        or snapshot["number"] != expected.pr_number
    ):
        raise ExactPRBindingError("bound PR detail number changed")
    head = _object(snapshot.get("head"), "bound PR head")
    pr_base = _object(snapshot.get("base"), "bound PR base")
    current_head_sha = head.get("sha")
    if (
        not isinstance(current_head_sha, str)
        or _SHA.fullmatch(current_head_sha) is None
    ):
        raise ExactPRBindingError("bound PR has an invalid head SHA")
    if current_head_sha != expected.head_sha:
        raise ExactPRBindingChanged("HEAD_CHANGED", current_head_sha=current_head_sha)
    if head.get("ref") != expected.head_branch:
        raise ExactPRBindingChanged("BRANCH_CHANGED", current_head_sha=current_head_sha)
    if pr_base.get("sha") != expected.base_sha:
        raise ExactPRBindingChanged("BASE_CHANGED", current_head_sha=current_head_sha)
    fresh = resolve_exact_open_pr(
        expected.repository,
        expected.head_sha,
        expected.head_branch,
        expected.base,
        expected.base_sha,
        gh=gh,
    )
    if fresh != expected:
        raise ExactPRBindingChanged("PR_CHANGED", current_head_sha=fresh.head_sha)
    return fresh
