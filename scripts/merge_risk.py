#!/usr/bin/env python3
"""Exact-base merge-risk controller.

This file is executed from the pull request's exact base commit. It is deliberately
self-contained so code from the pull request head cannot replace its policy parser,
Git input resolver, or classification logic.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import subprocess
from pathlib import Path

POLICY_PATH = "config/contracts/review-policy.yaml"
CONTROLLER_PATH = "scripts/merge_risk.py"
MAX_CHANGED_FILES = 10_000
MAX_CHANGED_CONTENT_BYTES = 16 * 1024 * 1024

MERGE_RISK_CAPABILITIES = (
    "governance",
    "delivery-authority",
    "branch-protection",
    "infrastructure-apply",
    "destructive-operation",
    "state-migration",
    "iam",
    "secrets",
    "network",
    "dns",
    "signing-or-provenance-policy",
    "security-policy",
    "artifact-publication-authority",
)

_PSYCH_STDIN_SCRIPT = r"""
source = STDIN.read
document = Psych.parse(source)
walk = lambda do |node|
  if node.is_a?(Psych::Nodes::Mapping)
    keys = node.children.each_slice(2).map { |key, _| key.value }
    duplicate = keys.group_by(&:itself).find { |_, values| values.length > 1 }
    raise "duplicate YAML mapping key: #{duplicate[0]}" if duplicate
  end
  Array(node.children).each { |child| walk.call(child) } if node.respond_to?(:children)
end
walk.call(document)
data = Psych.safe_load(source, aliases: false)
puts JSON.generate(data || {})
"""


def _run(
    command: list[str],
    *,
    root: Path,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=root,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )


def _git(root: Path, *args: str) -> str:
    completed = _run(["git", "--no-pager", *args], root=root)
    if completed.returncode:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise RuntimeError(detail or f"git {' '.join(args)} failed")
    return completed.stdout or ""


def merge_risk_policy_is_valid(policy: object, owner_boundary: object) -> bool:
    """Validate the closed-world policy before it can classify any pull request."""
    if not isinstance(policy, dict) or not isinstance(owner_boundary, dict):
        return False
    if set(policy) != {
        "authority",
        "implementation",
        "controller_source",
        "bootstrap_without_controller",
        "head_controller_execution",
        "policy_source",
        "model",
        "llm_decision",
        "exact_sha_binding",
        "self_modification",
        "unknown_or_ambiguous",
        "partial_analysis",
        "git_error",
        "classifications",
        "required_inputs",
        "low_risk",
        "sensitive",
    }:
        return False
    if any(
        (
            policy.get("authority") != "repository-policy",
            policy.get("implementation") != f"{CONTROLLER_PATH}#classify_merge_risk",
            policy.get("controller_source") != "exact-pr-base-sha",
            policy.get("bootstrap_without_controller") != "sensitive",
            policy.get("head_controller_execution") != "forbidden",
            policy.get("policy_source") != "exact-pr-base-sha",
            policy.get("model") != "deterministic-capabilities-and-paths",
            policy.get("llm_decision") != "forbidden",
            policy.get("exact_sha_binding") != "required",
            policy.get("self_modification") != "sensitive",
            policy.get("unknown_or_ambiguous") != "sensitive",
            policy.get("partial_analysis") != "sensitive",
            policy.get("git_error") != "sensitive",
            policy.get("classifications") != ["LOW_RISK", "SENSITIVE"],
            policy.get("required_inputs")
            != ["pr", "base_sha", "head_sha", "changed_files", "resolved_capabilities"],
        )
    ):
        return False
    required_for = list(MERGE_RISK_CAPABILITIES)
    if owner_boundary.get("mode") != "risk-based":
        return False
    if owner_boundary.get("automatic_generation") != "forbidden":
        return False
    if owner_boundary.get("required_for") != required_for:
        return False
    if owner_boundary.get("low_risk") != {"authorization": "not-required-by-policy"}:
        return False
    if owner_boundary.get("sensitive") != {
        "authorization": "explicit-repository-owner"
    }:
        return False
    low_risk = policy.get("low_risk")
    sensitive = policy.get("sensitive")
    if not isinstance(low_risk, dict) or set(low_risk) != {
        "authorization",
        "merge_mode",
        "eligible_paths",
    }:
        return False
    if (
        low_risk.get("authorization") != "not-required-by-policy"
        or low_risk.get("merge_mode") != "AUTO"
    ):
        return False
    eligible_paths = low_risk.get("eligible_paths")
    if (
        not isinstance(eligible_paths, list)
        or not eligible_paths
        or len(eligible_paths) != len(set(eligible_paths))
        or any(
            not isinstance(pattern, str)
            or not pattern
            or pattern in {"*", "**", "**/*"}
            or pattern.startswith("/")
            or ".." in Path(pattern).parts
            for pattern in eligible_paths
        )
    ):
        return False
    if not isinstance(sensitive, dict) or set(sensitive) != {
        "authorization",
        "merge_mode",
        "capabilities",
    }:
        return False
    if (
        sensitive.get("authorization") != "explicit-repository-owner"
        or sensitive.get("merge_mode") != "OWNER_GATED"
    ):
        return False
    capabilities = sensitive.get("capabilities")
    if not isinstance(capabilities, dict) or set(capabilities) != set(required_for):
        return False
    required_anchors = {
        "governance": {"architecture.lock.yaml", "config/contracts/review-policy.yaml"},
        "delivery-authority": {
            "scripts/merge_risk.py",
            "scripts/repoctl.py",
            "scripts/pr_monitor.py",
            "Makefile",
        },
        "branch-protection": {".github/CODEOWNERS", ".github/rulesets/**"},
        "infrastructure-apply": {"platform/terraform/**", "platform/ansible/**"},
        "state-migration": {"**/migrations/**"},
        "iam": {
            "config/contracts/identity-boundary-policy.yaml",
            "services/**/auth/**",
            "services/**/authentication/**",
            "services/**/authorization/**",
            "services/**/security/**",
            "services/**/oidc/**",
            "services/**/oauth/**",
            "services/**/jwt/**",
            "services/**/session/**",
            "services/**/*auth*",
            "services/**/*security*",
            "services/**/*oidc*",
            "services/**/*oauth*",
            "services/**/*jwt*",
            "services/**/*session*",
        },
        "secrets": {"config/contracts/secret-delivery-policy.yaml"},
        "network": {"config/infrastructure/network-plan.yaml"},
        "dns": {"config/contracts/dns-authority-policy.yaml"},
        "signing-or-provenance-policy": {"scripts/check_automation_signing.py"},
        "security-policy": {"config/contracts/security-scan-policy.yaml"},
        "artifact-publication-authority": {"platform/tekton/**"},
    }
    for capability, rule in capabilities.items():
        if not isinstance(rule, dict) or set(rule) - {
            "paths",
            "content_paths",
            "content_patterns",
        }:
            return False
        paths = rule.get("paths", [])
        content_paths = rule.get("content_paths", [])
        content_patterns = rule.get("content_patterns", [])
        if any(
            not isinstance(values, list)
            or len(values) != len(set(values))
            or any(not isinstance(value, str) or not value for value in values)
            for values in (paths, content_paths, content_patterns)
        ):
            return False
        if not paths and not content_patterns:
            return False
        if content_patterns and not content_paths:
            return False
        if not required_anchors.get(capability, set()).issubset(paths):
            return False
        try:
            for pattern in content_patterns:
                re.compile(pattern)
        except re.error:
            return False
    return True


def _path_matches(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def _result(
    classification: str,
    *,
    base_sha: str,
    head_sha: str,
    pr_number: int | None,
    changed_files: list[str],
    reasons: list[str],
    matched_capabilities: list[str],
    analysis_complete: bool,
) -> dict:
    return {
        "classification": classification,
        "authority": "repository-policy",
        "controller_source": "exact-pr-base-sha",
        "controller_path": CONTROLLER_PATH,
        "policy_source": "exact-pr-base-sha",
        "pr": pr_number,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "changed_files": sorted(changed_files),
        "reasons": sorted(set(reasons)),
        "matched_capabilities": sorted(set(matched_capabilities)),
        "analysis_complete": analysis_complete,
    }


def sensitive_result(
    *,
    base_sha: str,
    head_sha: str,
    pr_number: int | None,
    changed_files: list[str] | None,
    reason: str,
) -> dict:
    return _result(
        "SENSITIVE",
        base_sha=base_sha,
        head_sha=head_sha,
        pr_number=pr_number,
        changed_files=changed_files or [],
        reasons=[reason],
        matched_capabilities=[],
        analysis_complete=False,
    )


def _policy_at_base(root: Path, base_sha: str) -> dict:
    raw_policy = _git(root, "show", f"{base_sha}:{POLICY_PATH}")
    parsed = _run(
        ["ruby", "-rpsych", "-rjson", "-e", _PSYCH_STDIN_SCRIPT],
        root=root,
        input_text=raw_policy,
    )
    if parsed.returncode:
        raise RuntimeError(
            (parsed.stderr or parsed.stdout or "invalid exact-base YAML").strip()
        )
    document = json.loads(parsed.stdout or "{}")
    if not isinstance(document, dict):
        raise TypeError("exact base review policy must be a mapping")
    pr_loop_policy = (document.get("repository_delivery") or {}).get("pr_loop") or {}
    risk_policy = pr_loop_policy.get("risk_classification")
    owner_boundary = pr_loop_policy.get("owner_boundary")
    if not merge_risk_policy_is_valid(risk_policy, owner_boundary):
        raise RuntimeError("exact base review policy has no valid merge-risk authority")
    return risk_policy


def _git_inputs(
    root: Path, base_sha: str, head_sha: str
) -> tuple[list[str], dict[str, str]]:
    for label, sha in (("base", base_sha), ("head", head_sha)):
        if re.fullmatch(r"[0-9a-f]{40}", sha or "") is None:
            raise RuntimeError(f"{label} SHA is not exact")
        _git(root, "cat-file", "-e", f"{sha}^{{commit}}")
    lineage = _run(
        ["git", "--no-pager", "merge-base", "--is-ancestor", base_sha, head_sha],
        root=root,
    )
    if lineage.returncode:
        raise RuntimeError("head is not descended from the exact PR base")
    raw_status = _git(
        root,
        "diff",
        "--no-ext-diff",
        "--no-renames",
        "--name-status",
        "-z",
        base_sha,
        head_sha,
        "--",
    )
    fields = raw_status.split("\0")
    if fields and fields[-1] == "":
        fields.pop()
    if len(fields) % 2:
        raise RuntimeError("partial exact-SHA diff status")
    changed_files: list[str] = []
    for index in range(0, len(fields), 2):
        change_status, path = fields[index : index + 2]
        if change_status not in set("ACDMRTUXB"):
            raise RuntimeError(f"unknown diff status: {change_status!r}")
        if (
            not path
            or path.startswith("/")
            or "\\" in path
            or "\x00" in path
            or ".." in Path(path).parts
        ):
            raise RuntimeError("diff contains an invalid repository path")
        changed_files.append(path)
    if len(changed_files) > MAX_CHANGED_FILES:
        raise RuntimeError("exact-SHA diff exceeds the bounded changed-file limit")
    if len(changed_files) != len(set(changed_files)):
        raise RuntimeError("diff contains duplicate or ambiguous paths")
    changes: dict[str, str] = {}
    changed_content_bytes = 0
    for path in sorted(changed_files):
        numstat = _git(
            root,
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--numstat",
            "-z",
            base_sha,
            head_sha,
            "--",
            path,
        )
        if numstat.startswith("-\t-\t"):
            raise RuntimeError(f"unclassifiable binary diff for {path}")
        diff = _git(
            root,
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--no-color",
            "--unified=0",
            base_sha,
            head_sha,
            "--",
            path,
        )
        changed_lines = [
            line[1:]
            for line in diff.splitlines()
            if (line.startswith("+") and not line.startswith("+++"))
            or (line.startswith("-") and not line.startswith("---"))
        ]
        changes[path] = "\n".join(changed_lines)
        changed_content_bytes += len(changes[path].encode("utf-8"))
        if changed_content_bytes > MAX_CHANGED_CONTENT_BYTES:
            raise RuntimeError(
                "exact-SHA diff exceeds the bounded content-analysis limit"
            )
    if set(changes) != set(changed_files):
        raise RuntimeError("partial exact-SHA changed-file analysis")
    return sorted(changed_files), changes


def evaluate_merge_risk(
    policy: dict,
    *,
    base_sha: str,
    head_sha: str,
    pr_number: int | None,
    changed_files: list[str],
    file_changes: dict[str, str],
) -> dict:
    """Pure deterministic capability/path classification over complete exact-SHA inputs."""
    if re.fullmatch(r"[0-9a-f]{40}", base_sha or "") is None:
        return sensitive_result(
            base_sha=base_sha,
            head_sha=head_sha,
            pr_number=pr_number,
            changed_files=changed_files,
            reason="invalid-base-sha",
        )
    if re.fullmatch(r"[0-9a-f]{40}", head_sha or "") is None:
        return sensitive_result(
            base_sha=base_sha,
            head_sha=head_sha,
            pr_number=pr_number,
            changed_files=changed_files,
            reason="invalid-head-sha",
        )
    owner_boundary = {
        "mode": "risk-based",
        "automatic_generation": "forbidden",
        "required_for": list(MERGE_RISK_CAPABILITIES),
        "low_risk": {"authorization": "not-required-by-policy"},
        "sensitive": {"authorization": "explicit-repository-owner"},
    }
    if not merge_risk_policy_is_valid(policy, owner_boundary):
        return sensitive_result(
            base_sha=base_sha,
            head_sha=head_sha,
            pr_number=pr_number,
            changed_files=changed_files,
            reason="unknown-or-invalid-policy",
        )
    if (
        not isinstance(changed_files, list)
        or not changed_files
        or len(changed_files) != len(set(changed_files))
        or sorted(changed_files) != changed_files
        or not isinstance(file_changes, dict)
        or set(file_changes) != set(changed_files)
        or any(not isinstance(value, str) for value in file_changes.values())
    ):
        return sensitive_result(
            base_sha=base_sha,
            head_sha=head_sha,
            pr_number=pr_number,
            changed_files=changed_files if isinstance(changed_files, list) else [],
            reason="partial-or-ambiguous-diff",
        )
    capabilities = policy["sensitive"]["capabilities"]
    matched: set[str] = set()
    for capability, rule in capabilities.items():
        if any(_path_matches(path, rule.get("paths", [])) for path in changed_files):
            matched.add(capability)
        candidates = [
            path
            for path in changed_files
            if _path_matches(path, rule.get("content_paths", []))
        ]
        if candidates and any(
            re.search(pattern, file_changes[path], flags=re.IGNORECASE | re.MULTILINE)
            for pattern in rule.get("content_patterns", [])
            for path in candidates
        ):
            matched.add(capability)
    if matched:
        return _result(
            "SENSITIVE",
            base_sha=base_sha,
            head_sha=head_sha,
            pr_number=pr_number,
            changed_files=changed_files,
            reasons=sorted(matched),
            matched_capabilities=sorted(matched),
            analysis_complete=True,
        )
    unclassified = [
        path
        for path in changed_files
        if not _path_matches(path, policy["low_risk"]["eligible_paths"])
    ]
    if unclassified:
        return _result(
            "SENSITIVE",
            base_sha=base_sha,
            head_sha=head_sha,
            pr_number=pr_number,
            changed_files=changed_files,
            reasons=[f"unclassified-path:{path}" for path in unclassified],
            matched_capabilities=[],
            analysis_complete=True,
        )
    return _result(
        "LOW_RISK",
        base_sha=base_sha,
        head_sha=head_sha,
        pr_number=pr_number,
        changed_files=changed_files,
        reasons=[],
        matched_capabilities=[],
        analysis_complete=True,
    )


def classify_merge_risk(
    base_sha: str,
    head_sha: str,
    pr_number: int | None = None,
    *,
    root: Path | None = None,
) -> dict:
    """Classify with this exact-base controller; every incomplete input is sensitive."""
    repository = (root or Path.cwd()).resolve()
    changed_files: list[str] = []
    try:
        policy = _policy_at_base(repository, base_sha)
        changed_files, file_changes = _git_inputs(repository, base_sha, head_sha)
        return evaluate_merge_risk(
            policy,
            base_sha=base_sha,
            head_sha=head_sha,
            pr_number=pr_number,
            changed_files=changed_files,
            file_changes=file_changes,
        )
    except (
        OSError,
        RuntimeError,
        subprocess.TimeoutExpired,
        TypeError,
        ValueError,
    ) as exc:
        detail = re.sub(r"\s+", " ", str(exc)).strip()[:300] or type(exc).__name__
        return sensitive_result(
            base_sha=base_sha,
            head_sha=head_sha,
            pr_number=pr_number,
            changed_files=changed_files,
            reason=f"classification-error:{detail}",
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--pr", type=int)
    args = parser.parse_args()
    print(
        json.dumps(
            classify_merge_risk(args.base_sha, args.head_sha, args.pr),
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
