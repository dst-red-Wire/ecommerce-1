#!/usr/bin/env python3
"""Exact-base merge-risk controller.

This file is executed from the pull request's exact base commit. It is deliberately
self-contained so code from the pull request head cannot replace its policy parser,
Git input resolver, or classification logic.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import subprocess
from bisect import bisect_right
from pathlib import Path

POLICY_PATH = "config/contracts/review-policy.yaml"
CONTROLLER_PATH = "scripts/merge_risk.py"
MAX_CHANGED_FILES = 10_000
MAX_CHANGED_CONTENT_BYTES = 16 * 1024 * 1024
MAX_CONTENT_FINDINGS = 128
MAX_CONTENT_MATCHES = 4096
MAX_ASSESSMENT_BYTES = 8192
CONTENT_ASSESSMENT_KINDS = frozenset(
    {"comment", "read-only-validation", "metadata"}
)

CONTENT_ASSESSMENT_POLICY = {
    "mode": "controlled-arbitration",
    "scope": "content-findings-only",
    "marker": "chatgpt-risk-content-assessment:v1",
    "exact_binding": ["pr", "base_sha", "head_sha", "findings_sha256"],
    "baseline_digest_field": "content_findings_sha256",
    "required_kinds": ["code", "security"],
    "independent_attestations": "required",
    "dismissal": "matching-code-and-security",
    "accepted_kinds": ["comment", "read-only-validation", "metadata"],
    "path_matches": "immutable",
    "minimum_classification": "SENSITIVE",
    "owner_authorization": "explicit-repository-owner",
    "owner_after_attestations": "required",
    "invalid_or_missing": "retain-original-tier",
    "max_findings": MAX_CONTENT_FINDINGS,
    "max_attestation_bytes": MAX_ASSESSMENT_BYTES,
}

RISK_CLASSES = ("LOW_RISK", "SENSITIVE", "PRIVILEGED", "PRODUCTION")
RISK_REQUIREMENTS = {
    "LOW_RISK": {
        "owner_authorization": "not-required-by-policy",
        "review_depth": "standard",
        "runtime_evidence": "contract-driven",
        "recovery": "mutation-class-driven",
    },
    "SENSITIVE": {
        "owner_authorization": "explicit-repository-owner",
        "review_depth": "enhanced",
        "runtime_evidence": "contract-driven",
        "recovery": "mutation-class-driven",
    },
    "PRIVILEGED": {
        "owner_authorization": "explicit-repository-owner",
        "review_depth": "privileged",
        "runtime_evidence": "host-runtime-before-mutation",
        "recovery": "capture-restore-verify",
    },
    "PRODUCTION": {
        "owner_authorization": "explicit-repository-owner",
        "review_depth": "production",
        "runtime_evidence": "production-runtime-before-mutation",
        "recovery": "capture-restore-verify",
    },
}

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
        "class_requirements",
        "content_assessment",
        "low_risk",
        "sensitive",
        "privileged",
        "production",
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
            policy.get("classifications") != list(RISK_CLASSES),
            policy.get("class_requirements") != RISK_REQUIREMENTS,
            policy.get("required_inputs")
            != ["pr", "base_sha", "head_sha", "changed_files", "resolved_capabilities"],
        )
    ):
        return False
    if policy.get("content_assessment") != CONTENT_ASSESSMENT_POLICY:
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
    tier_anchors = {
        "privileged": {
            "host-mutation": {
                "scripts/windows/**",
                "config/contracts/workstation-policy.yaml",
            },
            "credential-identity": {"scripts/windows/LabSshIdentity.ps1"},
        },
        "production": {
            "production-inventory": {"config/infrastructure/prod-inventory.yaml"},
            "production-operations": {"platform/fleet/environments/prod*/**"},
        },
    }
    for tier_name, anchors in tier_anchors.items():
        tier = policy.get(tier_name)
        if not isinstance(tier, dict) or set(tier) != {
            "authorization",
            "merge_mode",
            "capabilities",
        }:
            return False
        if (
            tier.get("authorization") != "explicit-repository-owner"
            or tier.get("merge_mode") != "OWNER_GATED"
        ):
            return False
        rules = tier.get("capabilities")
        if not isinstance(rules, dict) or set(rules) != set(anchors):
            return False
        for capability, rule in rules.items():
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
            if not anchors[capability].issubset(paths):
                return False
            try:
                for pattern in content_patterns:
                    re.compile(pattern)
            except re.error:
                return False
    return True


def _canonical_sha256(value: object) -> str:
    raw = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _changed_line_records(diff: str) -> list[dict] | None:
    """Keep the exact side and hunk line for each changed line."""
    records: list[dict] = []
    old_line = new_line = None
    old_end = new_end = 0
    for raw in diff.splitlines():
        if raw.startswith("@@ "):
            if old_line is not None and (old_line != old_end or new_line != new_end):
                return None
            hunk = re.match(
                r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@",
                raw,
            )
            if hunk is None:
                return None
            old_line, old_count, new_line, new_count = (
                int(hunk.group(1)), int(hunk.group(2) or 1),
                int(hunk.group(3)), int(hunk.group(4) or 1),
            )
            old_end = old_line + old_count
            new_end = new_line + new_count
            continue
        if old_line is None:
            continue
        if raw.startswith("\\ No newline at end of file"):
            continue
        if raw.startswith("-"):
            records.append({"side": "-", "line": old_line, "text": raw[1:]})
            old_line += 1
        elif raw.startswith("+"):
            records.append({"side": "+", "line": new_line, "text": raw[1:]})
            new_line += 1
        elif raw.startswith(" "):
            old_line += 1
            new_line += 1
        else:
            return None
        if old_line > old_end or new_line > new_end:
            return None
    if old_line is not None and (old_line != old_end or new_line != new_end):
        return None
    return records


def _content_findings(
    policy: dict,
    changed_files: list[str],
    file_changes: dict[str, str],
    changed_lines: dict[str, list[dict]] | None,
) -> tuple[list[dict], set[tuple[str, str]], bool]:
    """Inventory only bounded, single-line high-tier content matches."""
    if not isinstance(changed_lines, dict) or set(changed_lines) != set(changed_files):
        return [], set(), False
    spans: dict[str, list[tuple[int, int, dict]]] = {}
    span_starts: dict[str, list[int]] = {}
    for path in changed_files:
        records = changed_lines[path]
        if not isinstance(records, list) or any(
            not isinstance(item, dict)
            or set(item) != {"side", "line", "text"}
            or item["side"] not in {"+", "-"}
            or type(item["line"]) is not int
            or item["line"] < 1
            or not isinstance(item["text"], str)
            for item in records
        ):
            return [], set(), False
        if "\n".join(item["text"] for item in records) != file_changes[path]:
            return [], set(), False
        offset = 0
        spans[path] = []
        span_starts[path] = []
        for item in records:
            end = offset + len(item["text"])
            spans[path].append((offset, end, item))
            span_starts[path].append(offset)
            offset = end + 1
    findings: dict[str, dict] = {}
    unmapped: set[tuple[str, str]] = set()
    seen: set[tuple[str, str, str, int, int]] = set()
    line_hashes: dict[tuple[str, int], str] = {}
    match_count = 0
    for tier, name in (("PRODUCTION", "production"), ("PRIVILEGED", "privileged")):
        for capability, rule in policy[name]["capabilities"].items():
            for path in changed_files:
                if not _path_matches(path, rule.get("content_paths", [])):
                    continue
                blob = file_changes[path]
                for rule_index, pattern in enumerate(rule.get("content_patterns", [])):
                    for match in re.finditer(
                        pattern, blob, flags=re.IGNORECASE | re.MULTILINE
                    ):
                        match_count += 1
                        if match_count > MAX_CONTENT_MATCHES:
                            return [], set(), False
                        span_index = bisect_right(span_starts[path], match.start()) - 1
                        if span_index < 0:
                            unmapped.add((tier, capability))
                            continue
                        start, end, item = spans[path][span_index]
                        if not start <= match.start() < match.end() <= end:
                            unmapped.add((tier, capability))
                            continue
                        key = (tier, capability, path, rule_index, span_index)
                        if key in seen:
                            continue
                        seen.add(key)
                        line_key = (path, span_index)
                        if line_key not in line_hashes:
                            line_hashes[line_key] = "sha256:" + hashlib.sha256(
                                item["text"].encode("utf-8")
                            ).hexdigest()
                        identity = {
                            "tier": tier,
                            "capability": capability,
                            "path": path,
                            "side": item["side"],
                            "line": item["line"],
                            "rule_index": rule_index,
                            "line_sha256": line_hashes[line_key],
                        }
                        finding = {"id": _canonical_sha256(identity), **identity}
                        findings[finding["id"]] = finding
                        if len(findings) > MAX_CONTENT_FINDINGS:
                            return [], set(), False
    result = sorted(findings.values(), key=lambda item: item["id"])
    return result, unmapped, True


def _disposed_finding_ids(
    assessment: object,
    *,
    base_sha: str,
    head_sha: str,
    pr_number: int | None,
    findings: list[dict],
) -> set[str]:
    """A bad or incomplete assessment never changes the original risk tier."""
    if not isinstance(assessment, dict) or set(assessment) != {
        "schema_version", "pr", "base_sha", "head_sha",
        "findings_sha256", "dispositions",
    }:
        return set()
    try:
        if len(json.dumps(assessment, ensure_ascii=True).encode("utf-8")) > MAX_ASSESSMENT_BYTES:
            return set()
    except (TypeError, ValueError):
        return set()
    if (
        type(assessment["schema_version"]) is not int
        or assessment["schema_version"] != 1
        or type(assessment["pr"]) is not int
        or assessment["pr"] != pr_number
        or assessment["base_sha"] != base_sha
        or assessment["head_sha"] != head_sha
        or assessment["findings_sha256"] != _canonical_sha256(findings)
        or not isinstance(assessment["dispositions"], list)
        or len(assessment["dispositions"]) != len(findings)
    ):
        return set()
    known = {item["id"] for item in findings}
    disposed: set[str] = set()
    for item in assessment["dispositions"]:
        if not isinstance(item, dict) or set(item) != {
            "finding_id", "kind", "rationale", "effect_trace",
        }:
            return set()
        finding_id = item["finding_id"]
        if (
            not isinstance(finding_id, str)
            or finding_id not in known
            or finding_id in disposed
            or not isinstance(item["kind"], str)
            or item["kind"] not in CONTENT_ASSESSMENT_KINDS
            or any(
                not isinstance(item[field], str)
                or not item[field].strip()
                for field in ("rationale", "effect_trace")
            )
        ):
            return set()
        disposed.add(finding_id)
    return disposed if disposed == known else set()


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate content assessment key")
        value[key] = item
    return value


def _read_assessment_file(path: Path | None) -> object:
    if path is None:
        return None
    try:
        if path.stat().st_size > MAX_ASSESSMENT_BYTES:
            return None
        raw = path.read_bytes()
        if len(raw) > MAX_ASSESSMENT_BYTES:
            return None
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_json_object)
    except (OSError, UnicodeError, ValueError, TypeError):
        return None


def _path_matches(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def _matched_capabilities(
    capabilities: dict,
    changed_files: list[str],
    file_changes: dict[str, str],
) -> set[str]:
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
    return matched


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
    content_findings: list[dict] | None = None,
) -> dict:
    inventory = content_findings or []
    return {
        "classification": classification,
        "requirements": dict(RISK_REQUIREMENTS[classification]),
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
        "content_findings": inventory,
        "content_findings_sha256": _canonical_sha256(inventory),
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
) -> tuple[list[str], dict[str, str], dict[str, list[dict]] | None]:
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
    records_by_path: dict[str, list[dict]] = {}
    inventory_supported = True
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
        records = _changed_line_records(diff)
        if records is None:
            inventory_supported = False
            changed_lines = [
                line[1:]
                for line in diff.splitlines()
                if (line.startswith("+") and not line.startswith("+++"))
                or (line.startswith("-") and not line.startswith("---"))
            ]
        else:
            records_by_path[path] = records
            changed_lines = [item["text"] for item in records]
        changes[path] = "\n".join(changed_lines)
        changed_content_bytes += len(changes[path].encode("utf-8"))
        if changed_content_bytes > MAX_CHANGED_CONTENT_BYTES:
            raise RuntimeError(
                "exact-SHA diff exceeds the bounded content-analysis limit"
            )
    if set(changes) != set(changed_files):
        raise RuntimeError("partial exact-SHA changed-file analysis")
    return sorted(changed_files), changes, (
        records_by_path if inventory_supported else None
    )


def evaluate_merge_risk(
    policy: dict,
    *,
    base_sha: str,
    head_sha: str,
    pr_number: int | None,
    changed_files: list[str],
    file_changes: dict[str, str],
    changed_lines: dict[str, list[dict]] | None = None,
    assessment: object = None,
) -> dict:
    """Pure exact-SHA classification; an assessed content signal never hides a path anchor."""
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
    findings, unmapped, inventory_complete = _content_findings(
        policy, changed_files, file_changes, changed_lines
    )
    disposed = (
        _disposed_finding_ids(
            assessment, base_sha=base_sha, head_sha=head_sha,
            pr_number=pr_number, findings=findings,
        )
        if inventory_complete else set()
    )
    for classification, tier_name in (
        ("PRODUCTION", "production"),
        ("PRIVILEGED", "privileged"),
        ("SENSITIVE", "sensitive"),
    ):
        capabilities = policy[tier_name]["capabilities"]
        matched = _matched_capabilities(capabilities, changed_files, file_changes)
        if classification in {"PRODUCTION", "PRIVILEGED"} and disposed:
            for capability in tuple(matched):
                rule = capabilities[capability]
                anchored = any(
                    _path_matches(path, rule.get("paths", []))
                    for path in changed_files
                )
                associated = [
                    item for item in findings
                    if item["tier"] == classification
                    and item["capability"] == capability
                ]
                if (
                    not anchored
                    and (classification, capability) not in unmapped
                    and associated
                    and all(item["id"] in disposed for item in associated)
                ):
                    matched.remove(capability)
        if matched:
            return _result(
                classification,
                base_sha=base_sha,
                head_sha=head_sha,
                pr_number=pr_number,
                changed_files=changed_files,
                reasons=sorted(matched | ({"content-assessment-applied"} if disposed else set())),
                matched_capabilities=sorted(matched),
                analysis_complete=True,
                content_findings=findings,
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
            reasons=[f"unclassified-path:{path}" for path in unclassified]
            + (["content-assessment-applied"] if disposed else []),
            matched_capabilities=[],
            analysis_complete=True,
            content_findings=findings,
        )
    if disposed:
        return _result(
            "SENSITIVE",
            base_sha=base_sha,
            head_sha=head_sha,
            pr_number=pr_number,
            changed_files=changed_files,
            reasons=["content-assessment-applied"],
            matched_capabilities=[],
            analysis_complete=True,
            content_findings=findings,
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
        content_findings=findings,
    )


def classify_merge_risk(
    base_sha: str,
    head_sha: str,
    pr_number: int | None = None,
    *,
    root: Path | None = None,
    assessment_file: Path | None = None,
) -> dict:
    """Classify with this exact-base controller; every incomplete input is sensitive."""
    repository = (root or Path.cwd()).resolve()
    changed_files: list[str] = []
    try:
        policy = _policy_at_base(repository, base_sha)
        changed_files, file_changes, changed_lines = _git_inputs(
            repository, base_sha, head_sha
        )
        return evaluate_merge_risk(
            policy,
            base_sha=base_sha,
            head_sha=head_sha,
            pr_number=pr_number,
            changed_files=changed_files,
            file_changes=file_changes,
            changed_lines=changed_lines,
            assessment=_read_assessment_file(assessment_file),
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
    parser.add_argument("--assessment-file", type=Path)
    args = parser.parse_args()
    print(
        json.dumps(
            classify_merge_risk(
                args.base_sha, args.head_sha, args.pr,
                assessment_file=args.assessment_file,
            ),
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
