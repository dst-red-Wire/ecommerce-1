#!/usr/bin/env python3
"""Deterministic CVE policy evaluation and reproducible KEV/EPSS snapshots."""

from __future__ import annotations

import csv
import gzip
import hashlib
import json
import re
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
import qualification_cache

UTC = timezone.utc
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
SEVERITIES = ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def load_policy(root: Path) -> dict[str, Any]:
    lock = qualification_cache.psych_load(root / "architecture.lock.yaml")
    relative = lock.get("machine_contracts", {}).get("security_scan_policy")
    if not isinstance(relative, str) or not relative:
        raise ValueError(
            "security scan policy is not registered in architecture.lock.yaml"
        )
    policy = qualification_cache.psych_load(root / relative)
    validate_policy(policy)
    return policy


def validate_policy(policy: dict[str, Any]) -> None:
    if (
        policy.get("version") != 2
        or policy.get("status") != "exact"
        or policy.get("architecture_authority") != "architecture.lock.yaml"
        or policy.get("scope") != "entire-repository"
    ):
        raise ValueError("invalid security scan policy header")
    vulnerability = policy.get("vulnerability_policy")
    if not isinstance(vulnerability, dict) or set(SEVERITIES) - {
        str(key).upper() for key in vulnerability if str(key).upper() in SEVERITIES
    }:
        raise ValueError(
            "security scan policy must define critical/high/medium/low/unknown"
        )
    threshold = vulnerability.get("epss_blocking_threshold")
    if (
        not isinstance(threshold, (int, float))
        or isinstance(threshold, bool)
        or not 0 <= threshold <= 1
    ):
        raise ValueError(
            "EPSS blocking threshold must be a number between zero and one"
        )
    if vulnerability["critical"].get("remediation_deadline_hours") != 72:
        raise ValueError("CRITICAL remediation deadline must remain 72 hours")
    if vulnerability["high"].get("remediation_deadline_days") != 7:
        raise ValueError("HIGH remediation deadline must remain 7 days")
    if vulnerability["medium"].get("remediation_deadline_days") != 30:
        raise ValueError("MEDIUM remediation deadline must remain 30 days")
    datasets = policy.get("risk_datasets")
    if (
        not isinstance(datasets, dict)
        or datasets.get("qualification_network_access") != "forbidden"
    ):
        raise ValueError(
            "risk datasets must forbid network access during qualification"
        )
    for name in ("kev", "epss"):
        item = datasets.get(name)
        if (
            not isinstance(item, dict)
            or not str(item.get("source", "")).startswith("https://")
            or item.get("checksum") != "sha256"
            or type(item.get("maximum_age_hours")) is not int
        ):
            raise ValueError(
                f"risk dataset {name} identity/freshness policy is invalid"
            )
    exceptions = policy.get("exceptions")
    required = {
        "finding_id",
        "owner",
        "reason",
        "scope",
        "affected_artifact",
        "created_at",
        "expires_at",
        "approval",
    }
    if (
        not isinstance(exceptions, dict)
        or set(exceptions.get("required_fields", [])) != required
    ):
        raise ValueError("security exception required fields are invalid")
    evidence = policy.get("evidence")
    if not isinstance(evidence, dict) or evidence.get("final_results") != [
        "PASS",
        "BLOCK",
    ]:
        raise ValueError("security evidence final results must be closed to PASS/BLOCK")


def _parse_time(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} timestamp is missing")
    normalized = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"{label} timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} timestamp must include a timezone")
    return parsed.astimezone(UTC)


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _read_dataset_manifest(
    policy: dict[str, Any], root: Path, now: datetime
) -> dict[str, Any]:
    relative = Path(str(policy["risk_datasets"]["manifest"]))
    manifest_path = relative if relative.is_absolute() else root / relative
    if not manifest_path.is_file():
        raise ValueError("risk dataset manifest is missing")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("risk dataset manifest is malformed") from exc
    if manifest.get("schema_version") != 1 or not isinstance(
        manifest.get("datasets"), dict
    ):
        raise ValueError("risk dataset manifest schema is invalid")

    identities: dict[str, Any] = {}
    kev_ids: set[str] = set()
    epss_scores: dict[str, float] = {}
    for name in ("kev", "epss"):
        entry = manifest["datasets"].get(name)
        contract = policy["risk_datasets"][name]
        if not isinstance(entry, dict) or entry.get("source") != contract["source"]:
            raise ValueError(f"{name.upper()} dataset provenance is invalid")
        file_name = entry.get("file")
        if (
            not isinstance(file_name, str)
            or Path(file_name).is_absolute()
            or ".." in Path(file_name).parts
        ):
            raise ValueError(f"{name.upper()} dataset path is unsafe")
        dataset_path = manifest_path.parent / file_name
        if not dataset_path.is_file():
            raise ValueError(f"{name.upper()} dataset is missing")
        raw = dataset_path.read_bytes()
        actual = _sha256_bytes(raw)
        if (
            not re.fullmatch(r"[0-9a-f]{64}", str(entry.get("sha256", "")))
            or actual != entry["sha256"]
        ):
            raise ValueError(f"{name.upper()} dataset checksum mismatch")
        snapshot = _parse_time(entry.get("snapshot_at"), f"{name} snapshot")
        age_hours = (now - snapshot).total_seconds() / 3600
        if age_hours < -1 or age_hours > int(contract["maximum_age_hours"]):
            raise ValueError(f"{name.upper()} dataset is stale")
        identities[name] = {
            "source": entry["source"],
            "snapshot_at": _iso(snapshot),
            "sha256": actual,
            "provenance": entry.get("provenance"),
        }
        if name == "kev":
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError("KEV dataset is malformed") from exc
            vulnerabilities = (
                payload.get("vulnerabilities") if isinstance(payload, dict) else None
            )
            if not isinstance(vulnerabilities, list):
                raise ValueError("KEV dataset has no vulnerability list")
            kev_ids = {
                str(item.get("cveID", "")).upper()
                for item in vulnerabilities
                if isinstance(item, dict)
                and CVE_PATTERN.fullmatch(str(item.get("cveID", "")))
            }
        else:
            try:
                decoded = gzip.decompress(raw).decode("utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                raise ValueError("EPSS dataset is malformed") from exc
            lines = [
                line
                for line in decoded.splitlines()
                if line and not line.startswith("#")
            ]
            reader = csv.DictReader(lines)
            if reader.fieldnames != ["cve", "epss", "percentile"]:
                raise ValueError("EPSS dataset columns are invalid")
            for row in reader:
                cve = str(row.get("cve", "")).upper()
                if not CVE_PATTERN.fullmatch(cve):
                    continue
                try:
                    score = float(row["epss"])
                except (TypeError, ValueError) as exc:
                    raise ValueError(f"EPSS score is invalid for {cve}") from exc
                if not 0 <= score <= 1:
                    raise ValueError(f"EPSS score is out of range for {cve}")
                epss_scores[cve] = score
    return {"identities": identities, "kev_ids": kev_ids, "epss_scores": epss_scores}


def _dataset_snapshot_time(name: str, raw: bytes, fetched: datetime) -> datetime:
    if name == "kev":
        payload = json.loads(raw)
        released = payload.get("dateReleased") or payload.get("dateUpdated")
        return _parse_time(released, "KEV release") if released else fetched
    decoded = gzip.decompress(raw).decode("utf-8")
    first = decoded.splitlines()[0] if decoded else ""
    match = re.search(r"score_date:([^,\s]+)", first)
    return _parse_time(match.group(1), "EPSS score date") if match else fetched


def sync_datasets(
    policy: dict[str, Any], output: Path, *, now: datetime | None = None
) -> Path:
    """Fetch official datasets outside qualification and write an atomic manifest."""
    validate_policy(policy)
    fetched = (now or datetime.now(UTC)).astimezone(UTC)
    output.mkdir(parents=True, exist_ok=True)
    file_names = {"kev": "cisa-kev.json", "epss": "epss.csv.gz"}
    entries: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(
        prefix="security-datasets-", dir=output.parent
    ) as temporary:
        staging = Path(temporary)
        for name, file_name in file_names.items():
            source = str(policy["risk_datasets"][name]["source"])
            request = Request(
                source, headers={"User-Agent": "ecommerce-1-security-dataset-sync/1"}
            )
            with urlopen(request, timeout=60) as response:  # nosec B310 - sources are exact HTTPS policy values
                raw = response.read()
            if not raw:
                raise ValueError(f"{name.upper()} dataset download is empty")
            snapshot = _dataset_snapshot_time(name, raw, fetched)
            (staging / file_name).write_bytes(raw)
            entries[name] = {
                "source": source,
                "file": file_name,
                "snapshot_at": _iso(snapshot),
                "fetched_at": _iso(fetched),
                "sha256": _sha256_bytes(raw),
                "provenance": "official-https-snapshot",
            }
        manifest = {
            "schema_version": 1,
            "generated_at": _iso(fetched),
            "datasets": entries,
        }
        (staging / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        for file_name in (*file_names.values(), "manifest.json"):
            (staging / file_name).replace(output / file_name)
    return output / "manifest.json"


def _cvss_floor(policy: dict[str, Any], severity: str, cvss: float | None) -> str:
    if cvss is None:
        return severity
    thresholds = policy["vulnerability_policy"]["cvss"]
    floor = "LOW"
    if cvss >= float(thresholds["critical_minimum"]):
        floor = "CRITICAL"
    elif cvss >= float(thresholds["high_minimum"]):
        floor = "HIGH"
    elif cvss >= float(thresholds["medium_minimum"]):
        floor = "MEDIUM"
    return floor if SEVERITIES.index(floor) > SEVERITIES.index(severity) else severity


def trivy_findings(
    payload: dict[str, Any], *, artifact: str, scope: str
) -> list[dict[str, Any]]:
    results = payload.get("Results")
    if results is None:
        raise ValueError("Trivy output is missing Results")
    if not isinstance(results, list):
        raise TypeError("Trivy Results must be a list")
    findings: list[dict[str, Any]] = []
    for result in results:
        if not isinstance(result, dict):
            raise TypeError("Trivy result entry is malformed")
        for item in result.get("Vulnerabilities") or []:
            if not isinstance(item, dict):
                raise TypeError("Trivy vulnerability entry is malformed")
            cvss_scores = []
            for source in (item.get("CVSS") or {}).values():
                if isinstance(source, dict):
                    for key in ("V3Score", "V2Score"):
                        if isinstance(source.get(key), (int, float)):
                            cvss_scores.append(float(source[key]))
            findings.append(
                {
                    "finding_id": str(item.get("VulnerabilityID", "")).upper(),
                    "severity": str(item.get("Severity", "UNKNOWN")).upper(),
                    "cvss": max(cvss_scores) if cvss_scores else None,
                    "fix_available": bool(str(item.get("FixedVersion", "")).strip()),
                    "fixed_version": str(item.get("FixedVersion", "")),
                    "reachable": item.get("Reachable"),
                    "artifact": artifact,
                    "scope": scope,
                    "scanner": "trivy",
                    "package": str(item.get("PkgName", "")),
                    "installed_version": str(item.get("InstalledVersion", "")),
                    "detected_at": item.get("PublishedDate"),
                }
            )
    return findings


def _exception_for(
    finding: dict[str, Any],
    exceptions: list[dict[str, Any]],
    *,
    head_sha: str,
    environment: str,
    now: datetime,
) -> tuple[dict[str, Any] | None, list[str]]:
    errors: list[str] = []
    matches = [
        item for item in exceptions if item.get("finding_id") == finding["finding_id"]
    ]
    if not matches:
        return None, errors
    if len(matches) > 1:
        return None, [f"duplicate exceptions for {finding['finding_id']}"]
    item = matches[0]
    for field in (
        "finding_id",
        "owner",
        "reason",
        "scope",
        "affected_artifact",
        "created_at",
        "expires_at",
        "approval",
    ):
        if not isinstance(item.get(field), str) or not str(item[field]).strip():
            errors.append(f"exception {finding['finding_id']} missing {field}")
    if errors:
        return None, errors
    if item["scope"] in {"*", "all", "global"} or item["scope"] != finding["scope"]:
        errors.append(f"exception {finding['finding_id']} has wrong CVE scope")
    if item["affected_artifact"] != finding["artifact"]:
        errors.append(f"exception {finding['finding_id']} targets the wrong artifact")
    if item.get("exact_sha") not in (None, head_sha):
        errors.append(f"exception {finding['finding_id']} exact SHA mismatch")
    if item.get("environment") not in (None, environment):
        errors.append(f"exception {finding['finding_id']} environment mismatch")
    try:
        created = _parse_time(item["created_at"], "exception created_at")
        expires = _parse_time(item["expires_at"], "exception expires_at")
        if expires <= created:
            errors.append(
                f"exception {finding['finding_id']} expiration must follow creation"
            )
        if expires <= now:
            errors.append(f"exception {finding['finding_id']} is expired")
    except ValueError as exc:
        errors.append(str(exc))
    expected_approval = f"/owner-authorization approve scope=cve-exception:{finding['finding_id']} sha={head_sha}"
    if item["approval"] != expected_approval:
        errors.append(
            f"exception {finding['finding_id']} approval is not exact-SHA owner authorization"
        )
    return (item if not errors else None), errors


def evaluate(
    payload: dict[str, Any],
    policy: dict[str, Any],
    root: Path,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    validate_policy(policy)
    evaluated_at = (now or datetime.now(UTC)).astimezone(UTC)
    reasons: list[str] = []
    base_sha = str(payload.get("base_sha", ""))
    head_sha = str(payload.get("head_sha", ""))
    tree_sha = str(payload.get("head_tree_sha", ""))
    if (
        not SHA_PATTERN.fullmatch(base_sha)
        or not SHA_PATTERN.fullmatch(head_sha)
        or not SHA_PATTERN.fullmatch(tree_sha)
    ):
        reasons.append("exact-SHA or tree identity is invalid")
    if payload.get("source_head_sha") not in (None, head_sha):
        reasons.append("exact-SHA mismatch")
    artifact = str(payload.get("artifact", "repository"))
    artifact_digest = payload.get("artifact_digest")
    release = bool(payload.get("release"))
    if release and (
        not isinstance(artifact_digest, str)
        or not DIGEST_PATTERN.fullmatch(artifact_digest)
    ):
        reasons.append("release artifact digest is missing or mutable")
    sbom_digest = payload.get("sbom_digest")
    sbom_artifact_digest = payload.get("sbom_artifact_digest")
    if sbom_artifact_digest is not None and sbom_artifact_digest != artifact_digest:
        reasons.append("SBOM/artifact mismatch")

    scanner_runs = payload.get("scanner_runs", [])
    if not isinstance(scanner_runs, list):
        scanner_runs = []
        reasons.append("scanner run inventory is malformed")
    scanner_index = {
        str(item.get("name")): item
        for item in scanner_runs
        if isinstance(item, dict) and item.get("name")
    }
    required_scanners = payload.get("required_scanners", [])
    if not isinstance(required_scanners, list):
        reasons.append("required scanner inventory is malformed")
        required_scanners = []
    for scanner in required_scanners:
        run = scanner_index.get(str(scanner))
        if run is None:
            reasons.append(f"required scanner missing: {scanner}")
        elif run.get("status") != "PASS":
            reasons.append(f"scanner failure: {scanner}")

    raw_findings = payload.get("findings", [])
    if not isinstance(raw_findings, list):
        reasons.append("scanner findings are malformed")
        raw_findings = []
    findings: list[dict[str, Any]] = []
    seen: dict[tuple[str, str, str], dict[str, Any]] = {}
    for raw in raw_findings:
        if not isinstance(raw, dict):
            reasons.append("scanner finding is malformed")
            continue
        finding_id = str(raw.get("finding_id", "")).upper()
        severity = str(raw.get("severity", "UNKNOWN")).upper()
        finding_artifact = str(raw.get("artifact", artifact))
        scanner = str(raw.get("scanner", "unknown"))
        if not CVE_PATTERN.fullmatch(finding_id) or severity not in SEVERITIES:
            reasons.append("scanner finding identifier or severity is malformed")
            continue
        cvss_value = raw.get("cvss")
        if cvss_value is not None:
            if (
                not isinstance(cvss_value, (int, float))
                or isinstance(cvss_value, bool)
                or not 0 <= cvss_value <= 10
            ):
                reasons.append(f"{finding_id} CVSS is invalid")
                continue
            cvss_value = float(cvss_value)
        normalized = dict(raw)
        normalized.update(
            {
                "finding_id": finding_id,
                "severity": _cvss_floor(policy, severity, cvss_value),
                "cvss": cvss_value,
                "artifact": finding_artifact,
                "scope": str(
                    raw.get("scope", payload.get("scope", "repository_filesystem"))
                ),
                "scanner": scanner,
                "fix_available": bool(raw.get("fix_available")),
            }
        )
        key = (finding_id, finding_artifact, scanner)
        if key in seen:
            if seen[key] != normalized:
                reasons.append(f"conflicting duplicate scanner finding: {finding_id}")
            continue
        seen[key] = normalized
        findings.append(normalized)

    dataset_state: dict[str, Any]
    if findings:
        try:
            dataset_state = _read_dataset_manifest(policy, root, evaluated_at)
        except ValueError as exc:
            reasons.append(str(exc))
            dataset_state = {"identities": {}, "kev_ids": set(), "epss_scores": {}}
    else:
        state = policy["risk_datasets"]["no_findings_dataset_state"]
        dataset_state = {
            "identities": {
                "kev": {
                    "status": state,
                    "source": policy["risk_datasets"]["kev"]["source"],
                },
                "epss": {
                    "status": state,
                    "source": policy["risk_datasets"]["epss"]["source"],
                },
            },
            "kev_ids": set(),
            "epss_scores": {},
        }

    exceptions = payload.get("exceptions", [])
    if not isinstance(exceptions, list):
        reasons.append("security exceptions are malformed")
        exceptions = []
    decisions: list[dict[str, Any]] = []
    exceptions_used: list[dict[str, Any]] = []
    threshold = float(policy["vulnerability_policy"]["epss_blocking_threshold"])
    environment = str(payload.get("environment", "development"))
    for finding in sorted(
        findings,
        key=lambda item: (item["finding_id"], item["artifact"], item["scanner"]),
    ):
        finding_id = finding["finding_id"]
        severity = finding["severity"]
        kev = finding_id in dataset_state["kev_ids"]
        epss = dataset_state["epss_scores"].get(finding_id)
        decision = "REPORT"
        decision_reasons: list[str] = []
        if severity == "CRITICAL":
            decision = "BLOCK"
            decision_reasons.append("CRITICAL is blocking whether fixed or unfixed")
        elif severity == "HIGH":
            decision = "BLOCK"
            decision_reasons.append(
                "HIGH requires remediation or governed temporary exception"
            )
        elif severity == "MEDIUM" and kev:
            decision = "BLOCK"
            decision_reasons.append("MEDIUM is listed in CISA KEV")
        elif severity == "MEDIUM" and epss is not None and epss >= threshold:
            decision = "BLOCK"
            decision_reasons.append(
                f"MEDIUM EPSS {epss:.5f} is at or above {threshold:.2f}"
            )
        elif severity == "UNKNOWN" and release:
            decision = "BLOCK"
            decision_reasons.append("UNKNOWN classification fails closed for release")
        elif severity == "UNKNOWN":
            decision_reasons.append("UNKNOWN requires explicit classification")
        else:
            decision_reasons.append(
                f"{severity} is report-only under current risk conditions"
            )
        if kev:
            decision_reasons.append("CISA KEV match")
        if finding.get("fix_available"):
            decision_reasons.append("fix available")
        else:
            decision_reasons.append("unfixed")
        deadline_hours = None
        severity_policy = policy["vulnerability_policy"].get(severity.lower(), {})
        if isinstance(severity_policy.get("remediation_deadline_hours"), int):
            deadline_hours = int(severity_policy["remediation_deadline_hours"])
        elif isinstance(severity_policy.get("remediation_deadline_days"), int):
            deadline_hours = int(severity_policy["remediation_deadline_days"]) * 24
        remediation_due_at = None
        remediation_overdue = False
        if deadline_hours is not None and finding.get("detected_at"):
            try:
                due = _parse_time(
                    finding["detected_at"], f"{finding_id} detected_at"
                ) + timedelta(hours=deadline_hours)
                remediation_due_at = _iso(due)
                remediation_overdue = evaluated_at > due
                if remediation_overdue:
                    decision_reasons.append("remediation deadline exceeded")
            except ValueError as exc:
                reasons.append(str(exc))
        exception, exception_errors = _exception_for(
            finding,
            exceptions,
            head_sha=head_sha,
            environment=environment,
            now=evaluated_at,
        )
        reasons.extend(exception_errors)
        if decision == "BLOCK" and exception is not None:
            if severity == "CRITICAL" and kev:
                decision_reasons.append("CRITICAL CISA KEV cannot be excepted")
            else:
                decision = "ACCEPTED_TEMPORARILY"
                exceptions_used.append(exception)
                decision_reasons.append("valid exact-scope temporary exception")
        decisions.append(
            {
                "finding_id": finding_id,
                "artifact": finding["artifact"],
                "severity": severity,
                "cvss": finding.get("cvss"),
                "fix_available": finding["fix_available"],
                "reachable": finding.get("reachable"),
                "kev": kev,
                "epss": epss,
                "decision": decision,
                "remediation_deadline_hours": deadline_hours,
                "remediation_due_at": remediation_due_at,
                "remediation_overdue": remediation_overdue,
                "reasons": decision_reasons,
            }
        )

    if any(item["decision"] == "BLOCK" for item in decisions):
        reasons.append("one or more vulnerability policy decisions are blocking")
    final = "BLOCK" if reasons else "PASS"
    versions = {
        str(item.get("name")): item.get("version")
        for item in scanner_runs
        if isinstance(item, dict)
    }
    checksums = {
        str(item.get("name")): item.get("checksum")
        for item in scanner_runs
        if isinstance(item, dict)
    }
    return {
        "schema_version": int(policy["evidence"]["schema_version"]),
        "base_sha": base_sha,
        "head_sha": head_sha,
        "head_tree_sha": tree_sha,
        "scanner_identities": sorted(scanner_index),
        "scanner_versions": versions,
        "tool_checksums": checksums,
        "kev_dataset_identity": dataset_state["identities"].get("kev", {}),
        "epss_dataset_identity": dataset_state["identities"].get("epss", {}),
        "artifact": artifact,
        "artifact_digest": artifact_digest,
        "sbom_digest": sbom_digest,
        "findings": findings,
        "policy_decisions": decisions,
        "exceptions_used": exceptions_used,
        "final_result": final,
        "reasons": sorted(set(reasons)),
        "generated_at": _iso(evaluated_at),
    }


def write_evidence(path: Path, evidence: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is missing or malformed") from exc
    if not isinstance(value, dict):
        raise TypeError(f"{label} must be a JSON object")
    return value


def sbom_identity(path: Path, artifact_digest: str | None) -> tuple[str, str | None]:
    raw = path.read_bytes()
    digest = "sha256:" + _sha256_bytes(raw)
    described = (
        artifact_digest
        if artifact_digest and artifact_digest in raw.decode("utf-8", errors="ignore")
        else None
    )
    return digest, described
