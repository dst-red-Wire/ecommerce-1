#!/usr/bin/env python3
"""Deterministic vulnerability policy evaluation and reproducible risk data."""

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
import architecture_authority
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
        policy.get("version") != 3
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
    identifiers = policy.get("advisory_identifiers")
    patterns = (
        identifiers.get("accepted_namespaces")
        if isinstance(identifiers, dict)
        else None
    )
    if not isinstance(patterns, dict) or set(patterns) != {"CVE", "GO", "GHSA", "OSV"}:
        raise ValueError("security scan policy advisory namespaces are invalid")
    for namespace, pattern in patterns.items():
        try:
            compiled = re.compile(str(pattern), re.IGNORECASE)
        except re.error as exc:
            raise ValueError(
                f"security advisory namespace {namespace} pattern is invalid"
            ) from exc
        sample = {
            "CVE": "CVE-2026-1234",
            "GO": "GO-2026-1234",
            "GHSA": "GHSA-XXXX-XXXX-XXXX",
            "OSV": "OSV-2026-1234",
        }[namespace]
        if not compiled.fullmatch(sample):
            raise ValueError(
                f"security advisory namespace {namespace} pattern is invalid"
            )
    non_cve = identifiers.get("non_cve_without_alias", {})
    if non_cve != {
        "kev": "NOT_APPLICABLE_NO_CVE_ALIAS",
        "epss": "NOT_APPLICABLE_NO_CVE_ALIAS",
        "automatic_pass": "forbidden",
        "release_unknown_or_reachable_unfixed": "BLOCK",
        "exact_unreachable": "REPORT",
    }:
        raise ValueError("non-CVE advisory policy must remain fail closed")
    reachability = vulnerability.get("reachability", {})
    if (
        reachability.get("scanner") != "govulncheck"
        or reachability.get("exact_proof_modes") != ["source", "binary"]
        or reachability.get("exact_proof_level") != "symbol"
        or reachability.get("exact_unreachable_release") != "REPORT"
        or reachability.get("unknown_reachability_release") != "risk-not-reduced"
    ):
        raise ValueError("Go reachability policy must remain exact and fail closed")
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
        or exceptions.get("approval_authentication")
        != "trusted-out-of-band-owner-record-required"
        or exceptions.get("untrusted_local_record") != "BLOCK"
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


def _identifier_namespace(value: object, policy: dict[str, Any]) -> str | None:
    identifier = str(value or "").strip().upper()
    patterns = policy["advisory_identifiers"]["accepted_namespaces"]
    matches = [
        namespace
        for namespace, pattern in patterns.items()
        if re.fullmatch(str(pattern), identifier, re.IGNORECASE)
    ]
    return matches[0] if len(matches) == 1 else None


def _normalize_identifiers(
    finding_id: object, aliases: object, policy: dict[str, Any]
) -> tuple[str, str, list[str]]:
    identifier = str(finding_id or "").strip().upper()
    namespace = _identifier_namespace(identifier, policy)
    if namespace is None:
        raise ValueError(f"malformed advisory identifier: {identifier or '<empty>'}")
    if aliases is None:
        values: list[object] = []
    elif isinstance(aliases, list):
        values = aliases
    else:
        raise ValueError(f"aliases for {identifier} are malformed")
    normalized: set[str] = set()
    for value in values:
        alias = str(value or "").strip().upper()
        if not alias or _identifier_namespace(alias, policy) is None:
            raise ValueError(f"invalid alias for {identifier}: {alias or '<empty>'}")
        if alias != identifier:
            normalized.add(alias)
    return identifier, namespace, sorted(normalized)


def _ecosystem(result: dict[str, Any], finding_id: str) -> str:
    kind = str(result.get("Type", "")).lower()
    if kind in {"gobinary", "gomod"} or finding_id.startswith("GO-"):
        return "Go"
    return str(result.get("Type") or result.get("Class") or "unknown")


def parse_json_stream(raw: str, label: str) -> list[dict[str, Any]]:
    decoder = json.JSONDecoder()
    offset = 0
    values: list[dict[str, Any]] = []
    while offset < len(raw):
        while offset < len(raw) and raw[offset].isspace():
            offset += 1
        if offset == len(raw):
            break
        try:
            value, offset = decoder.raw_decode(raw, offset)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{label} is missing or malformed") from exc
        if not isinstance(value, dict):
            raise TypeError(f"{label} entries must be JSON objects")
        values.append(value)
    if not values:
        raise ValueError(f"{label} is missing or malformed")
    return values


def load_json_stream(path: Path, label: str) -> list[dict[str, Any]]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"{label} is missing or malformed") from exc
    return parse_json_stream(raw, label)


def trivy_findings(
    payload: dict[str, Any], *, artifact: str, scope: str
) -> list[dict[str, Any]]:
    results = payload.get("Results")
    if results is None:
        if payload.get("SchemaVersion") == 2 and payload.get("ArtifactType") in {
            "filesystem",
            "container_image",
            "repository",
        }:
            return []
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
                    "identifier_namespace": None,
                    "aliases": sorted(
                        {
                            str(alias).upper()
                            for alias in item.get("Aliases") or []
                            if str(alias).strip()
                        }
                    ),
                    "severity": str(item.get("Severity", "UNKNOWN")).upper(),
                    "cvss": max(cvss_scores) if cvss_scores else None,
                    "fix_available": bool(str(item.get("FixedVersion", "")).strip()),
                    "fixed_version": str(item.get("FixedVersion", "")),
                    "reachable": item.get("Reachable"),
                    "presence": "module"
                    if _ecosystem(result, str(item.get("VulnerabilityID", "")).upper())
                    == "Go"
                    else "package",
                    "reachability_evidence": None,
                    "artifact": artifact,
                    "scope": scope,
                    "scanner": "trivy",
                    "ecosystem": _ecosystem(
                        result, str(item.get("VulnerabilityID", "")).upper()
                    ),
                    "package": str(item.get("PkgName", "")),
                    "installed_version": str(item.get("InstalledVersion", "")),
                    "detected_at": item.get("PublishedDate"),
                }
            )
    return findings


def govulncheck_findings(
    events: list[dict[str, Any]], *, artifact: str, scope: str, target: str = "artifact"
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    config = next(
        (item["config"] for item in events if isinstance(item.get("config"), dict)),
        None,
    )
    if not isinstance(config, dict) or config.get("scanner_name") != "govulncheck":
        raise ValueError("govulncheck output is missing scanner configuration")
    scan_mode = str(config.get("scan_mode", ""))
    scan_level = str(config.get("scan_level", ""))
    if scan_mode not in {"source", "binary"} or scan_level != "symbol":
        raise ValueError("govulncheck output is not exact symbol-level evidence")
    advisories = {
        str(item["osv"].get("id", "")).upper(): item["osv"]
        for item in events
        if isinstance(item.get("osv"), dict) and item["osv"].get("id")
    }
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in events:
        finding = item.get("finding")
        if not isinstance(finding, dict):
            continue
        identifier = str(finding.get("osv", "")).upper()
        grouped.setdefault(identifier, []).append(finding)
    findings: list[dict[str, Any]] = []
    for identifier, matches in sorted(grouped.items()):
        advisory = advisories.get(identifier)
        if advisory is None:
            raise ValueError(
                f"govulncheck advisory metadata is missing for {identifier}"
            )
        if not isinstance(advisory, dict):
            raise TypeError(
                f"govulncheck advisory metadata is malformed for {identifier}"
            )
        traces = [
            trace
            for match in matches
            for trace in (match.get("trace") or [])
            if isinstance(trace, dict)
        ]
        if not traces:
            raise ValueError(f"govulncheck trace is missing for {identifier}")
        symbol_present = any(str(trace.get("function", "")).strip() for trace in traces)
        package_present = any(str(trace.get("package", "")).strip() for trace in traces)
        module_frames = [
            trace for trace in traces if str(trace.get("module", "")).strip()
        ]
        if not module_frames:
            raise ValueError(f"govulncheck module identity is missing for {identifier}")
        presence = (
            "symbol" if symbol_present else "package" if package_present else "module"
        )
        affected = advisory.get("affected") or []
        advisory_package = next(
            (
                item.get("package", {})
                for item in affected
                if isinstance(item, dict) and isinstance(item.get("package"), dict)
            ),
            {},
        )
        fixed_versions = {
            str(match.get("fixed_version", "")).strip() for match in matches
        } - {""}
        if len(fixed_versions) > 1:
            raise ValueError(f"govulncheck fixed versions conflict for {identifier}")
        installed_versions = {
            str(frame.get("version", "")).strip() for frame in module_frames
        } - {""}
        if len(installed_versions) > 1:
            raise ValueError(
                f"govulncheck installed versions conflict for {identifier}"
            )
        findings.append(
            {
                "finding_id": identifier,
                "identifier_namespace": None,
                "aliases": list(advisory.get("aliases") or []),
                "scanner": "govulncheck",
                "ecosystem": str(advisory_package.get("ecosystem") or "Go"),
                "package": str(
                    advisory_package.get("name") or module_frames[0]["module"]
                ),
                "installed_version": next(iter(installed_versions), ""),
                "fixed_version": next(iter(fixed_versions), ""),
                "fix_available": bool(fixed_versions),
                "severity": "UNKNOWN",
                "cvss": None,
                "reachable": symbol_present,
                "presence": presence,
                "reachability_evidence": {
                    "scanner": "govulncheck",
                    "scan_mode": scan_mode,
                    "scan_level": scan_level,
                    "db": config.get("db"),
                    "db_last_modified": config.get("db_last_modified"),
                },
                "artifact": artifact,
                "scope": scope,
                "target": target,
                "detected_at": advisory.get("published"),
            }
        )
    return findings, config


def _normalize_observation(
    raw: dict[str, Any], payload: dict[str, Any], policy: dict[str, Any]
) -> dict[str, Any]:
    finding_id, namespace, aliases = _normalize_identifiers(
        raw.get("finding_id"), raw.get("aliases", []), policy
    )
    declared_namespace = raw.get("identifier_namespace")
    if declared_namespace not in (None, "", namespace):
        raise ValueError(f"identifier namespace conflicts for {finding_id}")
    severity = str(raw.get("severity", "UNKNOWN")).upper()
    if severity not in SEVERITIES:
        raise ValueError(f"severity is malformed for {finding_id}")
    cvss_value = raw.get("cvss")
    if cvss_value is not None:
        if (
            not isinstance(cvss_value, (int, float))
            or isinstance(cvss_value, bool)
            or not 0 <= cvss_value <= 10
        ):
            raise ValueError(f"{finding_id} CVSS is invalid")
        cvss_value = float(cvss_value)
    scanner = str(raw.get("scanner", "")).strip()
    ecosystem = str(raw.get("ecosystem", "")).strip()
    package = str(raw.get("package", "")).strip()
    installed = str(raw.get("installed_version", "")).strip()
    if not scanner or not ecosystem or not package or not installed:
        raise ValueError(f"required advisory fields are missing for {finding_id}")
    fixed_version = str(raw.get("fixed_version", "")).strip()
    fix_available = bool(raw.get("fix_available"))
    if fix_available != bool(fixed_version):
        raise ValueError(f"fix state conflicts for {finding_id}")
    reachable = raw.get("reachable")
    if reachable not in (True, False, None):
        raise ValueError(f"reachability is malformed for {finding_id}")
    evidence = raw.get("reachability_evidence")
    if reachable is False:
        expected = policy["vulnerability_policy"]["reachability"]
        if (
            scanner != expected["scanner"]
            or not isinstance(evidence, dict)
            or evidence.get("scanner") != expected["scanner"]
            or evidence.get("scan_mode") not in expected["exact_proof_modes"]
            or evidence.get("scan_level") != expected["exact_proof_level"]
        ):
            raise ValueError(
                f"unreachable state lacks exact govulncheck proof for {finding_id}"
            )
    presence = str(raw.get("presence", "unknown"))
    if presence not in {"module", "package", "symbol", "unknown"}:
        raise ValueError(f"presence is malformed for {finding_id}")
    artifact = str(raw.get("artifact", payload.get("artifact", "repository")))
    scope = str(raw.get("scope", payload.get("scope", "repository_filesystem")))
    return {
        **raw,
        "finding_id": finding_id,
        "identifier_namespace": namespace,
        "aliases": aliases,
        "severity": _cvss_floor(policy, severity, cvss_value),
        "cvss": cvss_value,
        "scanner": scanner,
        "ecosystem": ecosystem,
        "package": package,
        "installed_version": installed,
        "fixed_version": fixed_version,
        "fix_available": fix_available,
        "reachable": reachable,
        "presence": presence,
        "artifact": artifact,
        "scope": scope,
        "target": str(raw.get("target", "artifact")),
    }


def _identifier_priority(identifier: str, policy: dict[str, Any]) -> tuple[int, str]:
    namespace = _identifier_namespace(identifier, policy)
    order = {"CVE": 0, "GO": 1, "GHSA": 2, "OSV": 3}
    return order.get(str(namespace), 99), identifier


def _normalized_findings(
    raw_findings: list[object], payload: dict[str, Any], policy: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    reasons: list[str] = []
    observations: list[dict[str, Any]] = []
    exact_seen: dict[tuple[str, str, str, str, str, str, str], dict[str, Any]] = {}
    for raw in raw_findings:
        if not isinstance(raw, dict):
            reasons.append("scanner finding is malformed")
            continue
        try:
            observation = _normalize_observation(raw, payload, policy)
        except ValueError as exc:
            reasons.append(str(exc))
            continue
        key = (
            observation["finding_id"],
            observation["artifact"],
            observation["scope"],
            observation["scanner"],
            observation["target"],
            observation["package"],
            observation["installed_version"],
        )
        if key in exact_seen:
            if exact_seen[key] != observation:
                reasons.append(
                    f"conflicting duplicate scanner finding: {observation['finding_id']}"
                )
            continue
        exact_seen[key] = observation
        observations.append(observation)

    groups: list[dict[str, Any]] = []
    for observation in sorted(
        observations,
        key=lambda item: (
            item["artifact"],
            item["scope"],
            _identifier_priority(item["finding_id"], policy),
            item["scanner"],
            item["target"],
            item["package"],
        ),
    ):
        identifiers = {observation["finding_id"], *observation["aliases"]}
        matches = [
            group
            for group in groups
            if group["artifact"] == observation["artifact"]
            and group["scope"] == observation["scope"]
            and group["component"]
            == (
                observation["ecosystem"],
                observation["package"],
                observation["installed_version"],
            )
            and identifiers.intersection(group["identifiers"])
        ]
        if not matches:
            groups.append(
                {
                    "artifact": observation["artifact"],
                    "scope": observation["scope"],
                    "component": (
                        observation["ecosystem"],
                        observation["package"],
                        observation["installed_version"],
                    ),
                    "identifiers": set(identifiers),
                    "observations": [observation],
                }
            )
            continue
        primary = matches[0]
        primary["identifiers"].update(identifiers)
        primary["observations"].append(observation)
        for extra in matches[1:]:
            primary["identifiers"].update(extra["identifiers"])
            primary["observations"].extend(extra["observations"])
            groups.remove(extra)

    normalized: list[dict[str, Any]] = []
    severity_order = {severity: index for index, severity in enumerate(SEVERITIES)}
    presence_order = {"unknown": 0, "module": 1, "package": 2, "symbol": 3}
    for group in groups:
        items = group["observations"]
        identifiers = sorted(
            group["identifiers"], key=lambda value: _identifier_priority(value, policy)
        )
        canonical = identifiers[0]
        known_severities = {item["severity"] for item in items} - {"UNKNOWN"}
        if len(known_severities) > 1:
            reasons.append(f"conflicting scanner severity data: {canonical}")
        for field in ("ecosystem", "package", "installed_version"):
            values = {str(item.get(field, "")) for item in items} - {"", "unknown"}
            if len(values) > 1:
                reasons.append(f"conflicting scanner {field} data: {canonical}")
        fixed_versions = {item["fixed_version"] for item in items} - {""}
        fix_states = {item["fix_available"] for item in items}
        if len(fixed_versions) > 1 or (fixed_versions and fix_states == {True, False}):
            reasons.append(f"conflicting scanner fix data: {canonical}")
        exact_reachability = [
            item["reachable"]
            for item in items
            if item["scanner"]
            == policy["vulnerability_policy"]["reachability"]["scanner"]
            and item["reachable"] is not None
        ]
        reachable = any(exact_reachability) if exact_reachability else None
        severity = max(
            (item["severity"] for item in items),
            key=lambda value: severity_order[value],
        )
        cvss_values = [item["cvss"] for item in items if item["cvss"] is not None]
        ecosystem = next(
            (item["ecosystem"] for item in items if item["ecosystem"] != "unknown"),
            "unknown",
        )
        package = next((item["package"] for item in items if item["package"]), "")
        installed = next(
            (item["installed_version"] for item in items if item["installed_version"]),
            "",
        )
        presence = max(
            (item["presence"] for item in items),
            key=lambda value: presence_order[value],
        )
        reachability_evidence = next(
            (
                item.get("reachability_evidence")
                for item in items
                if item["scanner"]
                == policy["vulnerability_policy"]["reachability"]["scanner"]
                and item.get("reachability_evidence")
            ),
            None,
        )
        normalized.append(
            {
                "finding_id": canonical,
                "identifier_namespace": _identifier_namespace(canonical, policy),
                "aliases": identifiers[1:],
                "identifiers": identifiers,
                "scanners": sorted({item["scanner"] for item in items}),
                "ecosystem": ecosystem,
                "package": package,
                "installed_version": installed,
                "fixed_version": next(iter(sorted(fixed_versions)), ""),
                "fix_available": bool(fixed_versions),
                "severity": severity,
                "cvss": max(cvss_values) if cvss_values else None,
                "reachable": reachable,
                "presence": presence,
                "reachability_evidence": reachability_evidence,
                "artifact": group["artifact"],
                "scope": group["scope"],
                "detected_at": next(
                    (
                        item.get("detected_at")
                        for item in items
                        if item.get("detected_at")
                    ),
                    None,
                ),
                "observations": sorted(
                    items,
                    key=lambda item: (
                        item["scanner"],
                        item["finding_id"],
                        item["target"],
                        item["package"],
                    ),
                ),
            }
        )
    def observation_order(item: dict[str, Any]) -> tuple[Any, ...]:
        return (
            item["artifact"],
            item["scope"],
            _identifier_priority(item["finding_id"], policy),
            item["scanner"],
            item["target"],
            item["package"],
        )

    normalized.sort(
        key=lambda item: (item["artifact"], item["scope"], item["finding_id"])
    )
    return sorted(observations, key=observation_order), normalized, reasons


def _exception_for(
    finding: dict[str, Any],
    exceptions: list[dict[str, Any]],
    *,
    head_sha: str,
    environment: str,
    now: datetime,
    trusted_owner_authorizations: dict[str, dict[str, Any]],
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
        errors.append(f"exception {finding['finding_id']} has wrong advisory scope")
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
    approval_scope = f"vulnerability-exception:{finding['finding_id']}"
    trust = trusted_owner_authorizations.get(item["approval"])
    if not isinstance(trust, dict):
        errors.append(
            f"exception {finding['finding_id']} owner authorization is not authenticated"
        )
    else:
        authorization_errors = architecture_authority.owner_authorization_errors(
            item["approval"],
            expected_scope=approval_scope,
            head_sha=head_sha,
            decision_authority=trust.get("decision_authority"),
            recording_agent=trust.get("recording_agent"),
            explicit_owner_instruction=trust.get("explicit_owner_instruction") is True,
        )
        errors.extend(
            f"exception {finding['finding_id']} {error}" for error in authorization_errors
        )
    return (item if not errors else None), errors


def evaluate(
    payload: dict[str, Any],
    policy: dict[str, Any],
    root: Path,
    *,
    now: datetime | None = None,
    trusted_owner_authorizations: dict[str, dict[str, Any]] | None = None,
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

    scope = str(payload.get("scope", ""))
    scope_contract = policy.get("scan_scopes", {}).get(scope)
    if not isinstance(scope_contract, dict):
        reasons.append(f"unknown security scan scope: {scope or '<empty>'}")
        canonical_required_scanners: list[str] = []
    else:
        scanners = scope_contract.get("scanners")
        if not isinstance(scanners, list) or not all(
            isinstance(scanner, str) and scanner for scanner in scanners
        ):
            reasons.append(f"security scan scope has invalid scanner contract: {scope}")
            canonical_required_scanners = []
        else:
            canonical_required_scanners = list(dict.fromkeys(scanners))

    scanner_runs = payload.get("scanner_runs", [])
    if not isinstance(scanner_runs, list):
        scanner_runs = []
        reasons.append("scanner run inventory is malformed")
    scanner_index: dict[str, dict[str, Any]] = {}
    for item in scanner_runs:
        name = item.get("name") if isinstance(item, dict) else None
        if not isinstance(name, str) or not name or name != name.strip():
            reasons.append("scanner run is malformed")
            continue
        if name in scanner_index:
            reasons.append(f"duplicate scanner run: {name}")
            continue
        scanner_index[name] = item
    claimed_scanners = payload.get("required_scanners", [])
    if not isinstance(claimed_scanners, list) or not all(
        isinstance(scanner, str) and scanner for scanner in claimed_scanners
    ):
        reasons.append("claimed scanner inventory is malformed")
        claimed_scanners = []
    missing_claims = sorted(set(canonical_required_scanners) - set(claimed_scanners))
    for scanner in missing_claims:
        reasons.append(f"claimed scanner inventory omits contract requirement: {scanner}")
    required_scanners = sorted(
        set(canonical_required_scanners) | set(claimed_scanners)
    )
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
    observations, findings, normalization_reasons = _normalized_findings(
        raw_findings, payload, policy
    )
    reasons.extend(normalization_reasons)

    dataset_state: dict[str, Any]
    cve_identifiers = {
        identifier
        for finding in findings
        for identifier in finding["identifiers"]
        if _identifier_namespace(identifier, policy) == "CVE"
    }
    if cve_identifiers:
        try:
            dataset_state = _read_dataset_manifest(policy, root, evaluated_at)
        except ValueError as exc:
            reasons.append(str(exc))
            dataset_state = {"identities": {}, "kev_ids": set(), "epss_scores": {}}
    elif findings:
        state = policy["risk_datasets"]["non_cve_without_alias_dataset_state"]
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
    if trusted_owner_authorizations is None:
        trusted_owner_authorizations = {}
    elif not isinstance(trusted_owner_authorizations, dict):
        reasons.append("trusted owner authorization inventory is malformed")
        trusted_owner_authorizations = {}
    decisions: list[dict[str, Any]] = []
    exceptions_used: list[dict[str, Any]] = []
    threshold = float(policy["vulnerability_policy"]["epss_blocking_threshold"])
    environment = str(payload.get("environment", "development"))
    for finding in sorted(
        findings,
        key=lambda item: (item["finding_id"], item["artifact"]),
    ):
        finding_id = finding["finding_id"]
        severity = finding["severity"]
        cve_aliases = [
            identifier
            for identifier in finding["identifiers"]
            if _identifier_namespace(identifier, policy) == "CVE"
        ]
        datasets_applicable = bool(cve_aliases)
        kev = (
            any(identifier in dataset_state["kev_ids"] for identifier in cve_aliases)
            if datasets_applicable
            else None
        )
        epss_values = [
            dataset_state["epss_scores"][identifier]
            for identifier in cve_aliases
            if identifier in dataset_state["epss_scores"]
        ]
        epss = max(epss_values) if epss_values else None
        decision = "REPORT"
        decision_reasons: list[str] = []
        exact_unreachable = finding.get("reachable") is False
        non_cve_without_alias = (
            finding["identifier_namespace"] != "CVE" and not cve_aliases
        )
        if exact_unreachable:
            decision = policy["vulnerability_policy"]["reachability"][
                "exact_unreachable_release"
            ]
            decision_reasons.append(
                "not symbol-reachable according to exact govulncheck evidence"
            )
        elif non_cve_without_alias and release and not finding.get("fix_available"):
            decision = policy["advisory_identifiers"]["non_cve_without_alias"][
                "release_unknown_or_reachable_unfixed"
            ]
            decision_reasons.append(
                "non-CVE advisory without CVE alias or fix cannot pass automatically"
            )
        elif severity == "CRITICAL":
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
        if kev is True:
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
            trusted_owner_authorizations=trusted_owner_authorizations,
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
                "identifier_namespace": finding["identifier_namespace"],
                "aliases": finding["aliases"],
                "identifiers": finding["identifiers"],
                "artifact": finding["artifact"],
                "severity": severity,
                "cvss": finding.get("cvss"),
                "fix_available": finding["fix_available"],
                "reachable": finding.get("reachable"),
                "presence": finding.get("presence"),
                "kev": kev,
                "epss": epss,
                "kev_status": (
                    "APPLICABLE"
                    if datasets_applicable
                    else "NOT_APPLICABLE_NO_CVE_ALIAS"
                ),
                "epss_status": (
                    "APPLICABLE"
                    if datasets_applicable
                    else "NOT_APPLICABLE_NO_CVE_ALIAS"
                ),
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
    versions = {name: item.get("version") for name, item in scanner_index.items()}
    checksums = {name: item.get("checksum") for name, item in scanner_index.items()}
    return {
        "schema_version": int(policy["evidence"]["schema_version"]),
        "base_sha": base_sha,
        "head_sha": head_sha,
        "head_tree_sha": tree_sha,
        "scanner_identities": sorted(scanner_index),
        "required_scanners": canonical_required_scanners,
        "claimed_scanners": sorted(set(claimed_scanners)),
        "scanner_versions": versions,
        "tool_checksums": checksums,
        "kev_dataset_identity": dataset_state["identities"].get("kev", {}),
        "epss_dataset_identity": dataset_state["identities"].get("epss", {}),
        "artifact": artifact,
        "artifact_digest": artifact_digest,
        "sbom_digest": sbom_digest,
        "observations": observations,
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
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("SPDX SBOM is malformed") from exc
    if not isinstance(document, dict):
        raise ValueError("SPDX SBOM must be a JSON object")
    if (
        not str(document.get("spdxVersion", "")).startswith("SPDX-")
        or document.get("SPDXID") != "SPDXRef-DOCUMENT"
        or not isinstance(document.get("name"), str)
        or not document.get("name")
        or not isinstance(document.get("documentNamespace"), str)
        or not document.get("documentNamespace")
    ):
        raise ValueError("SPDX document identity is invalid")
    describes = document.get("documentDescribes")
    packages = document.get("packages")
    if (
        not isinstance(describes, list)
        or not describes
        or not all(isinstance(item, str) and item for item in describes)
        or not isinstance(packages, list)
    ):
        raise ValueError("SPDX root artifact description is missing")
    package_index = {
        package.get("SPDXID"): package
        for package in packages
        if isinstance(package, dict) and isinstance(package.get("SPDXID"), str)
    }
    if any(subject not in package_index for subject in describes):
        raise ValueError("SPDX documentDescribes references an unknown package")

    described_digests: set[str] = set()
    for subject in describes:
        package = package_index[subject]
        for checksum in package.get("checksums") or []:
            if (
                isinstance(checksum, dict)
                and str(checksum.get("algorithm", "")).upper() == "SHA256"
                and re.fullmatch(r"[0-9a-fA-F]{64}", str(checksum.get("checksumValue", "")))
            ):
                described_digests.add(
                    "sha256:" + str(checksum["checksumValue"]).lower()
                )
        for reference in package.get("externalRefs") or []:
            if not isinstance(reference, dict):
                continue
            reference_type = str(reference.get("referenceType", "")).lower()
            locator = str(reference.get("referenceLocator", ""))
            if reference_type not in {"purl", "other"}:
                continue
            match = re.search(
                r"(?:@|digest=|oci-digest:)(sha256:[0-9a-fA-F]{64})(?:$|[?&#])",
                locator,
            )
            if match:
                described_digests.add(match.group(1).lower())
    normalized_artifact = artifact_digest.lower() if isinstance(artifact_digest, str) else None
    described = normalized_artifact if normalized_artifact in described_digests else None
    return digest, described
