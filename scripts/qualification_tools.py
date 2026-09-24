#!/usr/bin/env python3
"""Validate and smoke-test the centrally governed qualification toolset."""

from __future__ import annotations

import argparse
from collections import Counter
from contextlib import contextmanager
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from threading import Thread
from typing import Any, Iterator
from urllib.parse import urlparse
import xml.etree.ElementTree as ET

import yaml


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "config/contracts/qualification-tools.yaml"
TOOLCHAIN_PATH = ROOT / "config/contracts/toolchain-lock.json"
SLO_PATH = ROOT / "config/contracts/service-slo.yaml"
FIXTURES = ROOT / "tests/fixtures/qualification-tools"
POLICIES = ROOT / "config/policies/qualification"
MAX_EVIDENCE_BYTES = 16 * 1024 * 1024


class QualificationError(ValueError):
    """A deterministic contract, execution, or evidence failure."""


def _read_bounded(path: Path, *, allow_empty: bool = False) -> bytes:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise QualificationError(f"evidence unavailable: {path}") from exc
    if size < 0 or size > MAX_EVIDENCE_BYTES or (size == 0 and not allow_empty):
        raise QualificationError(f"evidence size outside accepted bounds: {path}")
    return path.read_bytes()


def _load_json(path: Path) -> Any:
    try:
        return json.loads(_read_bounded(path))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise QualificationError(f"invalid JSON evidence: {path}") from exc


def _json_lines(path: Path, *, allow_empty: bool = False) -> list[dict[str, Any]]:
    try:
        text = _read_bounded(path, allow_empty=allow_empty).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise QualificationError(f"invalid UTF-8 JSONL evidence: {path}") from exc
    records: list[dict[str, Any]] = []
    for number, raw in enumerate(text.splitlines(), 1):
        if not raw.strip():
            continue
        try:
            record = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise QualificationError(
                f"invalid JSONL evidence at line {number}: {path}"
            ) from exc
        if not isinstance(record, dict):
            raise QualificationError(
                f"JSONL evidence line {number} is not an object: {path}"
            )
        records.append(record)
    if not records and not allow_empty:
        raise QualificationError(f"JSONL evidence contains no records: {path}")
    return records


def parse_openscap(path: Path) -> dict[str, Any]:
    raw = _read_bounded(path)
    upper = raw.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise QualificationError(
            "OpenSCAP XML evidence may not contain DTD or entity declarations"
        )
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise QualificationError(f"invalid OpenSCAP XML evidence: {path}") from exc
    results = []
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] != "rule-result":
            continue
        result = next(
            (
                child.text.strip().lower()
                for child in element
                if child.tag.rsplit("}", 1)[-1] == "result" and child.text
            ),
            "",
        )
        if result:
            results.append(result)
    if not results:
        raise QualificationError("OpenSCAP evidence contains no rule results")
    counts = dict(sorted(Counter(results).items()))
    if any(counts.get(status, 0) for status in ("fail", "error", "unknown")):
        final = "FAIL"
    elif any(
        counts.get(status, 0)
        for status in ("notchecked", "notapplicable", "notselected", "informational")
    ):
        final = "BLOCK"
    else:
        final = "PASS"
    return {"result_counts": counts, "final_result": final}


def _collect_statuses(value: Any) -> list[str]:
    statuses: list[str] = []
    if isinstance(value, dict):
        status = value.get("status")
        if isinstance(status, str):
            statuses.append(status.upper())
        for nested in value.values():
            statuses.extend(_collect_statuses(nested))
    elif isinstance(value, list):
        for nested in value:
            statuses.extend(_collect_statuses(nested))
    return statuses


def parse_kube_bench(path: Path, *, compatible: bool = True) -> dict[str, Any]:
    document = _load_json(path)
    statuses = _collect_statuses(document)
    accepted = {"PASS", "FAIL", "WARN", "INFO"}
    statuses = [status for status in statuses if status in accepted]
    if not statuses:
        raise QualificationError(
            "kube-bench evidence contains no recognized result statuses"
        )
    counts = dict(sorted(Counter(statuses).items()))
    if not compatible:
        final = "BLOCK"
    elif counts.get("FAIL", 0) or counts.get("WARN", 0):
        final = "FAIL"
    else:
        final = "PASS"
    return {"totals": counts, "final_result": final}


def parse_k6(path: Path) -> dict[str, Any]:
    document = _load_json(path)
    metrics = document.get("metrics") if isinstance(document, dict) else None
    if not isinstance(metrics, dict) or not metrics:
        raise QualificationError("k6 evidence contains no metrics")
    thresholds: dict[str, bool] = {}
    for metric_name, metric in metrics.items():
        if not isinstance(metric, dict):
            continue
        raw_thresholds = metric.get("thresholds", {})
        if not isinstance(raw_thresholds, dict):
            raise QualificationError(f"k6 metric {metric_name} has invalid thresholds")
        for expression, result in raw_thresholds.items():
            if type(result) is not bool:
                raise QualificationError(
                    f"k6 threshold {metric_name}:{expression} has no boolean result"
                )
            # k6 2.x summary-export records whether the threshold was crossed,
            # not whether it passed: false means satisfied, true means failed.
            thresholds[f"{metric_name}:{expression}"] = not result
    if not thresholds:
        raise QualificationError("k6 evidence contains no evaluated thresholds")
    return {
        "thresholds": thresholds,
        "final_result": "PASS" if all(thresholds.values()) else "FAIL",
    }


def _authorized_loopback_target(target: str) -> None:
    parsed = urlparse(target)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        raise QualificationError(
            "Nuclei target must be an HTTP(S) URL without user info"
        )
    if parsed.hostname == "localhost":
        return
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise QualificationError(
            "Nuclei smoke target must resolve by explicit loopback identity"
        ) from exc
    if not address.is_loopback:
        raise QualificationError(
            "Nuclei smoke target is outside the authorized loopback scope"
        )


def parse_nuclei(
    path: Path,
    *,
    scanner_exit_code: int,
    allowed_template_ids: set[str] | None = None,
) -> dict[str, Any]:
    if scanner_exit_code != 0:
        raise QualificationError(
            f"Nuclei execution failed with exit code {scanner_exit_code}"
        )
    records = _json_lines(path, allow_empty=True)
    allowed = allowed_template_ids or set()
    blocking = []
    for record in records:
        template_id = record.get("template-id") or record.get("templateID")
        if not isinstance(template_id, str) or not template_id:
            raise QualificationError("Nuclei finding is missing template identity")
        if template_id not in allowed:
            blocking.append(template_id)
    return {
        "findings": len(records),
        "blocking_templates": sorted(set(blocking)),
        "final_result": "FAIL" if blocking else "PASS",
    }


def parse_hubble(
    path: Path,
    *,
    assertions: set[str],
    compatible: bool = True,
) -> dict[str, Any]:
    if not assertions:
        raise QualificationError("Hubble evidence requires explicit assertions")
    records = _json_lines(path)
    observations = {
        "expected-allow": 0,
        "expected-drop": 0,
        "expected-dns": 0,
        "policy-enforcement": 0,
    }
    for record in records:
        flow = record.get("flow", record)
        if not isinstance(flow, dict):
            raise QualificationError("Hubble record has no flow object")
        verdict = str(flow.get("verdict", "")).upper()
        if verdict in {"FORWARDED", "REDIRECTED", "AUDIT"}:
            observations["expected-allow"] += 1
        if (
            verdict == "DROPPED"
            and str(flow.get("drop_reason_desc", "")).upper() == "POLICY_DENIED"
        ):
            observations["expected-drop"] += 1
            observations["policy-enforcement"] += 1
        if isinstance(flow.get("l7"), dict) and isinstance(flow["l7"].get("dns"), dict):
            observations["expected-dns"] += 1
    unknown = assertions - set(observations)
    if unknown:
        raise QualificationError(f"unsupported Hubble assertions: {sorted(unknown)}")
    satisfied = {name: observations[name] > 0 for name in sorted(assertions)}
    final = (
        "BLOCK" if not compatible else ("PASS" if all(satisfied.values()) else "FAIL")
    )
    return {
        "assertions": satisfied,
        "observations": observations,
        "final_result": final,
    }


def normalize_pint(exit_code: int, diagnostics: str) -> dict[str, Any]:
    if type(exit_code) is not int or exit_code < 0:
        raise QualificationError("Pint exit code is invalid")
    return {
        "diagnostics": [line for line in diagnostics.splitlines() if line.strip()][
            :100
        ],
        "final_result": "PASS" if exit_code == 0 else "FAIL",
    }


def _registry_entry(toolchain: dict[str, Any], reference: str) -> dict[str, Any]:
    prefix = "config/contracts/toolchain-lock.json#tools."
    if not reference.startswith(prefix):
        raise QualificationError(
            f"qualification tool uses a non-central registry reference: {reference}"
        )
    name = reference.removeprefix(prefix)
    entry = toolchain.get("tools", {}).get(name)
    if not isinstance(entry, dict):
        raise QualificationError(
            f"qualification tool references missing registry entry: {name}"
        )
    return entry


def validate_contract(root: Path = ROOT) -> dict[str, Any]:
    contract = yaml.safe_load(
        (root / CONTRACT_PATH.relative_to(ROOT)).read_text(encoding="utf-8")
    )
    toolchain = json.loads(
        (root / TOOLCHAIN_PATH.relative_to(ROOT)).read_text(encoding="utf-8")
    )
    architecture = yaml.safe_load(
        (root / "architecture.lock.yaml").read_text(encoding="utf-8")
    )
    if (
        contract.get("status") != "exact"
        or contract.get("architecture_authority") != "architecture.lock.yaml"
    ):
        raise QualificationError(
            "qualification tool contract must inherit the exact architecture authority"
        )
    if (
        architecture.get("machine_contracts", {}).get("qualification_tools")
        != "config/contracts/qualification-tools.yaml"
    ):
        raise QualificationError(
            "qualification tools must be registered by architecture.lock.yaml"
        )
    expected = {
        "openscap",
        "scap-security-guide",
        "kube-bench",
        "conftest",
        "opa",
        "k6",
        "nuclei",
        "hubble",
        "pint",
    }
    declarations = contract.get("tools", {})
    if set(declarations) != expected:
        raise QualificationError(
            "qualification tool inventory is incomplete or duplicated"
        )
    required_sections = {
        "owner",
        "input_contract",
        "tool",
        "policy",
        "output_contract",
        "evidence",
        "gate",
    }
    for name, declaration in declarations.items():
        if not isinstance(declaration, dict) or not required_sections.issubset(
            declaration
        ):
            raise QualificationError(
                f"qualification tool contract is incomplete: {name}"
            )
        registry = _registry_entry(
            toolchain, declaration["tool"].get("registry_ref", "")
        )
        version_ref = registry.get("version_ref")
        if version_ref not in toolchain.get("versions", {}):
            raise QualificationError(
                f"qualification tool has no central version: {name}"
            )
        version = str(toolchain["versions"][version_ref]).lower()
        if version in {"latest", "main", "master", "head", "nightly", "unstable"}:
            raise QualificationError(
                f"qualification tool has a floating version: {name}"
            )
        artifact = registry.get("artifact")
        if artifact:
            checksum_ref = registry.get("sha256_ref")
            checksum = toolchain.get("versions", {}).get(checksum_ref, "")
            if not isinstance(checksum, str) or len(checksum) != 64:
                raise QualificationError(
                    f"qualification tool has no exact artifact checksum: {name}"
                )
    if contract["tools"]["kube-bench"]["policy"].get("unsupported_behavior") != "BLOCK":
        raise QualificationError("unsupported kube-bench profiles must block")
    if contract["tools"]["hubble"]["policy"].get("unsupported_behavior") != "BLOCK":
        raise QualificationError("unverified Hubble/Cilium compatibility must block")
    nuclei_policy = contract["tools"]["nuclei"]["policy"]
    for key in (
        "automatic_update",
        "interactsh",
        "unsafe_templates",
        "destructive_templates",
    ):
        if nuclei_policy.get(key) != "forbidden":
            raise QualificationError(f"Nuclei policy must forbid {key}")
    slo = yaml.safe_load(
        (root / SLO_PATH.relative_to(ROOT)).read_text(encoding="utf-8")
    )
    normal = slo["profiles"]["normal"]
    smoke = (root / "tests/fixtures/qualification-tools/k6/smoke.js").read_text(
        encoding="utf-8"
    )
    smoke_policy = contract["tools"]["k6"]["policy"]["smoke"]
    for marker in (
        f"vus: {smoke_policy['virtual_users']}",
        f"iterations: {smoke_policy['iterations']}",
        f'maxDuration: "{smoke_policy["duration_limit_seconds"]}s"',
    ):
        if marker not in smoke:
            raise QualificationError(
                f"k6 smoke execution bounds drifted from the contract: {marker}"
            )
    if f"p(95)<={normal['latency_p95_ms']}" not in smoke:
        raise QualificationError(
            "k6 smoke latency threshold drifted from the normal SLO profile"
        )
    error_ratio = normal["error_rate_percent"] / 100
    if f"rate<={error_ratio:g}" not in smoke:
        raise QualificationError(
            "k6 smoke error threshold drifted from the normal SLO profile"
        )
    if "PROVEN" in json.dumps(contract):
        raise QualificationError(
            "qualification contract must not contain a static PROVEN state"
        )
    return contract


def _run(
    command: list[str], *, env: dict[str, str] | None = None, timeout: int = 30
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )


def _require_version(name: str, command: list[str], version: str) -> None:
    executable = shutil.which(command[0])
    if executable is None:
        raise QualificationError(f"required scanner is absent: {name}")
    result = _run([executable, *command[1:]])
    if result.returncode != 0 or version not in result.stdout + result.stderr:
        raise QualificationError(f"required scanner version mismatch: {name}")


class _SmokeHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path == "/healthz":
            body = b"ecommerce-qualified\n"
            self.send_response(200)
        else:
            body = b"not-found\n"
            self.send_response(404)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


@contextmanager
def _local_target() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _SmokeHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _write_evidence(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def smoke(output: Path) -> dict[str, Any]:
    validate_contract()
    toolchain = json.loads(TOOLCHAIN_PATH.read_text(encoding="utf-8"))
    for name in ("conftest", "opa", "k6", "nuclei", "hubble", "pint"):
        entry = toolchain["tools"][name]
        _require_version(
            name, entry["version_command"], toolchain["versions"][entry["version_ref"]]
        )

    opa_check = _run(["opa", "check", "--strict", os.fspath(POLICIES)])
    if opa_check.returncode:
        raise QualificationError("OPA rejected the repository policy bundle")
    conftest_args = [
        "conftest",
        "test",
        "--namespace",
        "qualification",
        "--policy",
        os.fspath(POLICIES),
    ]
    conftest_pass = _run([*conftest_args, os.fspath(FIXTURES / "opa/pass.yaml")])
    conftest_fail = _run([*conftest_args, os.fspath(FIXTURES / "opa/fail.yaml")])
    conftest_invalid = _run([*conftest_args, os.fspath(FIXTURES / "opa/invalid.yaml")])
    if (
        conftest_pass.returncode
        or conftest_fail.returncode == 0
        or conftest_invalid.returncode == 0
    ):
        raise QualificationError("Conftest PASS/FAIL/invalid fixture parity failed")

    pint_pass = _run(["pint", "lint", os.fspath(FIXTURES / "pint/valid.yaml")])
    pint_fail = _run(["pint", "lint", os.fspath(FIXTURES / "pint/invalid.yaml")])
    if (
        normalize_pint(pint_pass.returncode, pint_pass.stdout + pint_pass.stderr)[
            "final_result"
        ]
        != "PASS"
    ):
        raise QualificationError("Pint rejected the valid fixture")
    if (
        normalize_pint(pint_fail.returncode, pint_fail.stdout + pint_fail.stderr)[
            "final_result"
        ]
        != "FAIL"
    ):
        raise QualificationError("Pint accepted the invalid fixture")

    with (
        tempfile.TemporaryDirectory(
            prefix="ecommerce-qualification-tools-"
        ) as directory,
        _local_target() as target,
    ):
        temporary = Path(directory)
        k6_output = temporary / "k6-summary.json"
        k6_env = os.environ.copy()
        k6_env["QUALIFICATION_TARGET"] = target
        k6_run = _run(
            [
                "k6",
                "run",
                "--quiet",
                "--summary-export",
                os.fspath(k6_output),
                os.fspath(FIXTURES / "k6/smoke.js"),
            ],
            env=k6_env,
            timeout=20,
        )
        if k6_run.returncode or parse_k6(k6_output)["final_result"] != "PASS":
            raise QualificationError("bounded k6 loopback smoke failed")

        _authorized_loopback_target(target)
        nuclei_output = temporary / "nuclei.jsonl"
        nuclei_run = _run(
            [
                "nuclei",
                "-silent",
                "-disable-update-check",
                "-no-interactsh",
                "-jsonl",
                "-omit-raw",
                "-u",
                target,
                "-t",
                os.fspath(FIXTURES / "nuclei/local-smoke.yaml"),
                "-o",
                os.fspath(nuclei_output),
            ],
            timeout=20,
        )
        nuclei = parse_nuclei(
            nuclei_output,
            scanner_exit_code=nuclei_run.returncode,
            allowed_template_ids={"ecommerce-local-health-smoke"},
        )
        if nuclei["final_result"] != "PASS" or nuclei["findings"] != 1:
            raise QualificationError("controlled Nuclei loopback smoke failed")

    results = {
        "contract": "PASS",
        "opa": "PASS",
        "conftest": "PASS",
        "k6": "PASS",
        "nuclei": "PASS",
        "pint": "PASS",
        "openscap": "RUNTIME_REQUIRED",
        "scap-security-guide": "RUNTIME_REQUIRED",
        "kube-bench": "BLOCK_UNSUPPORTED_PROFILE",
        "hubble": "BLOCK_UNVERIFIED_COMPATIBILITY",
    }
    payload = {
        "schema_version": 1,
        "contract_sha256": hashlib.sha256(CONTRACT_PATH.read_bytes()).hexdigest(),
        "results": results,
        "final_result": "PASS_STATIC_RUNTIME_BLOCKED",
    }
    _write_evidence(output, payload)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("contract")
    smoke_parser = subparsers.add_parser("smoke")
    smoke_parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / ".context/evidence/qualification-tools/smoke.json",
    )
    args = parser.parse_args()
    try:
        if args.command == "contract":
            validate_contract()
            print("PASS qualification tools contract")
            return 0
        payload = smoke(
            args.output if args.output.is_absolute() else ROOT / args.output
        )
        print(json.dumps(payload, sort_keys=True))
        return 0
    except (
        QualificationError,
        OSError,
        subprocess.SubprocessError,
        KeyError,
        TypeError,
    ) as exc:
        print(f"FAIL qualification-tools: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
