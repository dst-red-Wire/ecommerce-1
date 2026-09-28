#!/usr/bin/env python3
"""Pre-invocation Codex budget decision and measured local result reuse.

Only an explicit, deterministic read-only run with a checked success condition
can populate this cache. It is never qualification or review evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import tomllib
import uuid
from typing import Any

try:
    from scripts.codex_instruction_identity import (
        instruction_chain_digest,
        normalize_fallback_names,
    )
except ModuleNotFoundError:  # Direct execution outside the repository import path.
    from codex_instruction_identity import (  # type: ignore[no-redef]
        instruction_chain_digest,
        normalize_fallback_names,
    )

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "config/contracts/codex-token-budget.json"

CACHEABLE_CODEX_OVERRIDES = (
    "approval_policy=\"never\"",
    "web_search=\"disabled\"",
    "features.apps=false",
    "features.hooks=false",
    "features.remote_plugin=false",
    "mcp_servers={}",
    "plugins={}",
    "notify=[]",
)


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def contract() -> dict[str, Any]:
    return load_json(CONTRACT)


def _under_context(path: Path) -> bool:
    root = (ROOT / ".context").resolve()
    target = path.resolve()
    return target == root or root in target.parents


def _result_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = ROOT / path
    if not _under_context(path):
        raise ValueError("Codex cache results must remain under .context")
    return path


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _codex_home() -> Path:
    configured = os.environ.get("CODEX_HOME", "").strip()
    return Path(configured).expanduser().resolve() if configured else Path.home() / ".codex"


def _read_toml(path: Path) -> dict[str, Any]:
    return tomllib.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}


def _project_is_trusted(user_config: dict[str, Any]) -> bool:
    matches: list[tuple[int, str]] = []
    for value, project in (user_config.get("projects") or {}).items():
        if not isinstance(project, dict):
            continue
        try:
            configured = Path(str(value)).expanduser().resolve()
        except OSError:
            continue
        if configured == ROOT.resolve() or configured in ROOT.resolve().parents:
            matches.append((len(configured.parts), str(project.get("trust_level") or "")))
    return bool(matches and max(matches, key=lambda item: item[0])[1] == "trusted")


def _identity_verified(identity: dict[str, Any] | None) -> bool:
    return bool(
        identity
        and identity.get("verified") is True
        and identity.get("model") not in {None, "", "UNKNOWN"}
        and identity.get("effort") not in {None, "", "UNKNOWN"}
    )


def _atomic_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent,
                                     prefix=".tmp-", delete=False) as stream:
        tmp = Path(stream.name)
        tmp.chmod(0o600)
        stream.write(value)
    os.replace(tmp, path)


def _context_module():
    spec = importlib.util.spec_from_file_location("context_pack", ROOT / "scripts/context-pack.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _verify_current(manifest: dict[str, Any]) -> None:
    if manifest.get("schema_version") != 2:
        raise ValueError("legacy context manifest cannot be reused")
    if manifest.get("instruction_identity_verified") is not True:
        raise ValueError("context instruction identity is not verified")
    module = _context_module()
    scope = manifest.get("scope") or {}
    since = str(scope.get("since") or "")
    staged = bool(scope.get("staged"))
    working_tree = bool(scope.get("working_tree"))
    explicit = list(scope.get("explicit_paths") or [])
    files = list(manifest.get("relevant_paths") or [])
    if subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip() != manifest.get("head_sha"):
        raise ValueError("context HEAD changed")
    if since and subprocess.check_output(["git", "rev-parse", since], cwd=ROOT, text=True).strip() != scope.get("base_sha"):
        raise ValueError("context base changed")
    candidates = module.changed_files(since=since, staged=staged, working_tree=working_tree)
    if module._sha256_parts(explicit or candidates) != manifest.get("candidate_paths_digest"):
        raise ValueError("context candidate paths changed")
    if module._relevant_state_digest(files, since=since, staged=staged) != manifest.get("relevant_paths_digest"):
        raise ValueError("context files or index changed")
    cfg = module.yq_json(".", module.ROUTER)
    budget = contract()
    if module._policy_version(cfg, budget) != manifest.get("context_policy_version"):
        raise ValueError("context policy changed")
    if module._contract_digest(str(manifest["route"]), cfg, list(manifest.get("services") or []), list(manifest.get("targeted_pointers") or [])) != manifest.get("applicable_contract_digest"):
        raise ValueError("applicable contract changed")
    if module._instruction_digest(files) != manifest.get("instruction_digest"):
        raise ValueError("applicable instructions changed")
    expected = module._cache_key(
        task_digest=str(manifest["task_digest"]),
        head_sha=str(manifest["head_sha"]),
        relevant_paths_digest=str(manifest["relevant_paths_digest"]),
        applicable_contract_digest=str(manifest["applicable_contract_digest"]),
        context_policy_version=str(manifest["context_policy_version"]),
        instruction_digest=str(manifest["instruction_digest"]),
        candidate_paths_digest=str(manifest["candidate_paths_digest"]),
    )
    if expected != manifest.get("cache_key"):
        raise ValueError("context identity mismatch")


def validate_manifest(manifest: dict[str, Any]) -> None:
    cfg = contract()
    route = str(manifest.get("route") or "")
    maxima = cfg["context_level_max_bytes"]
    if route not in maxima:
        raise ValueError(f"unknown context route: {route}")
    actual = int(manifest.get("actual_bytes", -1))
    declared = int(manifest.get("max_bytes", -1))
    allowed = int(maxima[route])
    if actual < 0 or declared < 1 or actual > declared or declared > allowed:
        raise ValueError(f"context budget violation route={route} actual={actual} declared={declared} allowed={allowed}")
    key = str(manifest.get("cache_key") or "")
    if re.fullmatch(r"[0-9a-f]{64}", key) is None:
        raise ValueError("manifest cache_key must be a full SHA-256")
    pack_path = _result_path(str(manifest.get("pack_path") or ""))
    pack_sha = str(manifest.get("pack_sha256") or "")
    if not pack_path.is_file() or pack_path.stat().st_size != actual or _sha256(pack_path) != pack_sha:
        raise ValueError("context pack integrity mismatch")


def _cache_path(cache_key: str, identity: dict[str, Any]) -> Path:
    state = ROOT / str(contract()["context_cache"]["state_directory"])
    return state / f"{_digest([cache_key, identity])}.json"


def decide(manifest_path: Path, identity: dict[str, Any] | None = None) -> dict[str, Any]:
    manifest = load_json(manifest_path)
    validate_manifest(manifest)
    cache_key = str(manifest["cache_key"])
    result = {
        "cache_key": cache_key,
        "route": manifest["route"],
        "actual_bytes": int(manifest["actual_bytes"]),
        "estimated_input_tokens": int(manifest.get("estimated_input_tokens", 0)),
        "should_invoke_ai": True,
        "reason": "exact_input_cache_miss",
        "cached_result": "",
    }
    if not _identity_verified(identity):
        result["reason"] = "unverified_identity"
        return result
    if manifest.get("scope_ambiguous") is not False:
        result["reason"] = "ambiguous_scope"
        return result
    try:
        _verify_current(manifest)
    except (ValueError, OSError, subprocess.CalledProcessError, RuntimeError) as exc:
        result["reason"] = f"current_input_unverified:{type(exc).__name__}"
        return result
    if manifest.get("truncated"):
        result["reason"] = "incomplete_context"
        return result
    marker_path = _cache_path(cache_key, identity or {})
    if not marker_path.is_file():
        return result
    try:
        marker = load_json(marker_path)
        result_path = _result_path(str(marker.get("result_path") or ""))
    except (OSError, ValueError, json.JSONDecodeError):
        result["reason"] = "cache_corrupt"
        return result
    try:
        intact = result_path.is_file() and marker.get("result_sha256") == _sha256(result_path)
    except OSError:
        intact = False
    if (marker.get("cache_key") == cache_key and marker.get("identity") == (identity or {})
        and marker.get("status") == "COMPLETE_VALIDATED" and intact):
        result.update(should_invoke_ai=False, reason="exact_input_cache_hit",
                      cached_result=str(result_path.relative_to(ROOT)))
    else:
        result["reason"] = "cache_integrity_or_identity_mismatch"
    return result


def mark(manifest_path: Path, result_value: str, *, identity: dict[str, Any] | None = None,
         validated: bool = False, read_only: bool = False) -> Path:
    if not validated or not read_only:
        raise ValueError("cache mark requires completed validated read-only result")
    manifest = load_json(manifest_path)
    validate_manifest(manifest)
    if not _identity_verified(identity):
        raise ValueError("unverified Codex identity is not reusable")
    if manifest.get("scope_ambiguous") is not False:
        raise ValueError("ambiguous context scope is not reusable")
    _verify_current(manifest)
    if manifest.get("truncated"):
        raise ValueError("truncated context is not reusable")
    result_path = _result_path(result_value)
    if not result_path.is_file() or not result_path.read_bytes():
        raise ValueError("result is empty or missing")
    cache_key = str(manifest["cache_key"])
    marker_path = _cache_path(cache_key, identity or {})
    payload = {
        "schema_version": 2, "status": "COMPLETE_VALIDATED",
        "cache_key": cache_key, "identity": identity or {},
        "head_sha": str(manifest.get("head_sha") or ""),
        "result_path": str(result_path.relative_to(ROOT)),
        "result_sha256": _sha256(result_path),
    }
    _atomic_text(marker_path, json.dumps(payload, sort_keys=True) + "\n")
    return marker_path


def normalize_usage(events: list[dict[str, Any]]) -> dict[str, Any]:
    """The CLI's cached input and reasoning output are subsets, not additions."""
    turns: list[dict[str, int | None]] = []
    current: dict[str, int | None] | None = None
    seen: set[str] = set()
    for event in events:
        kind = event.get("type")
        if kind == "turn.started":
            current = {"input_tokens": None, "cached_input_tokens": None,
                       "output_tokens": None, "reasoning_output_tokens": None}
            turns.append(current)
        if kind != "turn.completed" or not isinstance(event.get("usage"), dict):
            continue
        if current is None:
            current = {"input_tokens": None, "cached_input_tokens": None,
                       "output_tokens": None, "reasoning_output_tokens": None}
            turns.append(current)
        usage = event["usage"]
        details_in = usage.get("input_tokens_details") or {}
        details_out = usage.get("output_tokens_details") or {}
        values = {
            "input_tokens": usage.get("input_tokens"),
            "cached_input_tokens": usage.get("cached_input_tokens", details_in.get("cached_tokens")),
            "output_tokens": usage.get("output_tokens"),
            "reasoning_output_tokens": usage.get("reasoning_output_tokens", details_out.get("reasoning_tokens")),
        }
        fingerprint = _digest([len(turns), values])
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        for key, value in values.items():
            if isinstance(value, int) and value >= 0:
                current[key] = max(current[key] or 0, value)
    aggregate = {key: (sum(turn[key] for turn in turns if turn[key] is not None)
                       if any(turn[key] is not None for turn in turns) else None)
                 for key in ("input_tokens", "cached_input_tokens",
                             "output_tokens", "reasoning_output_tokens")}
    aggregate["turns"] = len(turns)
    return aggregate


def effective_identity(profile: str, model: str, effort: str, expectation: str) -> dict[str, Any]:
    codex_home = _codex_home()
    user = codex_home / "config.toml"
    layer = codex_home / f"{profile}.config.toml"
    project = ROOT / ".codex/config.toml"
    system = Path("/etc/codex/config.toml")
    system_values = _read_toml(system)
    base = _read_toml(user)
    selected = _read_toml(layer)
    trusted = _project_is_trusted(base)
    local = _read_toml(project) if trusted else {}
    resolved_model = (
        model
        or local.get("model")
        or selected.get("model")
        or base.get("model")
        or system_values.get("model")
    )
    resolved_effort = (
        effort
        or local.get("model_reasoning_effort")
        or selected.get("model_reasoning_effort")
        or base.get("model_reasoning_effort")
        or system_values.get("model_reasoning_effort")
    )
    config_paths = [system, user, layer, *([project] if trusted else [])]
    fallback_value = next(
        (
            values["project_doc_fallback_filenames"]
            for values in (local, selected, base, system_values)
            if "project_doc_fallback_filenames" in values
        ),
        None,
    )
    instructions_verified = True
    try:
        fallback_names = normalize_fallback_names(fallback_value)
        instruction_digest = instruction_chain_digest(
            global_directory=codex_home,
            project_directories=[ROOT],
            fallback_names=fallback_names,
        )
    except (OSError, ValueError):
        fallback_names = ()
        instruction_digest = "UNVERIFIED"
        instructions_verified = False
    verified = bool(
        isinstance(resolved_model, str) and resolved_model.strip()
        and isinstance(resolved_effort, str) and resolved_effort.strip()
        and instructions_verified
    )
    return {
        "profile": profile,
        "model": resolved_model or "UNKNOWN",
        "effort": resolved_effort or "UNKNOWN",
        "verified": verified,
        "codex_home_digest": hashlib.sha256(str(codex_home).encode()).hexdigest(),
        "config_digest": _digest([
            f"{path}:{_sha256(path) if path.is_file() else 'MISSING'}"
            for path in config_paths
        ]),
        "instruction_digest": instruction_digest,
        "instruction_fallback_filenames": list(fallback_names),
        "success_condition_digest": hashlib.sha256(expectation.encode()).hexdigest(),
        "generator": 4,
    }


def codex_exec_argv(args: argparse.Namespace) -> list[str]:
    argv = ["codex", "exec", "--json", "--profile", args.profile]
    if args.cacheable:
        argv += ["--ephemeral", "--sandbox", "read-only"]
        for override in CACHEABLE_CODEX_OVERRIDES:
            argv += ["--config", override]
    if args.model:
        argv += ["--model", args.model]
    if args.effort:
        argv += ["--config", f"model_reasoning_effort={args.effort}"]
    return [*argv, "-"]


def run_task(args: argparse.Namespace) -> int:
    task = args.task.strip()
    if not task:
        raise ValueError("task is required")
    run_id = uuid.uuid4().hex
    identity = effective_identity(args.profile, args.model, args.effort, args.expect or "")
    identity["scope"] = "local-static-read-only" if args.cacheable else "nonreusable"
    stem = f".context/codex-budget/runs/{run_id}"
    pack = f"{stem}.md"
    manifest = f"{stem}.json"
    command = [sys.executable, str(ROOT / "scripts/context-pack.py"), "--task-stdin",
               "--output", pack, "--manifest", manifest]
    if args.since:
        command += ["--since", args.since]
    if args.staged:
        command += ["--staged"]
    if args.paths:
        command += ["--paths", *args.paths]
    prepared = subprocess.run(command, input=task, text=True, cwd=ROOT, capture_output=True)
    if prepared.returncode:
        raise RuntimeError(prepared.stderr.strip() or "context preparation failed")
    manifest_path = ROOT / manifest
    data = load_json(manifest_path)
    start = time.monotonic()
    decision = decide(manifest_path, identity) if args.cacheable else {
        "should_invoke_ai": True, "reason": "operation_not_cacheable"}
    measurement = {
        "schema_version": 1, "run_id": run_id, "route": data["route"],
        "context_bytes": data["actual_bytes"],
        "estimated_input_tokens": data["estimated_input_tokens"],
        "estimate_authoritative": False, "profile": args.profile,
        "model": identity["model"], "effort": identity["effort"],
        "cache": decision["reason"], "cacheable": bool(args.cacheable),
        "calls": 0, "call_unit": "codex-exec", "model_calls": 0,
        "retries": None, "errors": 0, "usage": normalize_usage([]),
        "unobservable": ["hidden system context", "actual input before invocation",
                         "interactive and IDE calls", "internal model requests and retries"],
    }
    metrics = ROOT / f".context/codex-budget/metrics/{run_id}.json"
    if not decision["should_invoke_ai"]:
        result = _result_path(decision["cached_result"])
        print(result.read_text(encoding="utf-8"), end="")
        measurement["duration_seconds"] = round(time.monotonic() - start, 3)
        measurement["estimated_avoided_input_tokens"] = data["estimated_input_tokens"]
        _atomic_text(metrics, json.dumps(measurement, sort_keys=True) + "\n")
        return 0
    argv = codex_exec_argv(args)
    prompt = (ROOT / pack).read_text(encoding="utf-8")
    try:
        proc = subprocess.run(argv, input=prompt, text=True, cwd=ROOT, capture_output=True,
                              timeout=args.timeout)
    except subprocess.TimeoutExpired:
        measurement.update(calls=1, model_calls=None, errors=1,
                           success=False, duration_seconds=round(time.monotonic() - start, 3))
        _atomic_text(metrics, json.dumps(measurement, sort_keys=True) + "\n")
        raise
    measurement["calls"] = 1
    measurement["model_calls"] = None
    events = []
    for line in proc.stdout.splitlines():
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            measurement["errors"] += 1
    measurement["usage"] = normalize_usage(events)
    completed = proc.returncode == 0 and any(e.get("type") == "turn.completed" for e in events)
    blocked_types = {"command_execution", "file_change", "mcp_tool_call", "web_search"}
    used_tools = any(e.get("item", {}).get("type") in blocked_types
                     for e in events if isinstance(e.get("item"), dict))
    messages = [str(e["item"].get("text") or "") for e in events
                if e.get("type") == "item.completed" and
                isinstance(e.get("item"), dict) and e["item"].get("type") == "agent_message"]
    final = messages[-1] if messages else ""
    policy = _context_module()
    final = policy.redact_sensitive(final, policy.yq_json(".", policy.ROUTER))
    succeeded = completed and bool(final) and (not args.expect or args.expect in final)
    if not succeeded:
        measurement["errors"] += 1
    measurement["success"] = succeeded
    measurement["tool_events"] = used_tools
    measurement["event_errors"] = sum(e.get("type") in {"error", "turn.failed"} for e in events)
    measurement["errors"] += measurement["event_errors"]
    measurement["duration_seconds"] = round(time.monotonic() - start, 3)
    if final:
        print(final)
    if (args.cacheable and _identity_verified(identity) and args.expect and succeeded and not used_tools
            and data.get("scope_ambiguous") is False and not data.get("truncated")):
        result_path = ROOT / f"{stem}.result.txt"
        _atomic_text(result_path, final)
        mark(manifest_path, str(result_path.relative_to(ROOT)), identity=identity,
             validated=True, read_only=True)
    _atomic_text(metrics, json.dumps(measurement, sort_keys=True) + "\n")
    return 0 if succeeded else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    d = sub.add_parser("decide")
    d.add_argument("--manifest", default=".context/codex-context.json")
    m = sub.add_parser("mark")
    m.add_argument("--manifest", default=".context/codex-context.json")
    m.add_argument("--result", required=True)
    m.add_argument("--validated", action="store_true")
    m.add_argument("--read-only", action="store_true")
    for cache_command in (d, m):
        cache_command.add_argument("--profile", default="ecommerce-minimal")
        cache_command.add_argument("--model", default="")
        cache_command.add_argument("--effort", default="")
        cache_command.add_argument("--expect", default="")
    r = sub.add_parser("run")
    r.add_argument("--task", required=True)
    r.add_argument("--paths", nargs="*", default=[])
    r.add_argument("--since", default="")
    r.add_argument("--staged", action="store_true")
    r.add_argument("--profile", default="ecommerce-minimal")
    r.add_argument("--model", default="")
    r.add_argument("--effort", default="")
    r.add_argument("--cacheable", action="store_true")
    r.add_argument("--expect", default="")
    r.add_argument("--timeout", type=int, default=900)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "run":
        return run_task(args)
    manifest = Path(args.manifest)
    if not manifest.is_absolute():
        manifest = ROOT / manifest
    identity = effective_identity(args.profile, args.model, args.effort, args.expect)
    identity["scope"] = "local-static-read-only"
    if args.command == "decide":
        print(json.dumps(decide(manifest, identity), sort_keys=True))
        return 0
    marker = mark(
        manifest,
        args.result,
        identity=identity,
        validated=args.validated,
        read_only=args.read_only,
    )
    print(marker.relative_to(ROOT))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError,
            subprocess.TimeoutExpired) as exc:
        print(f"BLOCKED {type(exc).__name__}: {str(exc)[:300]}", file=sys.stderr)
        raise SystemExit(1) from None
