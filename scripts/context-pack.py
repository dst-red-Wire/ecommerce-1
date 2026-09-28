#!/usr/bin/env python3
"""Build a small task-delta context pack for Codex/Work.

The pack is read-only and non-authoritative. Task semantics plus the current
task delta select the smallest safe context level. Canonical documents are
pointers by default; their contents are included only when explicitly asked.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Iterable

ROOT = Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip())
ROUTER = ROOT / "config/context/router.yaml"
TOKEN_BUDGET = ROOT / "config/contracts/codex-token-budget.json"
OWNERSHIP = ROOT / "config/contracts/service-ownership.yaml"
DEPS = ROOT / "config/contracts/dependency-map.yaml"
PUBLIC_API = ROOT / "config/contracts/public-api-contracts.yaml"

PEM_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----.*?"
    r"-----END (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)
PEM_PRIVATE_KEY_BEGIN = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
    re.IGNORECASE,
)


class MissingManagedYq(RuntimeError):
    pass


def managed_yq() -> str:
    candidate = Path.home() / ".local" / "bin" / "yq"
    if not candidate.is_file() or not os.access(candidate, os.X_OK):
        raise MissingManagedYq(f"managed yq missing: run `make context-tools` ({candidate})")
    return str(candidate)


def run(*args: str, check: bool = True, input_text: str | None = None) -> str:
    p = subprocess.run(
        args,
        cwd=ROOT,
        text=True,
        input=input_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and p.returncode:
        raise RuntimeError(p.stderr.strip() or f"command failed: {' '.join(args)}")
    return p.stdout


def yq_json(expr: str, path: Path):
    return json.loads(run(managed_yq(), "-o=json", expr, str(path)))


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_parts(values: Iterable[str]) -> str:
    digest = hashlib.sha256()
    for value in sorted(values):
        digest.update(value.encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def context_input(path: str) -> Path:
    candidate = Path(path)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise RuntimeError(f"context input must be repository-relative: {path}")
    repository = ROOT.resolve()
    target = (repository / candidate).resolve()
    if target != repository and repository not in target.parents:
        raise RuntimeError(f"context input escapes repository: {path}")
    return target


def matches(path: str, pattern: str) -> bool:
    normalized = path.replace("\\", "/")
    if "**" in pattern:
        prefix = pattern.split("**", 1)[0]
        return normalized.startswith(prefix)
    return fnmatch.fnmatch(normalized, pattern)


def _historical(path: str, cfg: dict) -> bool:
    normalized = path.replace("\\", "/")
    patterns = cfg.get("agent_data_access", {}).get("historical_path_patterns", [])
    return any(re.search(str(pattern), normalized) for pattern in patterns)


def _git_name_only(args: list[str]) -> list[str]:
    p = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if p.returncode:
        return []
    return [line.strip() for line in p.stdout.splitlines() if line.strip()]


def changed_files(
    *,
    since: str = "",
    staged: bool = False,
    working_tree: bool = True,
) -> list[str]:
    files: set[str] = set()
    if since:
        files.update(_git_name_only(["diff", "--name-only", since, "--"]))
    elif staged:
        files.update(_git_name_only(["diff", "--cached", "--name-only", "--"]))
    elif working_tree:
        files.update(_git_name_only(["diff", "--name-only", "--"]))
        files.update(_git_name_only(["diff", "--cached", "--name-only", "--"]))
    files.update(_git_name_only(["ls-files", "--others", "--exclude-standard"]))
    return sorted(files)


def file_route(files: list[str], cfg: dict) -> str:
    for level in ("L2", "L1"):
        patterns = cfg["levels"][level].get("patterns", [])
        if any(matches(path, pattern) for path in files for pattern in patterns):
            return level
    return "L0"


def task_route(task: str, cfg: dict) -> str:
    lowered = task.lower()
    for level in ("L2", "L1"):
        if any(
            re.search(rf"(?<![a-z0-9-]){re.escape(str(word).lower())}(?![a-z0-9-])", lowered)
            for word in cfg["levels"][level].get("task_keywords", [])
        ):
            return level
    return "L0"


def route(task: str, files: list[str], cfg: dict | None = None) -> str:
    cfg = cfg or yq_json(".", ROUTER)
    ranks = {"L0": 0, "L1": 1, "L2": 2}
    candidates = [file_route(files, cfg), task_route(task, cfg)]
    return max(candidates, key=lambda item: ranks[item])


def service_names() -> list[str]:
    return [str(x) for x in yq_json(".services | keys", OWNERSHIP)]


def detect_services(task: str, files: list[str]) -> list[str]:
    names = service_names()
    found: set[str] = set()
    haystack = "\n".join([task, *files]).lower()
    for name in names:
        if re.search(rf"(?<![a-z0-9-]){re.escape(name.lower())}(?![a-z0-9-])", haystack):
            found.add(name)
        if any(path.startswith(f"services/{name}/") for path in files):
            found.add(name)
    return sorted(found)


def service_contract(name: str) -> str:
    owner = yq_json(f'.services."{name}"', OWNERSHIP)
    dep = yq_json(f'.services."{name}"', DEPS)
    services = yq_json(".services", DEPS) or {}
    consumers = sorted(
        service for service, contract in services.items() if name in ((contract or {}).get("sync") or [])
    )
    public = yq_json(f'.contracts."{name}"', PUBLIC_API)
    return json.dumps(
        {
            "ownership": owner,
            "dependency_map": dep,
            "direct_sync_consumers": consumers,
            "public_api": public,
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def excerpt(path: str, max_lines: int) -> str:
    target = context_input(path)
    if not target.is_file():
        return ""
    lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    if len(lines) > max_lines:
        lines = lines[:max_lines] + [f"... truncated after {max_lines} lines ..."]
    return "\n".join(lines)


def ast_outline(path: str, max_lines: int = 32) -> str:
    target = context_input(path)
    if not target.is_file():
        return ""
    suffix = target.suffix.lower()
    specs = {
        ".go": ("go", ["func $F($$$A) $$$R { $$$B }", "type $T struct { $$$F }"]),
        ".py": ("python", ["def $F($$$A): $$$B", "class $C: $$$B"]),
        ".ts": ("typescript", ["function $F($$$A) { $$$B }", "interface $T { $$$F }"]),
        ".tsx": ("tsx", ["function $F($$$A) { $$$B }", "const $F = ($$$A) => $B"]),
    }
    if suffix not in specs:
        return ""
    lang, patterns = specs[suffix]
    collected: list[str] = []
    if shutil.which("ast-grep"):
        for pattern in patterns:
            p = subprocess.run(
                ["ast-grep", "run", "--lang", lang, "--pattern", pattern, "--json", str(target)],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            if p.returncode != 0 or not p.stdout.strip():
                continue
            try:
                payload = json.loads(p.stdout)
                if isinstance(payload, dict):
                    payload = [payload]
                for match in payload:
                    text = (match.get("text") or "").splitlines()
                    if text:
                        collected.append(text[0][:240])
            except (json.JSONDecodeError, AttributeError):
                pass
    if not collected:
        pattern = (
            r"^(?:func|type|def|class|interface|export\s+(?:async\s+)?function|"
            r"export\s+const|const\s+[A-Za-z0-9_]+\s*=)"
        )
        p = subprocess.run(
            ["rg", "-n", pattern, str(target)],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        if p.returncode in (0, 1):
            collected.extend(p.stdout.splitlines())
    return "\n".join(dict.fromkeys(collected[:max_lines]))


def bounded(text: str, max_bytes: int) -> str:
    raw = text.encode("utf-8")
    if len(raw) <= max_bytes:
        return text
    marker = "\n\n[CONTEXT TRUNCATED TO BYTE BUDGET]\n"
    cut = raw[: max(0, max_bytes - len(marker.encode()))].decode("utf-8", errors="ignore")
    return cut + marker


def validate_router_contract(cfg: dict, lock: dict | None = None) -> None:
    access = cfg.get("agent_data_access")
    if not isinstance(access, dict):
        raise RuntimeError("context router is missing agent_data_access policy")
    expected = {
        "authority": "architecture.lock.yaml#machine_contracts.context_router",
        "default_mode": "read-only",
        "least_privilege": "required",
        "secret_values": "forbidden",
        "production_credentials": "forbidden",
        "private_keys": "forbidden",
        "unbounded_environment_dump": "forbidden",
        "output_root": ".context",
        "maximum_override_policy": "may-reduce-never-increase-level-budget",
    }
    for key, value in expected.items():
        if access.get(key) != value:
            raise RuntimeError(f"invalid context access policy: {key}")
    authority = lock if lock is not None else yq_json(".", ROOT / "architecture.lock.yaml")
    registry = authority.get("machine_contracts", {}) if isinstance(authority, dict) else {}
    prefix = "architecture.lock.yaml#machine_contracts."
    references = access.get("contract_references")
    if not isinstance(references, list) or not references:
        raise RuntimeError("context router must declare bounded contract references")
    for reference in references:
        if not isinstance(reference, str) or not reference.startswith(prefix):
            raise RuntimeError(f"invalid context authority reference: {reference!r}")
        role = reference.removeprefix(prefix)
        if role not in registry:
            raise RuntimeError(f"unknown context contract reference: {role}")
    for level, values in cfg.get("levels", {}).items():
        budget = values.get("max_bytes") if isinstance(values, dict) else None
        if type(budget) is not int or budget <= 0:
            raise RuntimeError(f"context level {level} must have a positive byte budget")


def guard_context_paths(paths: list[str], cfg: dict) -> None:
    patterns = cfg["agent_data_access"].get("forbidden_path_patterns", [])
    for path in paths:
        normalized = path.replace("\\", "/")
        context_input(path)
        if any(re.search(str(pattern), normalized) for pattern in patterns):
            raise RuntimeError(f"context input is forbidden by least-privilege policy: {path}")


def redact_sensitive(text: str, cfg: dict) -> str:
    redacted = PEM_PRIVATE_KEY_BLOCK.sub("[REDACTED PRIVATE KEY BY CONTEXT POLICY]", text)
    incomplete = PEM_PRIVATE_KEY_BEGIN.search(redacted)
    if incomplete:
        redacted = redacted[: incomplete.start()] + "[REDACTED INCOMPLETE PRIVATE KEY BY CONTEXT POLICY]"
    for pattern in cfg["agent_data_access"].get("redaction_patterns", []):
        redacted = re.sub(str(pattern), "[REDACTED BY CONTEXT POLICY]", redacted, flags=re.MULTILINE)
    return redacted


def output_path(relative: str, cfg: dict) -> Path:
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise RuntimeError("context output must be repository-relative")
    root = (ROOT / str(cfg["agent_data_access"]["output_root"])).resolve()
    destination = (ROOT / candidate).resolve()
    if destination != root and root not in destination.parents:
        raise RuntimeError("context output must remain under the governed .context root")
    return destination


def resolve_byte_budget(level_budget: int, override: str | None) -> int:
    try:
        requested = int(override) if override is not None else int(level_budget)
    except ValueError as exc:
        raise RuntimeError("context byte budget override must be an integer") from exc
    if requested <= 0 or requested > int(level_budget):
        raise RuntimeError(f"context byte budget override must be between 1 and {level_budget}")
    return requested


def _load_budget_contract() -> dict:
    return json.loads(TOKEN_BUDGET.read_text(encoding="utf-8"))


def _policy_version(cfg: dict, budget: dict) -> str:
    canonical = json.dumps({"router": cfg, "token_budget": budget}, sort_keys=True, separators=(",", ":"))
    return _sha256_text(canonical)


def _contract_digest(level: str, cfg: dict, services: list[str]) -> str:
    candidates = list(cfg.get("canonical", {}).get(level, []))
    for _service in services:
        candidates.extend([
            str(OWNERSHIP.relative_to(ROOT)),
            str(DEPS.relative_to(ROOT)),
            str(PUBLIC_API.relative_to(ROOT)),
        ])
    values: list[str] = []
    for path in sorted(set(candidates)):
        target = context_input(path)
        if target.is_file():
            values.append(path + ":" + hashlib.sha256(target.read_bytes()).hexdigest())
    return _sha256_parts(values)


def _relevant_state_digest(
    files: list[str],
    *,
    since: str,
    staged: bool,
) -> str:
    values = [f"scope:since={since}:staged={staged}"]
    for path in files:
        target = context_input(path)
        if target.is_file():
            values.append(path + ":" + hashlib.sha256(target.read_bytes()).hexdigest())
        else:
            values.append(path + ":MISSING")
    diff = _diff_for_scope(since=since, staged=staged, files=files)
    values.append("diff:" + _sha256_text(diff))
    return _sha256_parts(values)


def _cache_key(
    *,
    task_digest: str,
    head_sha: str,
    relevant_paths_digest: str,
    applicable_contract_digest: str,
    context_policy_version: str,
) -> str:
    return _sha256_parts([
        task_digest,
        head_sha,
        relevant_paths_digest,
        applicable_contract_digest,
        context_policy_version,
    ])


def _diff_for_scope(*, since: str, staged: bool, files: list[str]) -> str:
    if not files:
        return ""
    if since:
        args = ["git", "diff", "--no-ext-diff", "--unified=1", since, "--", *files]
    elif staged:
        args = ["git", "diff", "--cached", "--no-ext-diff", "--unified=1", "--", *files]
    else:
        args = ["git", "diff", "--no-ext-diff", "--unified=1", "--", *files]
    p = subprocess.run(args, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    return p.stdout if p.returncode == 0 else ""


def _stat_for_scope(*, since: str, staged: bool, files: list[str]) -> str:
    if not files:
        return ""
    if since:
        args = ["git", "diff", "--stat", since, "--", *files]
    elif staged:
        args = ["git", "diff", "--cached", "--stat", "--", *files]
    else:
        args = ["git", "diff", "--stat", "--", *files]
    p = subprocess.run(args, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    return p.stdout.strip() if p.returncode == 0 else ""


def build_pack(
    *,
    task: str,
    since: str,
    staged: bool,
    working_tree: bool,
    explicit_paths: list[str],
    include_excerpts: bool,
    cfg: dict,
) -> tuple[str, dict]:
    raw_files = explicit_paths or changed_files(since=since, staged=staged, working_tree=working_tree)
    guard_context_paths(raw_files, cfg)
    historical = [path for path in raw_files if _historical(path, cfg)]
    files = [path for path in raw_files if path not in historical]
    level = route(task, files, cfg)
    level_cfg = cfg["levels"][level]
    max_bytes = resolve_byte_budget(int(level_cfg["max_bytes"]), os.environ.get("CONTEXT_MAX_BYTES"))
    max_diff_lines = int(level_cfg["max_diff_lines"])
    max_excerpt_lines = int(level_cfg["max_excerpt_lines"])
    services = detect_services(task, files)
    head_sha = run("git", "rev-parse", "HEAD").strip()
    branch = run("git", "branch", "--show-current").strip() or "DETACHED"

    budget = _load_budget_contract()
    task_digest = _sha256_text(task)
    relevant_paths_digest = _relevant_state_digest(files, since=since, staged=staged)
    applicable_contract_digest = _contract_digest(level, cfg, services)
    context_policy_version = _policy_version(cfg, budget)
    cache_key = _cache_key(
        task_digest=task_digest,
        head_sha=head_sha,
        relevant_paths_digest=relevant_paths_digest,
        applicable_contract_digest=applicable_contract_digest,
        context_policy_version=context_policy_version,
    )

    parts = [
        "# Codex context pack v3",
        f"TASK: {task}",
        f"ROUTE: {level}",
        f"BRANCH: {branch}",
        f"HEAD: {head_sha}",
        f"SCOPE: {'since=' + since if since else 'staged' if staged else 'working-tree'}",
        f"CACHE_KEY: {cache_key}",
        "",
        "## Relevant paths",
        *(files[:80] or ["(none detected)"]),
    ]
    if len(files) > 80:
        parts.append(f"... {len(files) - 80} additional paths omitted ...")
    if historical:
        parts += ["", f"HISTORICAL_PATHS_EXCLUDED: {len(historical)}"]

    canonical = cfg.get("canonical", {}).get(level, [])
    guard_context_paths(canonical, cfg)
    if canonical:
        parts += ["", "## Canonical pointers (read only if needed)", *[f"- {path}" for path in canonical]]

    if services:
        parts += ["", "## Routed service contracts"]
        for service in services:
            parts += [f"### {service}", "~~~json", service_contract(service), "~~~"]

    outlines: list[str] = []
    for path in files[:16]:
        outline = ast_outline(path)
        if outline:
            outlines += [f"### {path}", "~~~text", outline, "~~~"]
    if outlines:
        parts += ["", "## Symbol outline", *outlines]

    if include_excerpts:
        for path in canonical:
            text = excerpt(path, max_excerpt_lines)
            if text:
                parts += ["", f"## {path} (explicit bounded excerpt)", "~~~text", text, "~~~"]

    stat = _stat_for_scope(since=since, staged=staged, files=files)
    if stat:
        parts += ["", "## Diff stat", "~~~text", stat[:2048], "~~~"]

    diff = _diff_for_scope(since=since, staged=staged, files=files)
    if diff:
        diff_lines = diff.splitlines()
        if len(diff_lines) > max_diff_lines:
            diff_lines = diff_lines[:max_diff_lines] + [f"... diff truncated after {max_diff_lines} lines ..."]
        parts += ["", "## Focused diff", "~~~diff", "\n".join(diff_lines), "~~~"]

    output = bounded(redact_sensitive("\n".join(parts) + "\n", cfg), max_bytes)
    actual_bytes = len(output.encode("utf-8"))
    manifest = {
        "schema_version": 1,
        "route": level,
        "head_sha": head_sha,
        "task_digest": task_digest,
        "relevant_paths": files,
        "historical_paths_excluded": historical,
        "relevant_paths_digest": relevant_paths_digest,
        "applicable_contract_digest": applicable_contract_digest,
        "context_policy_version": context_policy_version,
        "cache_key": cache_key,
        "max_bytes": max_bytes,
        "actual_bytes": actual_bytes,
        "estimated_input_tokens": math.ceil(actual_bytes / 4),
        "token_estimate_authoritative": False,
        "scope": {"since": since, "staged": staged, "working_tree": working_tree},
    }
    return output, manifest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    task = parser.add_mutually_exclusive_group(required=False)
    task.add_argument("--task", default="")
    task.add_argument("--task-stdin", action="store_true")
    parser.add_argument("--since", default="")
    parser.add_argument("--base", default="", help=argparse.SUPPRESS)
    parser.add_argument("--paths", nargs="*", default=[])
    parser.add_argument("--staged", action="store_true")
    parser.add_argument("--working-tree", action="store_true")
    parser.add_argument("--include-excerpts", action="store_true")
    parser.add_argument("--output", default=".context/codex-context.md")
    parser.add_argument("--manifest", default=".context/codex-context.json")
    parser.add_argument("--print", dest="print_pack", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    task = sys.stdin.read() if args.task_stdin else args.task
    task = task.strip()
    if not task:
        raise RuntimeError("task is required")
    since = (args.since or args.base).strip()
    cfg = yq_json(".", ROUTER)
    validate_router_contract(cfg)

    destination = output_path(args.output, cfg)
    manifest_path = output_path(args.manifest, cfg)
    output, manifest = build_pack(
        task=task,
        since=since,
        staged=bool(args.staged),
        working_tree=bool(args.working_tree or not args.staged),
        explicit_paths=list(dict.fromkeys(args.paths)),
        include_excerpts=bool(args.include_excerpts),
        cfg=cfg,
    )

    old_manifest: dict = {}
    if manifest_path.is_file():
        try:
            old_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            old_manifest = {}
    reused = bool(
        old_manifest.get("cache_key") == manifest["cache_key"]
        and destination.is_file()
        and len(destination.read_bytes()) <= int(manifest["max_bytes"])
    )
    manifest["pack_path"] = str(destination.relative_to(ROOT))
    manifest["pack_sha256"] = hashlib.sha256(output.encode("utf-8")).hexdigest()
    existing_pack_sha = (
        hashlib.sha256(destination.read_bytes()).hexdigest() if destination.is_file() else ""
    )
    reused = bool(
        reused
        and old_manifest.get("pack_sha256") == existing_pack_sha
        and existing_pack_sha == manifest["pack_sha256"]
    )
    manifest["pack_reused"] = reused
    if not reused:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(output, encoding="utf-8")
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if args.print_pack:
        print(destination.read_text(encoding="utf-8"), end="")
    print(
        f"PACK {destination.relative_to(ROOT)} route={manifest['route']} "
        f"bytes={manifest['actual_bytes']}/{manifest['max_bytes']} "
        f"est_tokens={manifest['estimated_input_tokens']} cache={'HIT' if reused else 'MISS'}",
        file=sys.stderr if args.print_pack else sys.stdout,
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except MissingManagedYq as exc:
        print(f"BLOCKED {exc}", file=sys.stderr)
        raise SystemExit(1) from None
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"BLOCKED {exc}", file=sys.stderr)
        raise SystemExit(1) from None
