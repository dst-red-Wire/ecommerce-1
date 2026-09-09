#!/usr/bin/env python3
"""Build a small, contract-routed context pack for Work/Codex.

The pack is read-only. Task semantics and changed paths choose the smallest
safe context level; AST outlines are preferred over broad file excerpts.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from contract_paths import machine_contract_path  # noqa: E402

ROOT = Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip())
ROUTER = ROOT / "config/context/router.yaml"
OWNERSHIP = machine_contract_path(ROOT, "service_ownership")
DEPS = machine_contract_path(ROOT, "dependency_map")
PUBLIC_API = machine_contract_path(ROOT, "public_api_contracts")


def run(*args: str, check: bool = True) -> str:
    p = subprocess.run(args, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and p.returncode:
        raise RuntimeError(p.stderr.strip() or f"command failed: {' '.join(args)}")
    return p.stdout


def yq_json(expr: str, path: Path):
    return json.loads(run("yq", "-o=json", expr, str(path)))


def changed_files(base: str) -> list[str]:
    files: set[str] = set()
    commands = (
        ["git", "diff", "--name-only", base, "--"],
        ["git", "ls-files", "--others", "--exclude-standard"],
    )
    for cmd in commands:
        p = subprocess.run(cmd, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        if p.returncode == 0:
            files.update(x.strip() for x in p.stdout.splitlines() if x.strip())
    return sorted(files)


def matches(path: str, pattern: str) -> bool:
    if "**" in pattern:
        return path.startswith(pattern.split("**", 1)[0])
    return fnmatch.fnmatch(path, pattern)


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


def route(task: str, files: list[str]) -> str:
    cfg = yq_json(".", ROUTER)
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
        indent=2,
        sort_keys=True,
    )


def excerpt(path: str, max_lines: int) -> str:
    target = ROOT / path
    if not target.is_file():
        return ""
    lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    if len(lines) > max_lines:
        lines = lines[:max_lines] + [f"... truncated after {max_lines} lines ..."]
    return "\n".join(lines)


def ast_outline(path: str, max_lines: int = 40) -> str:
    """Use ast-grep when supported, with a cheap textual fallback.

    AST extraction is best-effort context reduction only; it must never make a
    deterministic gate fail merely because a language pattern evolves.
    """
    target = ROOT / path
    if not target.is_file():
        return ""
    suffix = target.suffix.lower()
    specs = {
        ".go": ("go", ["func $F($$$A) $$$R { $$$B }", "type $T struct { $$$F }"]),
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
        pattern = r"^(?:func|type|interface|export\s+(?:async\s+)?function|export\s+const|const\s+[A-Za-z0-9_]+\s*=)"
        p = subprocess.run(
            ["rg", "-n", pattern, str(target)], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--task", required=True)
    parser.add_argument("--base", default="origin/main")
    parser.add_argument("--output", default=".context/codex-context.md")
    args = parser.parse_args()

    cfg = yq_json(".", ROUTER)
    files = changed_files(args.base)
    level = route(args.task, files)
    level_cfg = cfg["levels"][level]
    max_bytes = int(os.environ.get("CONTEXT_MAX_BYTES", level_cfg["max_bytes"]))
    max_diff_lines = int(level_cfg["max_diff_lines"])
    max_excerpt_lines = int(level_cfg["max_excerpt_lines"])
    services = detect_services(args.task, files)
    sha = run("git", "rev-parse", "HEAD").strip()
    branch = run("git", "branch", "--show-current").strip() or "DETACHED"

    parts = [
        "# Codex context pack v2",
        f"TASK: {args.task}",
        f"ROUTE: {level}",
        f"BRANCH: {branch}",
        f"HEAD: {sha}",
        f"BASE: {args.base}",
        "",
        "## Changed files",
        *(files or ["(none detected)"]),
    ]

    canonical = cfg.get("canonical", {}).get(level, [])
    if canonical:
        parts += ["", "## Canonical pointers", *[f"- {path}" for path in canonical]]

    if services:
        parts += ["", "## Routed service contracts"]
        for service in services:
            parts += [f"### {service}", "```json", service_contract(service), "```"]

    outlines = []
    for path in files[:20]:
        outline = ast_outline(path)
        if outline:
            outlines += [f"### {path}", "```text", outline, "```"]
    if outlines:
        parts += ["", "## AST symbol outline", *outlines]

    if level == "L2":
        for path in canonical:
            text = excerpt(path, max_excerpt_lines)
            if text:
                parts += ["", f"## {path} (bounded)", "```yaml", text, "```"]
    elif level == "L1" and not services:
        for path in canonical:
            text = excerpt(path, max_excerpt_lines)
            if text:
                parts += ["", f"## {path} (bounded)", "```yaml", text, "```"]

    stat = run("git", "diff", "--stat", args.base, "--", check=False).strip()
    if stat:
        parts += ["", "## Diff stat", "```text", stat, "```"]
    diff = run("git", "diff", "--no-ext-diff", "--unified=3", args.base, "--", *files, check=False)
    if diff:
        lines = diff.splitlines()
        if len(lines) > max_diff_lines:
            lines = lines[:max_diff_lines] + [f"... diff truncated after {max_diff_lines} lines ..."]
        parts += ["", "## Focused diff", "```diff", "\n".join(lines), "```"]

    output = bounded("\n".join(parts) + "\n", max_bytes)
    destination = ROOT / args.output
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(output, encoding="utf-8")
    print(output, end="")
    print(f"PACK: {destination.relative_to(ROOT)} ({len(output.encode('utf-8'))} bytes)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
