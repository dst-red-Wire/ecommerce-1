#!/usr/bin/env python3
"""Build a bounded, contract-routed context pack for Work/Codex.

Intent: give an agent only the repository facts required for the current change.
Safety: read-only; output is generated under .context/ and must never be committed.
"""
from __future__ import annotations
import argparse
import fnmatch
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip())
ROUTER = ROOT / "config/context/router.yaml"
OWNERSHIP = ROOT / "config/contracts/service-ownership.yaml"
DEPS = ROOT / "config/contracts/dependency-map.yaml"


def run(*args: str, check: bool = True) -> str:
    p = subprocess.run(args, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and p.returncode:
        raise RuntimeError(p.stderr.strip() or f"command failed: {' '.join(args)}")
    return p.stdout


def yq_json(expr: str, path: Path):
    out = run("yq", "-o=json", expr, str(path))
    return json.loads(out)


def changed_files(base: str) -> list[str]:
    files: set[str] = set()
    for cmd in (["git", "diff", "--name-only", f"{base}...HEAD"], ["git", "diff", "--name-only"], ["git", "ls-files", "--others", "--exclude-standard"]):
        p = subprocess.run(cmd, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        if p.returncode == 0:
            files.update(x.strip() for x in p.stdout.splitlines() if x.strip())
    return sorted(files)


def matches(path: str, pattern: str) -> bool:
    if "**" in pattern:
        prefix = pattern.split("**", 1)[0]
        return path.startswith(prefix)
    return fnmatch.fnmatch(path, pattern)


def route(files: list[str]) -> str:
    cfg = yq_json(".", ROUTER)
    for level in ("L2", "L1"):
        pats = cfg["levels"][level].get("patterns", [])
        if any(matches(f, p) for f in files for p in pats):
            return level
    return "L0"


def service_names() -> list[str]:
    data = yq_json(".services | keys", OWNERSHIP)
    return [str(x) for x in data]


def detect_services(task: str, files: list[str]) -> list[str]:
    names = service_names()
    found: set[str] = set()
    haystack = "\n".join([task, *files]).lower()
    for name in names:
        if re.search(rf"(?<![a-z0-9-]){re.escape(name.lower())}(?![a-z0-9-])", haystack):
            found.add(name)
        if any(f"/{name}/" in f"/{p}/" or p.startswith(name + "/") for p in files):
            found.add(name)
    return sorted(found)


def service_contract(name: str) -> str:
    owner = yq_json(f'.services."{name}"', OWNERSHIP)
    dep = yq_json(f'.services."{name}"', DEPS)
    consumers = yq_json(f'[.services | to_entries[] | select((.value.sync // []) | index("{name}")) | .key]', DEPS)
    return json.dumps({"ownership": owner, "dependency_map": dep, "direct_sync_consumers": consumers}, indent=2, sort_keys=True)


def excerpt(path: str, max_lines: int) -> str:
    p = ROOT / path
    if not p.is_file():
        return ""
    try:
        text = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    if len(text) > max_lines:
        text = text[:max_lines] + [f"... truncated after {max_lines} lines ..."]
    return "\n".join(text)


def bounded(text: str, max_bytes: int) -> str:
    raw = text.encode("utf-8")
    if len(raw) <= max_bytes:
        return text
    cut = raw[: max(0, max_bytes - 96)].decode("utf-8", errors="ignore")
    return cut + "\n\n[CONTEXT TRUNCATED TO BYTE BUDGET]\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--task", required=True)
    ap.add_argument("--base", default="origin/main")
    ap.add_argument("--output", default=".context/codex-context.md")
    args = ap.parse_args()

    cfg = yq_json(".", ROUTER)
    max_bytes = int(os.environ.get("CONTEXT_MAX_BYTES", cfg.get("max_bytes", 32768)))
    max_diff_lines = int(cfg.get("max_diff_lines", 240))
    max_excerpt_lines = int(cfg.get("max_excerpt_lines", 120))
    files = changed_files(args.base)
    level = route(files)
    services = detect_services(args.task, files)
    sha = run("git", "rev-parse", "HEAD").strip()
    branch = run("git", "branch", "--show-current").strip() or "DETACHED"

    parts = [
        "# Codex context pack",
        f"TASK: {args.task}",
        f"ROUTE: {level}",
        f"BRANCH: {branch}",
        f"HEAD: {sha}",
        f"BASE: {args.base}",
        "",
        "## Changed files",
        *(files or ["(none detected)"]),
    ]

    if services:
        parts += ["", "## Routed service contracts"]
        for svc in services:
            parts += [f"### {svc}", "```json", service_contract(svc), "```"]

    if level == "L2":
        for path in ("architecture.lock.yaml", "config/contracts/review-policy.yaml"):
            text = excerpt(path, max_excerpt_lines)
            if text:
                parts += ["", f"## {path}", "```yaml", text, "```"]
    elif level == "L1" and not services:
        # Contract changes with no uniquely identified service still receive only compact ownership/dependency data.
        for path in ("config/contracts/service-ownership.yaml", "config/contracts/dependency-map.yaml"):
            text = excerpt(path, max_excerpt_lines)
            if text:
                parts += ["", f"## {path} (bounded)", "```yaml", text, "```"]

    stat = run("git", "diff", "--stat", f"{args.base}...HEAD", check=False).strip()
    if stat:
        parts += ["", "## Diff stat", "```text", stat, "```"]
    diff = run("git", "diff", "--no-ext-diff", "--unified=3", f"{args.base}...HEAD", "--", *files, check=False)
    if diff:
        lines = diff.splitlines()
        if len(lines) > max_diff_lines:
            lines = lines[:max_diff_lines] + [f"... diff truncated after {max_diff_lines} lines ..."]
        parts += ["", "## Focused diff", "```diff", "\n".join(lines), "```"]

    output = bounded("\n".join(parts) + "\n", max_bytes)
    out = ROOT / args.output
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(output, encoding="utf-8")
    print(output, end="")
    print(f"PACK: {out.relative_to(ROOT)} ({len(output.encode('utf-8'))} bytes)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
