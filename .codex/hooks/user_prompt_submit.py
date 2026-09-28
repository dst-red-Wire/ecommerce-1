#!/usr/bin/env python3
"""Codex UserPromptSubmit hook: prepare tiny governed repository context.

This hook is an optimization only. It never changes review/merge authority and
fails open so a local context-tool problem cannot block an otherwise valid user
prompt.
"""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
from typing import Any


def _emit(text: str) -> None:
    payload = {
        "hookSpecificOutput": {
            "hookEventName": "UserPromptSubmit",
            "additionalContext": text,
        }
    }
    print(json.dumps(payload, separators=(",", ":")))


def _repo_root(cwd: Path) -> Path | None:
    p = subprocess.run(
        ["git", "-C", str(cwd), "rev-parse", "--show-toplevel"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if p.returncode:
        return None
    return Path(p.stdout.strip())


def _prompt(event: dict[str, Any]) -> str:
    for key in ("prompt", "userPrompt", "user_prompt"):
        value = event.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def main() -> int:
    try:
        event = json.loads(sys.stdin.read() or "{}")
        cwd = Path(str(event.get("cwd") or ".")).resolve()
        prompt = _prompt(event)
        if not prompt:
            return 0
        root = _repo_root(cwd)
        if root is None:
            return 0
        contract_path = root / "config/contracts/codex-token-budget.json"
        packer = root / "scripts/context-pack.py"
        if not (contract_path.is_file() and packer.is_file()):
            return 0
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        limit = int(contract["hook_additional_context_max_bytes"])

        p = subprocess.run(
            [sys.executable, str(packer), "--task-stdin"],
            cwd=root,
            input=prompt,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=3,
        )
        if p.returncode:
            return 0
        manifest_path = root / ".context/codex-context.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        message = (
            "Bounded repo context prepared: .context/codex-context.md "
            f"(route={manifest.get('route')}, bytes={manifest.get('actual_bytes')}, "
            f"est_tokens={manifest.get('estimated_input_tokens')}). "
            "Read the pack only if repository context is needed."
        )
        raw = message.encode("utf-8")
        if len(raw) > limit:
            message = raw[:limit].decode("utf-8", errors="ignore")
        _emit(message)
        return 0
    except Exception:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
