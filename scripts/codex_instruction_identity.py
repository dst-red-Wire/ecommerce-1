#!/usr/bin/env python3
"""Resolve and fingerprint the instruction files selected by Codex."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Iterable


PRIMARY_INSTRUCTION_NAMES = ("AGENTS.override.md", "AGENTS.md")


def normalize_fallback_names(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ValueError("project_doc_fallback_filenames must be a list")
    names: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ValueError("project instruction fallback names must be non-empty strings")
        name = item.strip()
        candidate = Path(name)
        if candidate.is_absolute() or candidate.name != name or name in {".", ".."}:
            raise ValueError("project instruction fallback names must be file names")
        if name not in PRIMARY_INSTRUCTION_NAMES and name not in names:
            names.append(name)
    return tuple(names)


def _selected(directory: Path, names: Iterable[str]) -> tuple[Path, bytes] | None:
    for name in names:
        candidate = directory / name
        if not candidate.is_file():
            continue
        content = candidate.read_bytes()
        if content:
            return candidate, content
    return None


def instruction_chain_digest(
    *,
    global_directory: Path,
    project_directories: Iterable[Path],
    fallback_names: Iterable[str] = (),
) -> str:
    """Hash the first non-empty instruction source selected at each scope."""
    fallbacks = tuple(fallback_names)
    records: list[str] = []
    scopes = [
        ("global", global_directory, PRIMARY_INSTRUCTION_NAMES),
        *(
            ("project", directory, (*PRIMARY_INSTRUCTION_NAMES, *fallbacks))
            for directory in project_directories
        ),
    ]
    seen: set[tuple[str, Path]] = set()
    for scope, directory, names in scopes:
        resolved = directory.resolve()
        scope_key = (scope, resolved)
        if scope_key in seen:
            continue
        seen.add(scope_key)
        selected = _selected(resolved, names)
        if selected is None:
            records.append(f"{scope}:{resolved}:MISSING")
            continue
        path, content = selected
        records.append(
            f"{scope}:{resolved}:{path.name}:{hashlib.sha256(content).hexdigest()}"
        )
    digest = hashlib.sha256()
    for record in records:
        digest.update(record.encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()
