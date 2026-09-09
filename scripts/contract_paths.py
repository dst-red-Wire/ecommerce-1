#!/usr/bin/env python3
"""Resolve repository contract authorities from architecture.lock.yaml.

Consumers must ask the lock for a machine/topology contract instead of opening
a canonical-looking path directly. Resolution is fail-closed and repository-local.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


class ContractPathError(ValueError):
    pass


def load_lock(root: Path) -> dict[str, Any]:
    path = root / "architecture.lock.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ContractPathError("architecture.lock.yaml must be a mapping")
    return data


def _resolve(root: Path, section: str, key: str, *, must_exist: bool = True) -> Path:
    lock = load_lock(root)
    mapping = lock.get(section)
    if not isinstance(mapping, dict):
        raise ContractPathError(f"architecture.lock.yaml {section} must be a mapping")
    relative = mapping.get(key)
    if not isinstance(relative, str) or not relative.strip():
        raise ContractPathError(f"architecture.lock.yaml {section}.{key} must declare a non-empty relative path")
    candidate = (root / relative).resolve()
    repository = root.resolve()
    if candidate == repository or repository not in candidate.parents:
        raise ContractPathError(f"architecture.lock.yaml {section}.{key} resolves outside the repository: {relative!r}")
    if must_exist and not candidate.is_file():
        raise ContractPathError(f"architecture.lock.yaml {section}.{key} declared file does not exist: {relative}")
    return candidate


def machine_contract_path(root: Path, key: str, *, must_exist: bool = True) -> Path:
    return _resolve(root, "machine_contracts", key, must_exist=must_exist)


def topology_contract_path(root: Path, key: str, *, must_exist: bool = True) -> Path:
    return _resolve(root, "topology_contracts", key, must_exist=must_exist)


def repository_relative(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()
