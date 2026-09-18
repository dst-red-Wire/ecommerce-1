#!/usr/bin/env python3
"""Central content-addressed cache for deterministic ecommerce-1 qualification work."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "architecture.lock.yaml"
_SCHEMA_VERSION = 1
_MEMORY: dict[tuple[str, str], Any] = {}
_TOOL_VERSIONS: dict[tuple[str, tuple[str, ...]], str] = {}
_EXECUTABLE_IDENTITIES: dict[str, dict[str, str]] = {}

_PSYCH_SCRIPT = r"""
document = Psych.parse_file(ARGV[0])
walk = lambda do |node|
  if node.is_a?(Psych::Nodes::Mapping)
    keys = node.children.each_slice(2).map { |key, _| key.value }
    duplicate = keys.group_by(&:itself).find { |_, values| values.length > 1 }
    raise "duplicate YAML mapping key: #{duplicate[0]}" if duplicate
  end
  Array(node.children).each { |child| walk.call(child) } if node.respond_to?(:children)
end
walk.call(document)
data = Psych.safe_load(File.read(ARGV[0]), aliases: false)
puts JSON.generate(data || {})
"""


def _raw_psych(path: Path) -> dict:
    completed = subprocess.run(
        ["ruby", "-rpsych", "-rjson", "-e", _PSYCH_SCRIPT, str(path)],
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode:
        raise ValueError(completed.stderr.strip() or f"cannot parse {path}")
    parsed = json.loads(completed.stdout)
    if not isinstance(parsed, dict):
        raise ValueError(f"{path} must contain a mapping")
    return parsed


_CONTRACT: dict | None = None


def contract() -> dict:
    global _CONTRACT
    if _CONTRACT is None:
        lock = _raw_psych(LOCK_PATH)
        relative = lock.get("machine_contracts", {}).get("cache_policy")
        if not isinstance(relative, str) or not relative.strip():
            raise ValueError("architecture.lock.yaml must register machine_contracts.cache_policy")
        loaded = _raw_psych(ROOT / relative)
        if (
            loaded.get("kind") != "CachePolicy"
            or loaded.get("architecture_authority") != "architecture.lock.yaml"
            or loaded.get("identity", {}).get("algorithm") != "sha256"
        ):
            raise ValueError("canonical cache policy envelope or SHA-256 identity is invalid")
        _CONTRACT = loaded
    return copy.deepcopy(_CONTRACT)


def _stable_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest_paths(paths: list[Path] | tuple[Path, ...], *, root: Path = ROOT) -> str:
    digest = hashlib.sha256()
    normalized: list[tuple[str, Path]] = []
    root = root.resolve()
    for raw in paths:
        path = Path(raw)
        resolved = path if path.is_absolute() else root / path
        try:
            label = resolved.relative_to(root).as_posix()
        except ValueError:
            label = resolved.as_posix()
        normalized.append((label, resolved))
    for label, path in sorted(normalized):
        digest.update(label.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def digest_globs(patterns: list[str] | tuple[str, ...], *, root: Path = ROOT) -> str:
    """Digest the complete current content set selected by repository-relative globs."""
    root = root.resolve()
    digest = hashlib.sha256()
    selected: dict[str, Path] = {}
    for pattern in patterns:
        if not isinstance(pattern, str) or not pattern.strip():
            raise ValueError("cache input patterns must be non-empty strings")
        digest.update(b"pattern\0")
        digest.update(pattern.encode("utf-8"))
        digest.update(b"\0")
        for path in root.glob(pattern):
            if not path.is_file():
                continue
            relative = path.resolve().relative_to(root).as_posix()
            selected[relative] = path
    for relative, path in sorted(selected.items()):
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def tool_version(executable: str, *args: str) -> str:
    key = (executable, tuple(args))
    cached = _TOOL_VERSIONS.get(key)
    if cached is not None:
        return cached
    completed = subprocess.run(
        [executable, *args],
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError(
            (completed.stderr or completed.stdout or "").strip()
            or f"cannot identify tool {executable}"
        )
    value = (completed.stdout or completed.stderr or "").strip()
    _TOOL_VERSIONS[key] = value
    return value


def executable_identity(executable: str) -> dict[str, str]:
    cached = _EXECUTABLE_IDENTITIES.get(executable)
    if cached is not None:
        return dict(cached)
    resolved = shutil.which(executable) if not Path(executable).is_absolute() else executable
    if not resolved:
        return {"path": executable, "sha256": "absent"}
    path = Path(resolved).resolve()
    identity = {"path": str(path), "sha256": sha256_bytes(path.read_bytes())}
    _EXECUTABLE_IDENTITIES[executable] = identity
    return dict(identity)


def build_key(
    namespace: str,
    *,
    input_content_digest: str,
    validator_content_digest: str,
    tool_identity: Any,
    options: Any,
) -> str:
    material = {
        "schema_version": _SCHEMA_VERSION,
        "namespace": namespace,
        "input_content_digest": input_content_digest,
        "validator_content_digest": validator_content_digest,
        "tool_identity": tool_identity,
        "options": options,
    }
    return sha256_bytes(_stable_json(material))


def cache_root() -> Path:
    layer = contract()["layers"]["l2"]
    env_name = str(layer["root_source"])
    configured = os.environ.get(env_name, "").strip()
    base = Path(configured).expanduser() if configured else Path(str(layer["fallback_root"])).expanduser()
    return base / str(layer["subdirectory"])


def _safe_namespace(namespace: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", namespace).strip("-")
    if not safe:
        raise ValueError("cache namespace must not be empty")
    return safe


def _entry_path(namespace: str, key: str) -> Path:
    return cache_root() / _safe_namespace(namespace) / f"{key}.json"


def clear_memory_cache(namespace: str | None = None) -> None:
    if namespace is None:
        _MEMORY.clear()
        return
    for entry in [entry for entry in _MEMORY if entry[0] == namespace]:
        _MEMORY.pop(entry, None)


def memory_entry_count(namespace: str | None = None) -> int:
    if namespace is None:
        return len(_MEMORY)
    return sum(1 for entry in _MEMORY if entry[0] == namespace)


def load_success(namespace: str, key: str) -> Any | None:
    memory_key = (namespace, key)
    if memory_key in _MEMORY:
        return copy.deepcopy(_MEMORY[memory_key])

    path = _entry_path(namespace, key)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != _SCHEMA_VERSION
        or payload.get("namespace") != namespace
        or payload.get("key") != key
        or payload.get("status") != "PASS"
        or "value" not in payload
    ):
        return None
    value = payload["value"]
    _MEMORY[memory_key] = value
    return copy.deepcopy(value)


def store_success(namespace: str, key: str, value: Any) -> None:
    memory_key = (namespace, key)
    safe_value = copy.deepcopy(value)
    _MEMORY[memory_key] = safe_value

    temporary: Path | None = None
    try:
        path = _entry_path(namespace, key)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": _SCHEMA_VERSION,
            "namespace": namespace,
            "key": key,
            "status": "PASS",
            "value": safe_value,
        }
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{key}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            temporary = Path(handle.name)
        os.replace(temporary, path)
        temporary = None
    except (OSError, TypeError, ValueError):
        # Cache availability must never become qualification authority.
        return
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass


def memoize_success(
    namespace: str,
    key: str,
    producer: Callable[[], Any],
) -> tuple[Any, bool]:
    cached = load_success(namespace, key)
    if cached is not None:
        return cached, True
    value = producer()
    store_success(namespace, key, value)
    return copy.deepcopy(value), False


def psych_load(path: Path | str) -> dict:
    path = Path(path)
    contents = path.read_bytes()
    input_digest = sha256_bytes(contents)
    key = build_key(
        "psych-yaml",
        input_content_digest=input_digest,
        validator_content_digest=sha256_bytes(_PSYCH_SCRIPT.encode("utf-8")),
        tool_identity={
            "version": tool_version("ruby", "--version"),
            "executable": executable_identity("ruby"),
        },
        options={"aliases": False, "result": "mapping"},
    )

    cached = load_success("psych-yaml", key)
    if cached is not None:
        return cached

    parsed = _raw_psych(path)
    if path.read_bytes() == contents:
        store_success("psych-yaml", key, parsed)
    return copy.deepcopy(parsed)
