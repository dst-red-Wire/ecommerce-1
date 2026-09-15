#!/usr/bin/env python3
"""Prepare the fully locked Galaxy collection closure once, then work offline."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
import re
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "platform/ansible/collections.lock.json"
TOOL_HOME = Path(os.environ.get("ECOMMERCE_TOOL_HOME", Path.home() / ".cache/ecommerce-1/qualification"))


def load_lock() -> dict:
    try:
        return _load_lock()
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise RuntimeError("invalid or missing locked Ansible collection metadata") from exc


def _load_lock() -> dict:
    data = json.loads(LOCK.read_text(encoding="utf-8"))
    names = {item["name"] for item in data["collections"]}
    direct = {item["name"] for item in data["collections"] if item["direct"]}
    expected = _direct_requirements()
    if direct != set(expected) or any(
        next(x for x in data["collections"] if x["name"] == n)["version"] != v for n, v in expected.items()
    ):
        raise RuntimeError("collections.lock.json direct pins differ from requirements.yml")
    for item in data["collections"]:
        for dependency in item["dependencies"]:
            if dependency not in names:
                raise RuntimeError(f"unlocked transitive dependency: {item['name']} -> {dependency}")
    return data


def _direct_requirements() -> dict[str, str]:
    result, name = {}, None
    for raw in (ROOT / "platform/ansible/requirements.yml").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line.startswith("- name:"):
            name = line.split(":", 1)[1].strip()
        elif line.startswith("version:") and name:
            result[name] = line.split(":", 1)[1].strip()
            name = None
    return result


def identity() -> str:
    return hashlib.sha256(LOCK.read_bytes()).hexdigest()


def paths() -> tuple[Path, Path]:
    base = TOOL_HOME / "ansible"
    return base / "archives", base / "collections" / identity()


def generation_root(destination: Path) -> Path:
    root = destination.with_suffix(".generations")
    if root.is_symlink():
        raise RuntimeError("collection generation root must not be a symlink")
    return root


def selected_path() -> Path:
    """Pin a concrete generation once for a consumer; legacy trees stay in place."""
    legacy = paths()[1]
    generations = generation_root(legacy)
    selector = legacy.with_suffix(".current")
    if selector.is_symlink():
        # A missing in-identity generation is an invalid cache, repairable from
        # locked archives. Still resolve existing links before checking ownership.
        selected = selector.resolve()
        if selected.parent != generations.resolve():
            raise RuntimeError("collection selector escapes its identity")
        return selected
    if selector.exists():
        raise RuntimeError("invalid collection generation selector")
    return legacy.resolve()


def payload_ok(item: dict, root: Path) -> bool:
    """Compare payload and inventory to the checksum-locked archive, including links.

    Galaxy FILES format 1 describes symlinks as files. Tar metadata is the
    authoritative type/link inventory, so do not mistake those links for files.
    """
    archive = archive_path(item)
    validate_archive(item, archive)
    if root.is_symlink() or not root.is_dir():
        return False
    concrete = root.resolve()
    with tarfile.open(archive, "r:gz") as bundle:
        seen = set()
        checked_parents = set()
        for member in bundle:
            name = PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts or member.name in seen:
                return False
            seen.add(str(name))
            target = root.joinpath(*name.parts)
            # Validate each parent once within this verification, never across runs.
            for parent in target.parents:
                if parent == root:
                    break
                if parent in checked_parents:
                    break
                if parent.is_symlink() or not parent.is_dir():
                    return False
                checked_parents.add(parent)
            if member.issym():
                if not target.is_symlink() or os.readlink(target) != member.linkname:
                    return False
                link = PurePosixPath(member.linkname)
                if link.is_absolute() or not (target.parent / member.linkname).resolve().is_relative_to(concrete):
                    return False
            elif member.isdir():
                if target.is_symlink() or not target.is_dir():
                    return False
            elif member.isfile():
                if target.is_symlink() or not target.is_file() or target.stat().st_size != member.size:
                    return False
                stream = bundle.extractfile(member)
                expected = hashlib.file_digest(stream, "sha256").hexdigest()
                if digest(target) != expected:
                    return False
            else:
                return False
    actual = set()
    pending = [root]
    while pending:
        for entry in pending.pop().iterdir():
            actual.add(entry.relative_to(root).as_posix())
            if entry.is_dir() and not entry.is_symlink():
                pending.append(entry)
    return actual == seen - {"."}


def archive_path(item: dict) -> Path:
    archives, _ = paths()
    return archives / f"{item['name'].replace('.', '-')}-{item['version']}-{item['sha256']}.tar.gz"


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def validate_archive(item: dict, path: Path) -> None:
    if not path.is_file() or path.stat().st_size != item["size"] or digest(path) != item["sha256"]:
        raise RuntimeError(f"invalid archive {item['name']}:{item['version']} ({path})")
    with tarfile.open(path, "r:gz") as bundle:
        seen = set()
        for member in bundle.getmembers():
            name = PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts or str(name) in seen:
                raise RuntimeError(f"unsafe archive path in {item['name']}")
            seen.add(str(name))
            if member.issym():
                link = PurePosixPath(member.linkname)
                target = posixpath.normpath(str(name.parent / link))
                if link.is_absolute() or target == ".." or target.startswith("../"):
                    raise RuntimeError(f"unsafe archive link in {item['name']}")
            elif not (member.isdir() or member.isfile()):
                raise RuntimeError(f"unsupported archive member type in {item['name']}")
        manifest = json.load(bundle.extractfile("MANIFEST.json"))
    info = manifest["collection_info"]
    got = f"{info['namespace']}.{info['name']}:{info['version']}"
    if got != f"{item['name']}:{item['version']}" or info.get("dependencies", {}) != item["dependencies"]:
        raise RuntimeError(f"archive manifest mismatch for {item['name']}:{item['version']}")


def installed_ok(data: dict, destination: Path) -> bool:
    marker = destination / ".ecommerce-collections.json"
    try:
        if marker.is_symlink() or {entry.name for entry in destination.iterdir()} != {
            "ansible_collections",
            marker.name,
        }:
            return False
        expected_names = {}
        for item in data["collections"]:
            namespace, collection = item["name"].split(".")
            expected_names.setdefault(namespace, set()).add(collection)
        closure = destination / "ansible_collections"
        if closure.is_symlink() or {entry.name for entry in closure.iterdir()} != set(expected_names):
            return False
        for namespace, names in expected_names.items():
            folder = closure / namespace
            if folder.is_symlink() or {entry.name for entry in folder.iterdir()} != names:
                return False
        provenance = json.loads(marker.read_text(encoding="utf-8"))
        if provenance.get("installer", {}).get("ansible_core") != data["installer"]["ansible_core"]:
            return False
        if not Path(provenance.get("installer", {}).get("executable", "")).is_absolute():
            return False
        if provenance["identity"] != identity():
            return False
        for item in data["collections"]:
            namespace, collection = item["name"].split(".")
            if any(
                (destination / relative).is_symlink()
                for relative in ("ansible_collections", f"ansible_collections/{namespace}")
            ):
                return False
            manifest = destination / "ansible_collections" / namespace / collection / "MANIFEST.json"
            if not payload_ok(item, manifest.parent):
                return False
            info = json.loads(manifest.read_text(encoding="utf-8"))["collection_info"]
            if str(info["version"]) != item["version"] or info.get("dependencies", {}) != item["dependencies"]:
                return False
    except (OSError, KeyError, ValueError, TypeError, RuntimeError, tarfile.TarError):
        return False
    return True


def acquire(item: dict, *, offline: bool) -> None:
    target = archive_path(item)
    try:
        validate_archive(item, target)
        print(f"REUSE archive {item['name']}:{item['version']}")
        return
    except RuntimeError:
        if target.exists() and not target.is_file() and not target.is_symlink():
            raise RuntimeError(
                f"invalid archive path type for {item['name']}:{item['version']}; expected file"
            ) from None
        if target.exists():
            target.unlink()
    if offline:
        raise RuntimeError(f"missing locked archive {item['name']}:{item['version']} sha256={item['sha256']}")
    target.parent.mkdir(parents=True, exist_ok=True)
    url = f"https://galaxy.ansible.com/api/v3/plugin/ansible/content/published/collections/artifacts/{item['name'].replace('.', '-')}-{item['version']}.tar.gz"
    for attempt in range(1, 4):
        temporary = target.with_name(f".{target.name}.{os.getpid()}.part")
        try:
            print(f"ACQUIRE {item['name']}:{item['version']} attempt={attempt}/3 timeout=30s")
            request = urllib.request.Request(url, headers={"User-Agent": "ecommerce-1-collection-lock/1"})
            with urllib.request.urlopen(request, timeout=30) as response, temporary.open("wb") as output:
                total = 0
                while chunk := response.read(1024 * 1024):
                    output.write(chunk)
                    total += len(chunk)
                    print(f"PROGRESS {item['name']} bytes={total}")
            validate_archive(item, temporary)
            os.replace(temporary, target)
            return
        except (OSError, urllib.error.URLError, RuntimeError) as exc:
            temporary.unlink(missing_ok=True)
            if attempt == 3:
                raise RuntimeError(
                    f"acquisition failed for {item['name']}:{item['version']}: {type(exc).__name__}"
                ) from exc
            time.sleep(attempt)


def installer_provenance(
    data: dict, *, env: dict[str, str] | None = None, playbook_command: str = "ansible-playbook"
) -> dict[str, str]:
    effective_env = os.environ if env is None else env
    search_path = effective_env.get("PATH", os.defpath)
    galaxy = shutil.which("ansible-galaxy", path=search_path)
    if not galaxy:
        raise RuntimeError("ansible-galaxy missing: run make seed and use its locked PATH")
    galaxy = str(Path(galaxy).resolve())
    probe = subprocess.run(
        [galaxy, "--version"], text=True, capture_output=True, check=False, timeout=15, env=effective_env
    )
    match = re.search(r"ansible-galaxy \[core ([^\]]+)\]", probe.stdout)
    actual = match.group(1) if match else "unknown"
    expected = data["installer"]["ansible_core"]
    if probe.returncode or actual != expected:
        raise RuntimeError(
            f"ansible-galaxy installer mismatch: expected {expected}, got {actual} at {galaxy}; run make seed"
        )
    playbook = shutil.which(playbook_command, path=search_path)
    if not playbook:
        raise RuntimeError("ansible-playbook missing: run make seed")
    probe = subprocess.run(
        [playbook, "--version"], text=True, capture_output=True, check=False, timeout=15, env=effective_env
    )
    match = re.search(r"ansible-playbook \[core ([^\]]+)\]", probe.stdout)
    if probe.returncode or not match or match.group(1) != expected:
        raise RuntimeError(f"ansible-playbook provider mismatch: expected {expected}; run make seed")
    return {"ansible_core": actual, "executable": galaxy}


def install(data: dict, destination: Path) -> None:
    provenance = installer_provenance(data)
    destination.parent.mkdir(parents=True, exist_ok=True)
    generations = generation_root(destination)
    generations.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix="generation-", dir=generations))
    selector = destination.with_suffix(".current")
    pending = selector.with_name(f".{selector.name}.{os.getpid()}.tmp")
    published = False
    try:
        galaxy = provenance["executable"]
        env = os.environ.copy()
        env["ANSIBLE_COLLECTIONS_PATH"] = str(temporary)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        for item in data["collections"]:
            subprocess.run(
                [
                    galaxy,
                    "collection",
                    "install",
                    str(archive_path(item)),
                    "--collections-path",
                    str(temporary),
                    "--no-deps",
                ],
                check=True,
                env=env,
            )
        (temporary / ".ecommerce-collections.json").write_text(
            json.dumps({"identity": identity(), "installer": provenance}, sort_keys=True) + "\n", encoding="utf-8"
        )
        if not installed_ok(data, temporary):
            raise RuntimeError("installed collection closure failed validation")
        pending.unlink(missing_ok=True)
        pending.symlink_to(temporary, target_is_directory=True)
        os.replace(pending, selector)
        published = True
        print(f"PUBLISH collections identity={identity()} path={temporary} selector={selector}")
    finally:
        pending.unlink(missing_ok=True)
        if not published and temporary.exists():
            shutil.rmtree(temporary)


def prepare(*, offline: bool = False) -> None:
    data = load_lock()
    _, destination = paths()
    installer_provenance(data)
    current = selected_path()
    if installed_ok(data, current):
        print(f"REUSE collections identity={identity()} path={current}")
        return
    lock_path = destination.with_suffix(".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    from capability_bootstrap import identity_lock

    with identity_lock(lock_path):
        current = selected_path()
        if installed_ok(data, current):
            print(f"REUSE collections identity={identity()} path={current} after-lock=true")
            return
        for item in data["collections"]:
            acquire(item, offline=offline)
        install(data, destination)


def run_playbook(arguments: list[str]) -> int:
    from capability_bootstrap import seed_environment, LOCAL_SEED_VENV

    seed_environment()
    env = os.environ.copy()
    env["PATH"] = str(LOCAL_SEED_VENV / "bin") + os.pathsep + env.get("PATH", "")
    subprocess.run([str(LOCAL_SEED_VENV / "bin/python"), str(Path(__file__).resolve()), "prepare"], env=env, check=True)
    env["ANSIBLE_COLLECTIONS_PATH"] = str(selected_path())
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    executable = LOCAL_SEED_VENV / "bin/ansible-playbook"
    return subprocess.run([str(executable), *arguments], env=env, check=False).returncode


def main() -> int:
    if sys.argv[1:2] == ["run-playbook"]:
        return run_playbook(sys.argv[3:] if sys.argv[2:3] == ["--"] else sys.argv[2:])
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("prepare", "acquire", "check", "identity"))
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "identity":
            print(identity())
        elif args.command == "check":
            data = load_lock()
            if not installed_ok(data, selected_path()):
                raise RuntimeError(f"collection installation invalid or missing: identity={identity()}")
            print(f"PASS collections identity={identity()} path={selected_path()}")
        elif args.command == "acquire":
            for item in load_lock()["collections"]:
                acquire(item, offline=args.offline)
        else:
            prepare(offline=args.offline)
    except RuntimeError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
