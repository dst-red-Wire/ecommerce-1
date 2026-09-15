#!/usr/bin/env python3
"""Prepare the fully locked Galaxy collection closure once, then work offline."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
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
        manifest = json.load(bundle.extractfile("MANIFEST.json"))
    info = manifest["collection_info"]
    got = f"{info['namespace']}.{info['name']}:{info['version']}"
    if got != f"{item['name']}:{item['version']}" or info.get("dependencies", {}) != item["dependencies"]:
        raise RuntimeError(f"archive manifest mismatch for {item['name']}:{item['version']}")


def installed_ok(data: dict, destination: Path) -> bool:
    marker = destination / ".ecommerce-collections.json"
    try:
        provenance = json.loads(marker.read_text(encoding="utf-8"))
        if provenance.get("installer", {}).get("ansible_core") != data["installer"]["ansible_core"]:
            return False
        if not Path(provenance.get("installer", {}).get("executable", "")).is_absolute():
            return False
        if provenance["identity"] != identity():
            return False
        for item in data["collections"]:
            namespace, collection = item["name"].split(".")
            manifest = destination / "ansible_collections" / namespace / collection / "MANIFEST.json"
            info = json.loads(manifest.read_text(encoding="utf-8"))["collection_info"]
            if str(info["version"]) != item["version"] or info.get("dependencies", {}) != item["dependencies"]:
                return False
    except (OSError, KeyError, json.JSONDecodeError):
        return False
    return True


def acquire(item: dict, *, offline: bool) -> None:
    target = archive_path(item)
    try:
        validate_archive(item, target)
        print(f"REUSE archive {item['name']}:{item['version']}")
        return
    except RuntimeError:
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


def installer_provenance(data: dict) -> dict[str, str]:
    galaxy = shutil.which("ansible-galaxy")
    if not galaxy:
        raise RuntimeError("ansible-galaxy missing: run make seed and use its locked PATH")
    galaxy = str(Path(galaxy).resolve())
    probe = subprocess.run([galaxy, "--version"], text=True, capture_output=True, check=False, timeout=15)
    match = re.search(r"ansible-galaxy \[core ([^\]]+)\]", probe.stdout)
    actual = match.group(1) if match else "unknown"
    expected = data["installer"]["ansible_core"]
    if probe.returncode or actual != expected:
        raise RuntimeError(
            f"ansible-galaxy installer mismatch: expected {expected}, got {actual} at {galaxy}; run make seed"
        )
    playbook = shutil.which("ansible-playbook")
    if not playbook:
        raise RuntimeError("ansible-playbook missing: run make seed")
    probe = subprocess.run([playbook, "--version"], text=True, capture_output=True, check=False, timeout=15)
    match = re.search(r"ansible-playbook \[core ([^\]]+)\]", probe.stdout)
    if probe.returncode or not match or match.group(1) != expected:
        raise RuntimeError(f"ansible-playbook provider mismatch: expected {expected}; run make seed")
    return {"ansible_core": actual, "executable": galaxy}


def install(data: dict, destination: Path) -> None:
    provenance = installer_provenance(data)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{identity()}.install-", dir=destination.parent))
    try:
        galaxy = provenance["executable"]
        env = os.environ.copy()
        env["ANSIBLE_COLLECTIONS_PATH"] = str(temporary)
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
        if destination.exists():
            shutil.rmtree(destination)
        os.replace(temporary, destination)
        print(f"PUBLISH collections identity={identity()} path={destination}")
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def prepare(*, offline: bool = False) -> None:
    data = load_lock()
    _, destination = paths()
    installer_provenance(data)
    if installed_ok(data, destination):
        print(f"REUSE collections identity={identity()} path={destination}")
        return
    lock_path = destination.with_suffix(".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    from capability_bootstrap import identity_lock

    with identity_lock(lock_path):
        if installed_ok(data, destination):
            print(f"REUSE collections identity={identity()} path={destination} after-lock=true")
            return
        for item in data["collections"]:
            acquire(item, offline=offline)
        install(data, destination)


def run_playbook(arguments: list[str]) -> int:
    from capability_bootstrap import seed_environment, LOCAL_SEED_VENV

    seed_environment()
    env = os.environ.copy()
    env["PATH"] = str(LOCAL_SEED_VENV / "bin") + os.pathsep + env.get("PATH", "")
    env["ANSIBLE_COLLECTIONS_PATH"] = str(paths()[1])
    subprocess.run([str(LOCAL_SEED_VENV / "bin/python"), str(Path(__file__).resolve()), "prepare"], env=env, check=True)
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
            if not installed_ok(data, paths()[1]):
                raise RuntimeError(f"collection installation invalid or missing: identity={identity()}")
            print(f"PASS collections identity={identity()} path={paths()[1]}")
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
