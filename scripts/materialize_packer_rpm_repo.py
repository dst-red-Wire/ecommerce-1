#!/usr/bin/env python3
"""Materialize the complete checksum-locked offline input for the Rocky Packer build."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


class MaterializationError(ValueError):
    """Bounded failure without artifact content in diagnostics."""


def digest(path: Path) -> str:
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def _verify(path: Path, *, artifact: str, version: str, expected: str) -> None:
    actual = digest(path)
    if actual != expected:
        raise MaterializationError(
            f"artifact={artifact} expected_version={version} "
            f"expected_sha256={expected} actual_sha256={actual}"
        )


def _copy_file(source: Path, destination: Path) -> None:
    """Copy across filesystems without the platform-dependent sendfile fast path."""
    with source.open("rb") as input_stream, destination.open("wb") as output_stream:
        shutil.copyfileobj(input_stream, output_stream, length=4 * 1024 * 1024)
        output_stream.flush()
        os.fsync(output_stream.fileno())


def _acquire(entry: dict, destination: Path, cache: Path | None, offline: bool) -> None:
    artifact = entry["file"]
    version = entry.get("nevra", entry.get("version", "locked"))
    expected = entry["sha256"]
    cached = cache / expected / artifact if cache is not None else None
    if cached is not None and cached.is_file():
        _verify(cached, artifact=artifact, version=version, expected=expected)
        _copy_file(cached, destination)
    elif offline:
        raise MaterializationError(
            f"artifact={artifact} expected_version={version} "
            f"expected_sha256={expected} actual_sha256=missing"
        )
    else:
        request = urllib.request.Request(
            entry["url"],
            headers={"User-Agent": "ecommerce-packer-offline-materializer/2"},
        )
        try:
            with (
                urllib.request.urlopen(request, timeout=120) as response,
                destination.open("wb") as output,
            ):
                shutil.copyfileobj(response, output, length=1024 * 1024)
        except (OSError, urllib.error.URLError) as error:
            raise MaterializationError(
                f"artifact={artifact} expected_version={version} "
                f"expected_sha256={expected} actual_sha256=missing"
            ) from error
        _verify(destination, artifact=artifact, version=version, expected=expected)
        if cached is not None:
            cached.parent.mkdir(parents=True, exist_ok=True)
            _copy_file(destination, cached)
    _verify(destination, artifact=artifact, version=version, expected=expected)


def _manifest_is_valid(document: dict) -> bool:
    unsigned = dict(document)
    approved = unsigned.pop("approved_manifest_sha256", None)
    body = json.dumps(unsigned, sort_keys=True, indent=2) + "\n"
    return approved == hashlib.sha256(body.encode()).hexdigest()


def _write_sums(directory: Path, entries: list[dict]) -> None:
    lines = [f"{entry['sha256']}  {entry['file']}" for entry in entries]
    (directory / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _tool_entry(toolchain: dict, name: str) -> dict:
    try:
        tool = toolchain["tools"][name]
        version = toolchain["versions"][tool["version_ref"]]
        checksum = toolchain["versions"][tool["sha256_ref"]]
    except KeyError as error:
        raise MaterializationError(
            f"incomplete central tool entry for {name}: {error}"
        ) from error
    return {
        "file": tool["artifact"]["filename"],
        "url": tool["artifact"]["url"],
        "sha256": checksum,
        "version": version,
        "name": name,
        "architecture": tool["architecture"],
        "install": tool["install"],
        "binary": tool["binary"],
        "version_command": tool["version_command"],
        **({"qualification": tool["qualification"]} if "qualification" in tool else {}),
    }


def materialize(
    contract_path: Path,
    package_lock_path: Path,
    toolchain_path: Path,
    output: Path,
    *,
    cache: Path | None = None,
    offline: bool = False,
) -> dict:
    contract = yaml.safe_load(contract_path.read_text(encoding="utf-8"))
    image = contract["packer_image"]
    package_lock = json.loads(package_lock_path.read_text(encoding="utf-8"))
    toolchain = json.loads(toolchain_path.read_text(encoding="utf-8"))
    if (
        package_lock.get("schema_version") != 2
        or package_lock.get("image") != image["id"]
        or package_lock.get("dependency_closure") != "complete-per-profile"
        or not _manifest_is_valid(package_lock)
    ):
        raise MaterializationError("invalid Rocky image package lock")
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise MaterializationError(
            "output must be a new path below an existing directory"
        )

    source = image["source"]
    iso = {
        "file": source["iso"],
        "url": source["url"],
        "sha256": source["sha256"],
        "version": image["os"]["version"],
    }
    tool_profiles = {
        "base": image["profiles"]["base"]["external_tools"],
        "rke2": image["profiles"]["rke2"]["external_tools"],
        "admin-qualification": image["profiles"]["admin-qualification"][
            "external_tools"
        ],
    }
    with tempfile.TemporaryDirectory(
        prefix=output.name + ".", dir=output.parent
    ) as temporary:
        staging = Path(temporary)
        shutil.copyfile(
            ROOT / "scripts/install_packer_tools.py", staging / "install_tools.py"
        )
        iso_dir = staging / "iso"
        key_dir = staging / "rpm-keys"
        iso_dir.mkdir()
        key_dir.mkdir()
        _acquire(iso, iso_dir / iso["file"], cache, offline)
        _write_sums(iso_dir, [iso])

        keys = package_lock["rpm_signing_keys"]
        for entry in keys:
            _acquire(entry, key_dir / entry["file"], cache, offline)
        _write_sums(key_dir, keys)

        for profile, definition in package_lock["profiles"].items():
            if not _manifest_is_valid(definition):
                raise MaterializationError(f"invalid RPM profile manifest: {profile}")
            profile_dir = staging / "rpms" / profile
            profile_dir.mkdir(parents=True)
            for entry in definition["packages"]:
                _acquire(entry, profile_dir / entry["file"], cache, offline)
            _write_sums(profile_dir, definition["packages"])
            (profile_dir / "manifest.json").write_text(
                json.dumps(definition, sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
            )

        tool_counts = {}
        for profile, names in tool_profiles.items():
            entries = [_tool_entry(toolchain, name) for name in names]
            profile_dir = staging / "tools" / profile
            profile_dir.mkdir(parents=True)
            for entry in entries:
                _acquire(entry, profile_dir / entry["file"], cache, offline)
            _write_sums(profile_dir, entries)
            (profile_dir / "manifest.json").write_text(
                json.dumps(entries, sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
            )
            tool_counts[profile] = len(entries)

        evidence = {
            "image": image["id"],
            "contract_sha256": digest(contract_path),
            "package_lock_sha256": digest(package_lock_path),
            "toolchain_lock_sha256": digest(toolchain_path),
            "rpm_profiles": {
                name: len(value["packages"])
                for name, value in package_lock["profiles"].items()
            },
            "tool_profiles": tool_counts,
        }
        (staging / "evidence.json").write_text(
            json.dumps(evidence, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        os.replace(staging, output)
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--package-lock", required=True, type=Path)
    parser.add_argument("--toolchain-lock", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cache", type=Path)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    evidence = materialize(
        args.contract.resolve(),
        args.package_lock.resolve(),
        args.toolchain_lock.resolve(),
        args.output.resolve(),
        cache=args.cache.resolve() if args.cache else None,
        offline=args.offline,
    )
    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
