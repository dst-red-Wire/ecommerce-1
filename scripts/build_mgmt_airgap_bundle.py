#!/usr/bin/env python3
"""Assemble the locked MGMT RKE2 air-gap bundle without installing it."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.request
import uuid
from pathlib import Path


class BuildError(ValueError):
    """A bounded bundle construction failure."""


def digest(path: Path) -> str:
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BuildError(message)


def safe_name(value: object) -> str:
    require(isinstance(value, str), "artifact filename must be a string")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", value) is not None,
            "unsafe artifact filename")
    return value


def checked_lock(path: Path, expected_version: str) -> dict:
    document = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(document, dict) and document.get("schema_version") == 1,
            "unsupported bundle lock schema")
    require(document.get("rke2_version") == expected_version,
            "bundle lock differs from canonical RKE2 version")
    require(re.fullmatch(r"[0-9a-f]{64}", str(document.get("approved_manifest_sha256"))) is not None,
            "independently approved manifest SHA256 is required")
    target = document.get("target")
    require(target == {"architecture": "amd64", "os": "rocky-10.2"},
            "bundle lock target must be Rocky 10.2 amd64")
    image = document.get("preparer_image")
    require(isinstance(image, str) and re.fullmatch(
        r"[A-Za-z0-9./_-]+@sha256:[0-9a-f]{64}", image),
        "preparer image must use a digest")
    releases = document.get("release_artifacts")
    require(isinstance(releases, dict)
            and set(releases) == {"binary", "images-core", "images-cilium"},
            "locked RKE2 release artifact set is incomplete")
    keys = document.get("rpm_signing_keys")
    rpms = document.get("rpms")
    require(isinstance(keys, list) and keys and isinstance(rpms, list) and rpms,
            "locked RPMs and signing keys are required")
    names: set[str] = set()
    for entry in [*releases.values(), *keys, *rpms]:
        require(isinstance(entry, dict), "invalid locked artifact")
        name = safe_name(entry.get("file"))
        require(name not in names, "duplicate locked artifact filename")
        names.add(name)
        checksum = entry.get("sha256")
        require(isinstance(checksum, str) and re.fullmatch(r"[0-9a-f]{64}", checksum),
                "locked artifact SHA256 is required")
        url = entry.get("url")
        require(isinstance(url, str) and url.startswith("https://"),
                "locked artifact URL must use HTTPS")
        if "compressed_file" in entry:
            safe_name(entry.get("compressed_file"))
            require(re.fullmatch(r"[0-9a-f]{64}", str(entry.get("compressed_sha256"))) is not None,
                    "compressed artifact SHA256 is required")
    inventory = document.get("image_inventory")
    require(isinstance(inventory, dict)
            and inventory.get("rke2_version") == expected_version,
            "locked image inventory differs from canonical RKE2 version")
    return document


def download(url: str, destination: Path, expected_sha256: str) -> None:
    partial = destination.with_name(destination.name + ".partial")
    partial.unlink(missing_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": "ecommerce-mgmt-bundle-builder/1"})
    try:
        with urllib.request.urlopen(request, timeout=120) as response, partial.open("wb") as output:
            shutil.copyfileobj(response, output, length=1024 * 1024)
        require(digest(partial) == expected_sha256, "downloaded artifact digest mismatch")
        os.replace(partial, destination)
    finally:
        partial.unlink(missing_ok=True)


def acquire(entry: dict, cache: Path, source: Path | None, offline: bool,
            compressed: bool = False) -> Path:
    filename = safe_name(entry["compressed_file"] if compressed else entry["file"])
    expected = entry["compressed_sha256"] if compressed else entry["sha256"]
    roots = [path for path in (source, cache) if path is not None]
    candidates = []
    if compressed:
        # A prepared source bundle or cache may provide the already verified,
        # uncompressed bytes. Prefer them so an offline build never needs a
        # decompressor container or package repository.
        candidates.extend(path / safe_name(entry["file"]) for path in roots)
    candidates.extend(path / filename for path in roots)
    for candidate in candidates:
        if candidate.is_file():
            candidate_expected = entry["sha256"] if candidate.name == entry["file"] else expected
            require(digest(candidate) == candidate_expected, "cached artifact digest mismatch")
            return candidate
    require(not offline, "locked artifact absent from offline cache")
    destination = cache / filename
    download(entry["url"], destination, expected)
    return destination


def docker(*arguments: str, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *arguments], check=True, text=True,
        capture_output=capture, timeout=1800,
    )


def decompress_zstd(source: Path, destination: Path, image: str) -> None:
    name = "ecommerce-mgmt-zstd-" + uuid.uuid4().hex
    docker("create", "--name", name, "--network", "bridge",
           "--mount", f"type=bind,src={source.parent},dst=/input,readonly",
           "--mount", f"type=bind,src={destination.parent},dst=/output",
           image, "/usr/bin/sleep", "infinity")
    try:
        docker("start", name)
        docker("exec", name, "dnf", "-qy", "install", "zstd")
        docker("exec", name, "unzstd", "--force", "/input/" + source.name,
               "-o", "/output/" + destination.name)
    finally:
        subprocess.run(["docker", "rm", "--force", name], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def materialize_release(entry: dict, cache: Path, source: Path | None,
                        destination: Path, image: str, offline: bool) -> None:
    acquired = acquire(entry, cache, source, offline, compressed=True)
    if acquired.name == entry["file"]:
        shutil.copyfile(acquired, destination)
    else:
        require(not offline,
                "offline mode requires the verified uncompressed artifact; "
                "networked decompression is forbidden")
        decompress_zstd(acquired, destination, image)
    require(digest(destination) == entry["sha256"],
            "decompressed artifact digest mismatch")


def manifest_from_lock(lock: dict) -> dict:
    artifacts = []
    for entry in lock["rpm_signing_keys"]:
        artifacts.append({key: value for key, value in entry.items() if key != "url"})
    for entry in lock["rpms"]:
        artifacts.append({key: value for key, value in entry.items() if key != "url"})
    for entry in lock["release_artifacts"].values():
        artifacts.append({
            key: value for key, value in entry.items()
            if key not in {"url", "compressed_file", "compressed_sha256"}
        })
    return {
        "architecture": "amd64",
        "artifacts": sorted(artifacts, key=lambda item: item["file"]),
        "image_inventory": lock["image_inventory"],
        "os": "rocky-10.2",
        "rke2_version": lock["rke2_version"],
        "rpm_dependency_closure": "complete",
        "schema_version": 1,
    }


def checked_services(value: str) -> str:
    services = json.loads(value)
    require(isinstance(services, dict) and set(services) == {"dns", "ntp"},
            "fixture services must contain only dns and ntp")
    for name in ("dns", "ntp"):
        require(isinstance(services[name], list) and services[name],
                f"fixture {name} service addresses are required")
        require(all(isinstance(address, str) for address in services[name]),
                f"fixture {name} service addresses must be strings")
    return json.dumps(services, separators=(",", ":"), sort_keys=True)


def validate_in_pinned_container(bundle: Path, manifest_sha256: str, lock: dict,
                                 repository: Path, services: str) -> dict:
    result = docker(
        "run", "--rm", "--network", "none",
        "--mount", f"type=bind,src={bundle},dst=/bundle,readonly",
        "--mount", f"type=bind,src={repository},dst=/repo,readonly",
        lock["preparer_image"], "python3", "/repo/scripts/mgmt_airgap.py",
        "--bundle", "/bundle", "--manifest-sha256", manifest_sha256,
        "--rke2-version", lock["rke2_version"], "--services-json", services,
        "--rpm-metadata-check", "--rpm-signature-check", capture=True,
    )
    return json.loads(result.stdout)


def build(args: argparse.Namespace) -> dict:
    lock = checked_lock(args.lock.resolve(), args.rke2_version)
    output = args.output.resolve()
    cache = args.cache.resolve()
    source = args.source.resolve() if args.source else None
    require(output.is_absolute() and output.parent.is_dir(), "bundle parent directory must exist")
    require(not output.exists(), "bundle output already exists")
    cache.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=output.name + ".", dir=output.parent) as temporary:
        staging = Path(temporary)
        for entry in [*lock["rpm_signing_keys"], *lock["rpms"]]:
            acquired = acquire(entry, cache, source, args.offline)
            shutil.copyfile(acquired, staging / entry["file"])
        for entry in lock["release_artifacts"].values():
            if "compressed_file" not in entry:
                acquired = acquire(entry, cache, source, args.offline)
                shutil.copyfile(acquired, staging / entry["file"])
                continue
            destination = staging / entry["file"]
            materialize_release(
                entry, cache, source, destination, lock["preparer_image"], args.offline,
            )
        manifest = manifest_from_lock(lock)
        manifest_path = staging / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        manifest_sha256 = digest(manifest_path)
        require(manifest_sha256 == lock["approved_manifest_sha256"],
                "generated manifest differs from independent approval")
        validation = validate_in_pinned_container(
            staging, manifest_sha256, lock, args.repository.resolve(),
            checked_services(args.services_json),
        )
        os.replace(staging, output)
    return {
        "bundle": str(output),
        "manifest_sha256": manifest_sha256,
        "offline": args.offline,
        "rpms": len(lock["rpms"]),
        "validated_images": sum(len(value) for value in validation["images"].values()),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--rke2-version", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cache", required=True, type=Path)
    parser.add_argument("--source", type=Path,
                        help="optional trusted directory containing locked source bytes")
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--services-json", required=True)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    try:
        print(json.dumps(build(args), sort_keys=True))
    except (BuildError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        parser.exit(1, f"FAIL: {type(error).__name__}; bundle was not published\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
