#!/usr/bin/env python3
"""Materialize hash-locked Gitea, Harbor and Docker inputs for the local VM proof."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONTRACT = ROOT / "config/contracts/local-services-qualification.yaml"
DEFAULT_OUTPUT = ROOT / ".context/cache/local-services-vm"


class AssetError(RuntimeError):
    """Raised when an input cannot be proven against its lock."""


def sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise AssetError(f"regular non-symlink file required: {path}")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def download(url: str, target: Path, expected: str, *, offline: bool) -> None:
    if not re.fullmatch(r"https://[^\r\n]+", url):
        raise AssetError(f"HTTPS asset URL required: {url}")
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise AssetError(f"invalid expected SHA-256 for {target.name}")
    if target.exists() or target.is_symlink():
        if target.is_symlink() or not target.is_file() or sha256(target) != expected:
            raise AssetError(f"cached asset fails SHA-256 validation: {target}")
        return
    if offline:
        raise AssetError(f"offline asset is absent: {target.name}")
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": "ecommerce-qualification/1"})
    temporary: Path | None = None
    try:
        with urllib.request.urlopen(request, timeout=60) as response, tempfile.NamedTemporaryFile(
            dir=target.parent, prefix=f".{target.name}.", delete=False
        ) as output:
            temporary = Path(output.name)
            shutil.copyfileobj(response, output, length=1024 * 1024)
        if sha256(temporary) != expected:
            raise AssetError(f"downloaded asset SHA-256 mismatch: {target.name}")
        os.replace(temporary, target)
        target.chmod(0o600)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def verify_signing_key(path: Path, expected_fingerprint: str) -> None:
    result = subprocess.run(
        ["gpg", "--batch", "--show-keys", "--with-colons", str(path)],
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if result.returncode:
        raise AssetError("Docker RPM signing key cannot be inspected")
    fingerprints = {
        fields[9]
        for line in result.stdout.splitlines()
        if (fields := line.split(":"))[0] == "fpr" and len(fields) > 9
    }
    if expected_fingerprint not in fingerprints:
        raise AssetError(f"RPM signing key fingerprint mismatch: {path.name}")


def extract_harbor_image_archive(archive: Path, target: Path, expected: str) -> None:
    if target.exists() or target.is_symlink():
        if target.is_symlink() or not target.is_file() or sha256(target) != expected:
            raise AssetError("cached Harbor image archive fails SHA-256 validation")
        return
    with tarfile.open(archive, mode="r:gz") as outer:
        member = outer.getmember("harbor/harbor.v2.13.2.tar.gz")
        if not member.isfile():
            raise AssetError("Harbor image archive member is not a regular file")
        source = outer.extractfile(member)
        if source is None:
            raise AssetError("Harbor image archive member cannot be read")
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                dir=target.parent, prefix=f".{target.name}.", delete=False
            ) as output:
                temporary = Path(output.name)
                shutil.copyfileobj(source, output, length=1024 * 1024)
            if sha256(temporary) != expected:
                raise AssetError("nested Harbor image archive SHA-256 mismatch")
            os.replace(temporary, target)
            target.chmod(0o600)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)


def verify_harbor_images(path: Path, contract: dict) -> list[dict[str, str]]:
    with tarfile.open(path, mode="r:gz") as archive:
        stream = archive.extractfile("manifest.json")
        if stream is None:
            raise AssetError("Harbor offline image manifest is absent")
        manifest = json.load(stream)
    actual = {}
    for record in manifest:
        tags = record.get("RepoTags")
        config = record.get("Config")
        if not isinstance(tags, list) or len(tags) != 1 or not isinstance(config, str):
            raise AssetError("Harbor offline image manifest has an invalid entry")
        actual[tags[0]] = "sha256:" + config.removesuffix(".json")
    expected = {
        f"goharbor/{item['name']}:v{contract['version']}": item["offline_config_digest"]
        for item in contract["images"]
    }
    if actual != expected:
        raise AssetError("Harbor offline image identities differ from the contract")
    return [
        {
            "name": item["name"],
            "manifest_digest": item["manifest_digest"],
            "offline_config_digest": item["offline_config_digest"],
        }
        for item in contract["images"]
    ]


def materialize(contract_path: Path, output: Path, *, offline: bool) -> dict:
    contract = yaml.safe_load(contract_path.read_text(encoding="utf-8"))
    if contract.get("status") != "exact-local-runtime-qualification":
        raise AssetError("local service contract must be exact")
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    if output.is_symlink():
        raise AssetError("asset output must not be a symbolic link")
    assets: list[dict[str, str]] = []
    for owner in ("gitea", "harbor"):
        item = contract[owner]
        target = output / item["filename"]
        download(item["source"], target, item["sha256"], offline=offline)
        assets.append({"owner": owner, "file": target.name, "sha256": sha256(target)})
    docker = contract["harbor"]["container_runtime"]
    key = docker["signing_key"]
    key_path = output / key["filename"]
    download(key["url"], key_path, key["sha256"], offline=offline)
    verify_signing_key(key_path, key["fingerprint"])
    assets.append({"owner": "docker", "file": key_path.name, "sha256": sha256(key_path)})
    rpm_root = output / "docker-rpms"
    rpm_root.mkdir(mode=0o700, exist_ok=True)
    for rpm in docker["rpms"]:
        target = rpm_root / rpm["filename"]
        download(rpm["url"], target, rpm["sha256"], offline=offline)
        assets.append({"owner": "docker", "file": f"docker-rpms/{target.name}", "sha256": sha256(target)})
    rpm_lock_path = ROOT / contract["gitea"]["rpm_lock"]
    rpm_lock = json.loads(rpm_lock_path.read_text(encoding="utf-8"))
    if rpm_lock.get("dependency_closure") != "complete-minus-base-image":
        raise AssetError("Gitea RPM lock does not declare a complete extra closure")
    key_root = output / "rpm-keys"
    key_root.mkdir(mode=0o700, exist_ok=True)
    for signing_key in rpm_lock["rpm_signing_keys"]:
        target = key_root / signing_key["file"]
        download(signing_key["url"], target, signing_key["sha256"], offline=offline)
        verify_signing_key(target, signing_key["fingerprint"])
        assets.append({"owner": "gitea-rpm", "file": f"rpm-keys/{target.name}", "sha256": sha256(target)})
    gitea_rpm_root = output / "gitea-rpms"
    gitea_rpm_root.mkdir(mode=0o700, exist_ok=True)
    for rpm in rpm_lock["gitea"]["packages"]:
        target = gitea_rpm_root / rpm["file"]
        download(rpm["url"], target, rpm["sha256"], offline=offline)
        assets.append({"owner": "gitea-rpm", "file": f"gitea-rpms/{target.name}", "sha256": sha256(target)})
    nested = output / f"harbor-images-v{contract['harbor']['version']}.tar.gz"
    extract_harbor_image_archive(
        output / contract["harbor"]["filename"],
        nested,
        contract["harbor"]["nested_image_archive_sha256"],
    )
    images = verify_harbor_images(nested, contract["harbor"])
    assets.append({"owner": "harbor", "file": nested.name, "sha256": sha256(nested)})
    manifest = output / "SHA256SUMS"
    manifest.write_text(
        "".join(f"{item['sha256']}  {item['file']}\n" for item in sorted(assets, key=lambda value: value["file"])),
        encoding="utf-8",
    )
    evidence = {
        "schema": 1,
        "status": "PASS",
        "contract": str(contract_path.relative_to(ROOT)),
        "assets": assets,
        "harbor_images": images,
        "completed_at": datetime.now(UTC).isoformat(),
    }
    (output / "evidence.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    try:
        evidence = materialize(args.contract.resolve(), args.output.resolve(), offline=args.offline)
    except (AssetError, KeyError, OSError, subprocess.SubprocessError, tarfile.TarError, ValueError) as exc:
        print(f"FAIL local-service-assets: {exc}")
        return 1
    print(f"PASS local-service-assets files={len(evidence['assets'])} images={len(evidence['harbor_images'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
