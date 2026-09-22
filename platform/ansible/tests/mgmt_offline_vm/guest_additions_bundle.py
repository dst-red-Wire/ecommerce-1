#!/usr/bin/env python3
"""Build and validate the locked Rocky prerequisites for VirtualBox Guest Additions."""
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
from pathlib import Path


class BundleError(ValueError):
    """A deterministic Guest Additions bundle validation failure."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BundleError(message)


def digest(path: Path) -> str:
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def write_json(path: Path, document: dict) -> None:
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def safe_name(value: object) -> str:
    require(
        isinstance(value, str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", value) is not None,
        "unsafe artifact filename",
    )
    return value


def checked_lock(document: dict) -> dict:
    require(isinstance(document, dict) and document.get("schema_version") == 1,
            "unsupported Guest Additions lock schema")
    require(document.get("virtualbox_version") == "7.2.18r175117",
            "VirtualBox host version differs from the approved pin")
    target = document.get("target")
    require(
        isinstance(target, dict)
        and target.get("architecture") == "x86_64"
        and target.get("os") == "rocky-9.8"
        and re.fullmatch(r"[0-9A-Za-z._+-]+\.x86_64", str(target.get("kernel_release"))) is not None,
        "unsupported Rocky Guest Additions target",
    )
    additions = document.get("guest_additions")
    require(
        isinstance(additions, dict)
        and additions.get("version") == "7.2.18"
        and additions.get("revision") == 175117,
        "Guest Additions version differs from the approved pin",
    )
    iso = additions.get("iso")
    require(
        isinstance(iso, dict)
        and iso.get("file") == "VBoxGuestAdditions_7.2.18.iso"
        and re.fullmatch(r"[0-9a-f]{64}", str(iso.get("sha256"))) is not None
        and iso.get("url")
        == "https://download.virtualbox.org/virtualbox/7.2.18/VBoxGuestAdditions_7.2.18.iso"
        and iso.get("windows_path")
        == r"C:\Program Files\Oracle\VirtualBox\VBoxGuestAdditions.iso"
        and iso.get("wsl_path")
        == "/mnt/c/Program Files/Oracle/VirtualBox/VBoxGuestAdditions.iso",
        "Guest Additions ISO identity is incomplete or unpinned",
    )
    repositories = document.get("rocky_repositories")
    require(isinstance(repositories, dict) and repositories,
            "at least one pinned Rocky repository is required")
    for name, url in repositories.items():
        require(
            name in {"BaseOS", "AppStream"}
            and url == f"https://dl.rockylinux.org/pub/rocky/9.8/{name}/x86_64/os/Packages",
            "Rocky repository must be the pinned 9.8 HTTPS source",
        )
    key = document.get("rpm_signing_key")
    require(
        isinstance(key, dict)
        and safe_name(key.get("file")).endswith(".asc")
        and re.fullmatch(r"[0-9A-F]{40}", str(key.get("fingerprint"))) is not None
        and re.fullmatch(r"[0-9a-f]{64}", str(key.get("sha256"))) is not None
        and str(key.get("url", "")).startswith("https://dl.rockylinux.org/"),
        "Rocky signing key is incomplete or unpinned",
    )
    required_packages = document.get("required_packages")
    require(
        isinstance(required_packages, list)
        and required_packages
        and len(required_packages) == len(set(required_packages))
        and all(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9+_.-]+", name)
                for name in required_packages),
        "required Guest Additions package set is invalid",
    )
    rpms = document.get("rpms")
    require(isinstance(rpms, list) and rpms, "locked RPM closure is required")
    names = set()
    for entry in rpms:
        require(isinstance(entry, dict), "invalid locked RPM entry")
        name = safe_name(entry.get("file"))
        require(name.endswith(".rpm") and name not in names, "duplicate or invalid RPM filename")
        require(entry.get("repository") in repositories, "RPM repository is not pinned")
        require(re.fullmatch(r"[0-9a-f]{64}", str(entry.get("sha256"))) is not None,
                "locked RPM SHA256 is required")
        names.add(name)
    for package in required_packages:
        require(any(name.startswith(package + "-") for name in names),
                f"required package {package} missing from locked closure")
    approved = document.get("approved_manifest_sha256")
    require(re.fullmatch(r"[0-9a-f]{64}", str(approved)) is not None,
            "approved Guest Additions manifest SHA256 is required")
    return document


def manifest_from_lock(lock: dict) -> dict:
    key = lock["rpm_signing_key"]
    fingerprint = key["fingerprint"]
    artifacts = [{
        "category": "rpm-signing-key",
        "file": key["file"],
        "fingerprint": fingerprint,
        "sha256": key["sha256"],
    }]
    artifacts.extend({
        "category": "rpm",
        "file": entry["file"],
        "sha256": entry["sha256"],
        "signer_fingerprint": fingerprint,
    } for entry in lock["rpms"])
    return {
        "architecture": lock["target"]["architecture"],
        "artifacts": sorted(artifacts, key=lambda entry: entry["file"]),
        "guest_additions_revision": lock["guest_additions"]["revision"],
        "guest_additions_version": lock["guest_additions"]["version"],
        "kernel_release": lock["target"]["kernel_release"],
        "os": lock["target"]["os"],
        "rpm_dependency_closure": "complete",
        "schema_version": 1,
    }


def regular(path: Path) -> None:
    require(path.is_file() and not path.is_symlink(), f"bundle member {path.name} is not a regular file")


def validate_bundle(
    directory: Path,
    lock: dict,
    *,
    rpm_metadata: bool = False,
    rpm_signatures: bool = False,
) -> dict:
    require(directory.is_absolute() and directory.is_dir() and not directory.is_symlink(),
            "bundle must be an absolute regular directory")
    expected_manifest = manifest_from_lock(lock)
    manifest_path = directory / "manifest.json"
    regular(manifest_path)
    require(digest(manifest_path) == lock["approved_manifest_sha256"],
            "manifest integrity differs from approval")
    require(json.loads(manifest_path.read_text(encoding="utf-8")) == expected_manifest,
            "manifest content differs from canonical lock")
    entries = expected_manifest["artifacts"]
    expected_names = {entry["file"] for entry in entries} | {"manifest.json"}
    actual_names = set()
    for path in directory.iterdir():
        regular(path)
        actual_names.add(path.name)
    require(actual_names == expected_names, "bundle member set differs from canonical lock")
    for entry in entries:
        path = directory / entry["file"]
        regular(path)
        require(digest(path) == entry["sha256"], f"artifact integrity failure: {path.name}")

    rpm_entries = [entry for entry in entries if entry["category"] == "rpm"]
    key_entry = next(entry for entry in entries if entry["category"] == "rpm-signing-key")
    if rpm_metadata:
        for entry in rpm_entries:
            metadata = subprocess.run(
                ["rpm", "-qp", "--qf", "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}.rpm",
                 str(directory / entry["file"])],
                check=True, capture_output=True, text=True, timeout=30,
            )
            require(metadata.stdout.strip() == entry["file"],
                    f"RPM metadata differs from approved filename: {entry['file']}")
    if rpm_signatures:
        rpmdb_parent = Path("/var/lib/rpm")
        isolated_parent = str(rpmdb_parent) if os.geteuid() == 0 and rpmdb_parent.is_dir() else None
        with tempfile.TemporaryDirectory(prefix="ecommerce-vbox-rpmdb-", dir=isolated_parent) as rpmdb:
            subprocess.run(["rpm", "--dbpath", rpmdb, "--initdb"], check=True,
                           capture_output=True, text=True, timeout=30)
            subprocess.run(
                ["rpm", "--dbpath", rpmdb, "--import", str(directory / key_entry["file"])],
                check=True, capture_output=True, text=True, timeout=30,
            )
            fingerprint = key_entry["fingerprint"].lower()
            for entry in rpm_entries:
                signature = subprocess.run(
                    ["rpm", "--dbpath", rpmdb, "--checksig", "--verbose",
                     str(directory / entry["file"])],
                    check=True, capture_output=True, text=True, timeout=30,
                )
                signer_ids = {value.lower() for value in re.findall(
                    r"(?im)^.*Signature.*key ID ([0-9a-f]{8,16}): OK$", signature.stdout
                )}
                require(signer_ids and all(fingerprint.endswith(key_id) for key_id in signer_ids),
                        f"RPM signature signer differs from approval: {entry['file']}")
    return {
        "guest_additions_version": lock["guest_additions"]["version"],
        "kernel_release": lock["target"]["kernel_release"],
        "manifest_sha256": lock["approved_manifest_sha256"],
        "rpm_count": len(rpm_entries),
    }


def artifact_url(lock: dict, entry: dict) -> str:
    base = lock["rocky_repositories"][entry["repository"]]
    return f"{base}/{entry['file'][0].lower()}/{entry['file']}"


def download(url: str, destination: Path, expected_sha256: str) -> None:
    partial = destination.with_name(destination.name + ".partial")
    partial.unlink(missing_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": "ecommerce-vbox-ga-bundle/1"})
    try:
        with urllib.request.urlopen(request, timeout=120) as response, partial.open("wb") as output:
            shutil.copyfileobj(response, output, length=1024 * 1024)
        require(digest(partial) == expected_sha256, "downloaded artifact digest mismatch")
        os.replace(partial, destination)
    finally:
        partial.unlink(missing_ok=True)


def acquire(url: str, name: str, expected_sha256: str, cache: Path, offline: bool) -> Path:
    destination = cache / safe_name(name)
    if destination.is_file():
        require(not destination.is_symlink() and digest(destination) == expected_sha256,
                "cached artifact integrity failure")
        return destination
    require(not offline, "locked Guest Additions prerequisite absent from offline cache")
    download(url, destination, expected_sha256)
    return destination


def build_bundle(lock: dict, output: Path, cache: Path, offline: bool = False) -> dict:
    output = output.resolve()
    cache = cache.resolve()
    require(output.is_absolute() and output.parent.is_dir(), "bundle parent directory must exist")
    cache.mkdir(parents=True, exist_ok=True)
    if output.exists():
        return validate_bundle(output, lock)
    with tempfile.TemporaryDirectory(prefix=output.name + ".", dir=output.parent) as temporary:
        staging = Path(temporary)
        key = lock["rpm_signing_key"]
        shutil.copyfile(
            acquire(key["url"], key["file"], key["sha256"], cache, offline),
            staging / key["file"],
        )
        for entry in lock["rpms"]:
            shutil.copyfile(
                acquire(artifact_url(lock, entry), entry["file"], entry["sha256"], cache, offline),
                staging / entry["file"],
            )
        write_json(staging / "manifest.json", manifest_from_lock(lock))
        result = validate_bundle(staging, lock)
        os.replace(staging, output)
        return result


def stream_bundle(lock: dict, bundle: Path, ssh_config: Path, host: str, destination: str) -> dict:
    validation = validate_bundle(bundle.resolve(), lock)
    require(ssh_config.is_absolute() and ssh_config.is_file() and not ssh_config.is_symlink(),
            "SSH configuration must be an absolute regular file")
    require(re.fullmatch(r"ecommerce-mgmt-test-[a-z0-9-]+", host) is not None,
            "unsafe Guest Additions destination host")
    require(
        re.fullmatch(r"/var/lib/ecommerce/guest-additions/[0-9a-f]{64}", destination) is not None
        and destination.endswith(lock["approved_manifest_sha256"]),
        "unsafe Guest Additions destination path",
    )
    names = sorted(path.name for path in bundle.iterdir())
    producer = subprocess.Popen(
        ["tar", "--format=ustar", "--owner=0", "--group=0", "--numeric-owner",
         "--mode=u+rwX,go-rwx", "--mtime=@0", "-C", str(bundle), "-cf", "-", *names],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    require(producer.stdout is not None and producer.stderr is not None,
            "failed to open bounded tar stream")
    consumer = subprocess.Popen(
        ["ssh", "-F", str(ssh_config), host, "sudo", "-n", "tar",
         "--extract", "--file", "-", "--directory", destination,
         "--no-same-owner", "--no-same-permissions", "--mode=u+rwX,go-rwx"],
        stdin=producer.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    producer.stdout.close()
    try:
        _, consumer_stderr = consumer.communicate(timeout=300)
        producer_stderr = producer.stderr.read()
        producer_rc = producer.wait(timeout=30)
    except subprocess.TimeoutExpired:
        producer.kill()
        consumer.kill()
        producer.wait()
        consumer.wait()
        raise BundleError("bounded Guest Additions stream timed out")
    require(producer_rc == 0 and consumer.returncode == 0,
            "Guest Additions stream failed before remote validation")
    require(not producer_stderr and not consumer_stderr,
            "Guest Additions stream emitted unexpected diagnostics")
    return validation


def load_lock(path: Path) -> dict:
    return checked_lock(json.loads(path.read_text(encoding="utf-8")))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("build", "validate", "manifest-digest", "stream"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--lock", required=True, type=Path)
        if command in {"build", "validate", "stream"}:
            subparser.add_argument("--bundle", required=True, type=Path)
        if command == "build":
            subparser.add_argument("--cache", required=True, type=Path)
            subparser.add_argument("--offline", action="store_true")
        if command == "validate":
            subparser.add_argument("--rpm-metadata-check", action="store_true")
            subparser.add_argument("--rpm-signature-check", action="store_true")
        if command == "stream":
            subparser.add_argument("--ssh-config", required=True, type=Path)
            subparser.add_argument("--host", required=True)
            subparser.add_argument("--destination", required=True)
    args = parser.parse_args()
    try:
        raw_lock = json.loads(args.lock.read_text(encoding="utf-8"))
        if args.command == "manifest-digest":
            with tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "manifest.json"
                write_json(path, manifest_from_lock(raw_lock))
                print(digest(path))
                return 0
        lock = checked_lock(raw_lock)
        if args.command == "build":
            result = build_bundle(lock, args.bundle, args.cache, args.offline)
        elif args.command == "stream":
            result = stream_bundle(
                lock, args.bundle, args.ssh_config, args.host, args.destination,
            )
        else:
            result = validate_bundle(
                args.bundle.resolve(), lock,
                rpm_metadata=args.rpm_metadata_check,
                rpm_signatures=args.rpm_signature_check,
            )
    except (BundleError, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        parser.exit(1, "FAIL: Guest Additions bundle or lock invalid; no unapproved bytes accepted\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
