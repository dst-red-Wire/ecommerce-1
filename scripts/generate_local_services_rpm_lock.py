#!/usr/bin/env python3
"""Generate the minimal extra Rocky RPM closure needed by local service VMs."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tempfile
import uuid
from pathlib import Path

import generate_mgmt_rpm_lock as rpm_source
from generate_packer_rpm_lock import _collect

ROOT = Path(__file__).resolve().parents[1]
BASE_LOCK = ROOT / "config/artifacts/rocky-10.2-base-packages.lock.json"
ROOTS = ["git"]


def generate(destination: Path) -> dict:
    base = json.loads(BASE_LOCK.read_text(encoding="utf-8"))
    installed = {item["file"] for item in base["profiles"]["base"]["packages"]}
    container = "ecommerce-local-services-lock-" + uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix="ecommerce-local-services-rpms-") as directory:
        output = Path(directory)
        rpm_source.run(
            "docker",
            "create",
            "--name",
            container,
            "--mount",
            f"type=bind,src={output},dst=/rpms",
            rpm_source.ROCKY_IMAGE,
            "sleep",
            "infinity",
        )
        try:
            rpm_source.run("docker", "start", container)
            rpm_source.run("docker", "exec", container, "dnf", "-qy", "install", "dnf-plugins-core")
            rpm_source.run(
                "docker",
                "exec",
                container,
                "dnf",
                *rpm_source.ROCKY_REPO_OPTIONS,
                "-qy",
                "download",
                "--resolve",
                "--alldeps",
                "--destdir",
                "/rpms",
                *ROOTS,
            )
            packages = [item for item in _collect(container, output, "/rpms") if item["file"] not in installed]
        finally:
            subprocess.run(
                ["docker", "rm", "--force", container],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
    body = {"roots": ROOTS, "packages": packages}
    body["approved_manifest_sha256"] = hashlib.sha256(
        (json.dumps(body, indent=2, sort_keys=True) + "\n").encode()
    ).hexdigest()
    document = {
        "schema_version": 1,
        "image": "rocky-10.2-base",
        "source_contract": "config/contracts/local-services-qualification.yaml",
        "base_lock": "config/artifacts/rocky-10.2-base-packages.lock.json",
        "dependency_closure": "complete-minus-base-image",
        "rpm_signing_keys": [rpm_source.ROCKY_KEY],
        "gitea": body,
    }
    document["approved_manifest_sha256"] = hashlib.sha256(
        (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
    ).hexdigest()
    destination.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"packages": len(packages), "manifest_sha256": document["approved_manifest_sha256"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(generate(args.output.resolve()), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
