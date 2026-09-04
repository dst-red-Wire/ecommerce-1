#!/usr/bin/env python3
"""Adversarial PromotionProof contract tests."""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "scripts/validate-promotion-proof.py"
NOW_EPOCH = 1_893_456_000
SERVICE = "catalog"
REPOSITORY = f"ghcr.io/dst-red-wire/ecommerce-1/{SERVICE}"
DIGEST = "sha256:" + "d" * 64
IMAGE_REFERENCE = f"{REPOSITORY}@{DIGEST}"
PIPELINE_UID = "12345678-1234-4234-8234-123456789abc"


def timestamp(epoch: int) -> str:
    return dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_json(path: Path, value: dict) -> bytes:
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    path.write_bytes(raw)
    return raw


def fixtures() -> tuple[dict, dict]:
    hashes = {
        "gitleaks-source": "1" * 64,
        "trivy-source": "2" * 64,
        "trivy-image": "3" * 64,
    }
    delivery = {
        "apiVersion": "ecommerce.dev/v1alpha1",
        "kind": "DeliveryEvidence",
        "status": {
            "phase": "NOT_PROVEN",
            "reason": "awaiting-signed-completed-pipelinerun-and-final-attestor",
        },
        "subject": {
            "gitRepository": "https://github.com/dst-red-Wire/ecommerce-1.git",
            "sourceCommit": "a" * 40,
            "sourceSnapshotSha256": "b" * 64,
            "serviceContext": SERVICE,
            "image": {"repository": REPOSITORY, "digest": DIGEST},
        },
        "materials": {
            "scans": [
                {"id": scan_id, "status": "PASSED_BY_TASK", "sha256": sha}
                for scan_id, sha in hashes.items()
            ],
            "sbom": {"format": "CycloneDX", "sha256": "4" * 64},
        },
        "attestationBoundary": {
            "requiredPipeline": "build-and-publish",
            "pipelineRunUid": PIPELINE_UID,
            "chainsPipelineRunProvenance": "NOT_PROVEN",
            "finalApproval": "NOT_PROVEN",
        },
    }
    proof = {
        "schemaVersion": "ecommerce.dev/promotion-proof/v1",
        "apiVersion": "ecommerce.dev/v1alpha1",
        "kind": "PromotionProof",
        "status": {"phase": "APPROVED", "verification": "CRYPTOGRAPHICALLY_VERIFIED"},
        "subject": {
            "gitRepository": "https://github.com/dst-red-Wire/ecommerce-1.git",
            "sourceCommit": "a" * 40,
            "sourceSnapshotSha256": "b" * 64,
            "service": SERVICE,
            "image": {"repository": REPOSITORY, "digest": DIGEST},
        },
        "promotion": {
            "sourceEnvironment": "build",
            "environment": "integration",
            "baseBranch": "main",
            "pullRequestRequired": True,
            "allowedPath": f"gitops/apps/{SERVICE}/overlays/integration/kustomization.yaml",
            "idempotenceKey": "sha256:"
            + hashlib.sha256(f"integration|{REPOSITORY}|{DIGEST}".encode()).hexdigest(),
        },
        "evidence": {
            "deliveryEvidenceSha256": "",
            "scans": [
                {"id": scan_id, "status": "PASS", "sha256": sha}
                for scan_id, sha in hashes.items()
            ],
            "sbom": {"format": "CycloneDX", "uri": f"oci://{IMAGE_REFERENCE}", "sha256": "4" * 64},
            "chains": {
                "pipeline": "build-and-publish",
                "pipelineRunUid": PIPELINE_UID,
                "status": "VERIFIED",
                "provenance": {"subject": IMAGE_REFERENCE, "bundleSha256": "5" * 64},
            },
        },
        "approval": {
            "gateId": "promotion-integration",
            "issuer": "ecommerce-promotion-attestor",
            "issuedAt": timestamp(NOW_EPOCH - 60),
            "expiresAt": timestamp(NOW_EPOCH + 3600),
            "expiresAtEpoch": NOW_EPOCH + 3600,
            "signatureMechanism": "cosign-key",
            "keyId": "sha256:" + "6" * 64,
        },
    }
    return proof, delivery


def validate(proof_path: Path, delivery_path: Path, expected_sha: str | None = None) -> bool:
    command = [
        sys.executable,
        str(VALIDATOR),
        "--proof",
        str(proof_path),
        "--delivery-evidence",
        str(delivery_path),
        "--target-environment",
        "integration",
        "--now-epoch",
        str(NOW_EPOCH),
    ]
    if expected_sha:
        command.extend(["--expected-proof-sha256", expected_sha])
    return subprocess.run(command, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def assert_runtime_task_is_frozen() -> None:
    task_path = ROOT / "gitops/infrastructure/tekton-ci/tasks/verify-promotion-proof.yaml"
    task = yaml.safe_load(task_path.read_text(encoding="utf-8"))
    steps = {step["name"]: step for step in task["spec"]["steps"]}
    cosign_args = " ".join(steps["verify-frozen-cryptographic-bundle"]["args"])
    semantics = steps["validate-frozen-semantics"]["script"]
    if "/var/run/frozen/payload/promotion-proof.json" not in cosign_args:
        raise AssertionError("Cosign does not verify the frozen PromotionProof")
    if "proof=\"$frozen/promotion-proof.json\"" not in semantics:
        raise AssertionError("semantic parser does not consume the frozen PromotionProof")
    if "$(workspaces.evidence.path)/promotion-proof.json" in semantics:
        raise AssertionError("semantic parser reopens the mutable evidence workspace")
    for step_name in (
        "verify-frozen-cryptographic-bundle",
        "validate-promotion-proof-schema",
        "validate-delivery-evidence-schema",
        "validate-frozen-semantics",
    ):
        mounts = {mount["name"]: mount for mount in steps[step_name].get("volumeMounts", [])}
        if not mounts.get("frozen-input", {}).get("readOnly"):
            raise AssertionError(f"{step_name} can write the frozen snapshot")


def main() -> int:
    assert_runtime_task_is_frozen()
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        proof_path = directory / "promotion-proof.json"
        delivery_path = directory / "delivery-evidence.json"
        base_proof, base_delivery = fixtures()
        delivery_raw = write_json(delivery_path, base_delivery)
        base_proof["evidence"]["deliveryEvidenceSha256"] = hashlib.sha256(delivery_raw).hexdigest()
        proof_raw = write_json(proof_path, base_proof)
        if not validate(proof_path, delivery_path, hashlib.sha256(proof_raw).hexdigest()):
            raise AssertionError("nominal PromotionProof fixture was rejected")

        cases = {
            "schema incorrect": lambda value: value.update({"unexpected": True}),
            "mauvais service": lambda value: value["subject"].update({"service": "orders"}),
            "mauvais repository": lambda value: value["subject"].update({"gitRepository": "https://example.invalid/repo.git"}),
            "mauvais commit": lambda value: value["subject"].update({"sourceCommit": "short"}),
            "mauvais digest": lambda value: value["subject"]["image"].update({"digest": "sha256:bad"}),
            "DeliveryEvidence hash faux": lambda value: value["evidence"].update({"deliveryEvidenceSha256": "0" * 64}),
            "mauvais pipelineRunUid": lambda value: value["evidence"]["chains"].update({"pipelineRunUid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}),
            "scan duplique": lambda value: value["evidence"]["scans"][1].update({"id": "gitleaks-source"}),
            "scan ID inconnu": lambda value: value["evidence"]["scans"][1].update({"id": "unknown"}),
            "issuer inconnu": lambda value: value["approval"].update({"issuer": "self-declared"}),
            "expiresAt divergent": lambda value: value["approval"].update({"expiresAtEpoch": NOW_EPOCH + 7200}),
            "preuve expiree": lambda value: value["approval"].update({"expiresAt": timestamp(NOW_EPOCH - 1), "expiresAtEpoch": NOW_EPOCH - 1}),
            "timestamp futur abusif": lambda value: value["approval"].update({"issuedAt": timestamp(NOW_EPOCH + 3600)}),
        }
        for label, mutate in cases.items():
            candidate = copy.deepcopy(base_proof)
            mutate(candidate)
            write_json(proof_path, candidate)
            if validate(proof_path, delivery_path):
                raise AssertionError(f"adversarial fixture was accepted: {label}")

        proof_path.write_text("{not-json", encoding="utf-8")
        if validate(proof_path, delivery_path):
            raise AssertionError("invalid JSON was accepted")

        write_json(proof_path, base_proof)
        signed_a_sha = hashlib.sha256(proof_path.read_bytes()).hexdigest()
        replacement = copy.deepcopy(base_proof)
        replacement["subject"]["sourceCommit"] = "c" * 40
        write_json(proof_path, replacement)
        if validate(proof_path, delivery_path, signed_a_sha):
            raise AssertionError("signed file A followed by content B was accepted")

        real_proof = directory / "real-proof.json"
        write_json(real_proof, base_proof)
        proof_path.unlink()
        os.symlink(real_proof, proof_path)
        if validate(proof_path, delivery_path):
            raise AssertionError("symlink PromotionProof was accepted")

    print("PromotionProof adversarial tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
