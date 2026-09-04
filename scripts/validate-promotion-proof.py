#!/usr/bin/env python3
"""Validate frozen PromotionProof and DeliveryEvidence bytes fail-closed."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


EXPECTED_REPOSITORY = "https://github.com/dst-red-Wire/ecommerce-1.git"
EXPECTED_SCANS = {"gitleaks-source", "trivy-source", "trivy-image"}
PROMOTION_EDGES = {
    "integration": "build",
    "preproduction": "integration",
    "production": "preproduction",
}
MAX_VALIDITY_SECONDS = 24 * 60 * 60
MAX_FUTURE_SKEW_SECONDS = 5 * 60


class ValidationError(Exception):
    pass


def read_regular_file_once(path: Path) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValidationError(f"cannot open regular non-symlink file {path}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValidationError(f"not a regular file: {path}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ValidationError(f"file changed while being read: {path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def load_json_bytes(raw: bytes, label: str) -> dict:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"invalid JSON in {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValidationError(f"{label} must be a JSON object")
    return value


def load_schema(path: Path) -> dict:
    return load_json_bytes(read_regular_file_once(path), str(path))


def apply_schema(instance: dict, schema: dict, label: str) -> None:
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(instance), key=lambda item: list(item.absolute_path))
    if errors:
        first = errors[0]
        location = "/".join(str(part) for part in first.absolute_path) or "<root>"
        raise ValidationError(f"{label} schema violation at {location}: {first.message}")


def parse_timestamp(value: str, label: str) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError(f"invalid {label}: {value}") from exc
    if parsed.tzinfo is None:
        raise ValidationError(f"{label} must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def indexed_scans(scans: list[dict], label: str) -> dict[str, dict]:
    result: dict[str, dict] = {}
    for scan in scans:
        scan_id = scan["id"]
        if scan_id in result:
            raise ValidationError(f"duplicate {label} scan id: {scan_id}")
        result[scan_id] = scan
    if set(result) != EXPECTED_SCANS:
        raise ValidationError(f"unexpected {label} scan set: {sorted(result)}")
    return result


def validate_semantics(proof: dict, delivery: dict, delivery_sha: str, target: str, now: dt.datetime) -> None:
    subject = proof["subject"]
    promotion = proof["promotion"]
    evidence = proof["evidence"]
    approval = proof["approval"]
    delivery_subject = delivery["subject"]

    if target not in PROMOTION_EDGES or promotion["environment"] != target:
        raise ValidationError("target environment does not match the signed promotion")
    if promotion["sourceEnvironment"] != PROMOTION_EDGES[target]:
        raise ValidationError("invalid source/target promotion edge")
    if approval["gateId"] != f"promotion-{target}":
        raise ValidationError("approval gate does not match target environment")
    if evidence["deliveryEvidenceSha256"] != delivery_sha:
        raise ValidationError("DeliveryEvidence SHA-256 mismatch")

    service = subject["service"]
    image_repository = subject["image"]["repository"]
    image_digest = subject["image"]["digest"]
    image_reference = f"{image_repository}@{image_digest}"
    if image_repository != f"ghcr.io/dst-red-wire/ecommerce-1/{service}":
        raise ValidationError("service/image repository mapping mismatch")
    expected_path = f"gitops/apps/{service}/overlays/{target}/kustomization.yaml"
    if promotion["allowedPath"] != expected_path:
        raise ValidationError("allowed path does not match service/environment")
    expected_key = "sha256:" + hashlib.sha256(
        f"{target}|{image_repository}|{image_digest}".encode()
    ).hexdigest()
    if promotion["idempotenceKey"] != expected_key:
        raise ValidationError("invalid idempotence key")

    bindings = (
        (subject["gitRepository"], delivery_subject["gitRepository"], "repository"),
        (subject["sourceCommit"], delivery_subject["sourceCommit"], "source commit"),
        (
            subject["sourceSnapshotSha256"],
            delivery_subject["sourceSnapshotSha256"],
            "source snapshot",
        ),
        (service, delivery_subject["serviceContext"], "service"),
        (image_repository, delivery_subject["image"]["repository"], "image repository"),
        (image_digest, delivery_subject["image"]["digest"], "image digest"),
        (
            evidence["chains"]["pipelineRunUid"],
            delivery["attestationBoundary"]["pipelineRunUid"],
            "PipelineRun UID",
        ),
    )
    for signed, delivered, label in bindings:
        if signed != delivered:
            raise ValidationError(f"PromotionProof/DeliveryEvidence {label} mismatch")

    if evidence["chains"]["provenance"]["subject"] != image_reference:
        raise ValidationError("provenance subject does not match promoted image")
    if not evidence["sbom"]["uri"].startswith(f"oci://{image_reference}"):
        raise ValidationError("SBOM reference does not match promoted image")

    proof_scans = indexed_scans(evidence["scans"], "PromotionProof")
    delivery_scans = indexed_scans(delivery["materials"]["scans"], "DeliveryEvidence")
    for scan_id in EXPECTED_SCANS:
        if proof_scans[scan_id]["sha256"] != delivery_scans[scan_id]["sha256"]:
            raise ValidationError(f"scan hash mismatch for {scan_id}")
    if evidence["sbom"]["sha256"] != delivery["materials"]["sbom"]["sha256"]:
        raise ValidationError("SBOM hash mismatch")

    issued = parse_timestamp(approval["issuedAt"], "issuedAt")
    expires = parse_timestamp(approval["expiresAt"], "expiresAt")
    if int(expires.timestamp()) != approval["expiresAtEpoch"]:
        raise ValidationError("expiresAt and expiresAtEpoch diverge")
    if issued > now + dt.timedelta(seconds=MAX_FUTURE_SKEW_SECONDS):
        raise ValidationError("issuedAt is too far in the future")
    if expires <= now:
        raise ValidationError("PromotionProof is expired")
    if expires <= issued:
        raise ValidationError("expiresAt must be after issuedAt")
    if (expires - issued).total_seconds() > MAX_VALIDITY_SECONDS:
        raise ValidationError("PromotionProof validity window exceeds 24 hours")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--proof", type=Path, required=True)
    parser.add_argument("--delivery-evidence", type=Path, required=True)
    parser.add_argument("--target-environment", required=True)
    parser.add_argument(
        "--proof-schema",
        type=Path,
        default=Path("contracts/supply-chain/promotion-proof.schema.json"),
    )
    parser.add_argument(
        "--delivery-schema",
        type=Path,
        default=Path("contracts/supply-chain/delivery-evidence.schema.json"),
    )
    parser.add_argument("--now-epoch", type=int)
    parser.add_argument("--expected-proof-sha256")
    args = parser.parse_args()

    try:
        proof_raw = read_regular_file_once(args.proof)
        delivery_raw = read_regular_file_once(args.delivery_evidence)
        proof_sha = hashlib.sha256(proof_raw).hexdigest()
        if args.expected_proof_sha256 and proof_sha != args.expected_proof_sha256:
            raise ValidationError("verified PromotionProof bytes were replaced")
        proof = load_json_bytes(proof_raw, "PromotionProof")
        delivery = load_json_bytes(delivery_raw, "DeliveryEvidence")
        apply_schema(proof, load_schema(args.proof_schema), "PromotionProof")
        apply_schema(delivery, load_schema(args.delivery_schema), "DeliveryEvidence")
        now = dt.datetime.fromtimestamp(
            args.now_epoch if args.now_epoch is not None else dt.datetime.now().timestamp(),
            tz=dt.timezone.utc,
        )
        validate_semantics(
            proof,
            delivery,
            hashlib.sha256(delivery_raw).hexdigest(),
            args.target_environment,
            now,
        )
        print(proof_sha)
        return 0
    except (ValidationError, KeyError, TypeError) as exc:
        print(f"PromotionProof rejected: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
