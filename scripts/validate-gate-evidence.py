#!/usr/bin/env python3
"""Apply GateEvidence schema, issuer mapping, artifact binding, and replay rules."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import stat
import sys
from pathlib import Path, PurePosixPath

from jsonschema import Draft202012Validator, FormatChecker


class GateError(Exception):
    pass


def read_once(path: Path, *, reject_symlink: bool = True) -> bytes:
    flags = os.O_RDONLY
    if reject_symlink and hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise GateError(f"cannot open trusted regular file {path}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise GateError(f"not a regular file: {path}")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise GateError(f"file changed during validation: {path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def parse_json(path: Path) -> dict:
    try:
        value = json.loads(read_once(path))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GateError(f"invalid JSON: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise GateError(f"JSON object required: {path}")
    return value


def parse_time(value: str, label: str) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GateError(f"invalid {label}") from exc
    if parsed.tzinfo is None:
        raise GateError(f"{label} lacks timezone")
    return parsed.astimezone(dt.timezone.utc)


def safe_artifact(root: Path, relative: str) -> Path:
    posix = PurePosixPath(relative)
    if posix.is_absolute() or ".." in posix.parts:
        raise GateError("evidence artifact path traversal is forbidden")
    resolved_root = root.resolve()
    resolved = (resolved_root / Path(*posix.parts)).resolve()
    if resolved == resolved_root or resolved_root not in resolved.parents:
        raise GateError("evidence artifact escapes its configured root")
    return resolved


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--expected-gate", required=True)
    parser.add_argument("--artifact-root", type=Path, default=Path.cwd())
    parser.add_argument("--trust-dir", type=Path)
    parser.add_argument("--now-epoch", type=int)
    parser.add_argument("--schema", type=Path, default=Path("contracts/supply-chain/gate-evidence.schema.json"))
    parser.add_argument("--trust-policy", type=Path, default=Path("contracts/supply-chain/gate-trust-policy.json"))
    args = parser.parse_args()
    try:
        evidence = parse_json(args.evidence)
        schema = parse_json(args.schema)
        policy = parse_json(args.trust_policy)
        errors = sorted(
            Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(evidence),
            key=lambda item: list(item.absolute_path),
        )
        if errors:
            location = "/".join(str(part) for part in errors[0].absolute_path) or "<root>"
            raise GateError(f"JSON Schema violation at {location}: {errors[0].message}")
        if evidence["gateId"] != args.expected_gate:
            raise GateError("gateId does not match the expected catalog gate")
        authority_name = policy["gateAuthorities"].get(args.expected_gate)
        if not authority_name:
            raise GateError("gate has no closed authority mapping")
        authority = policy["authorities"][authority_name]
        if evidence["issuer"] != {"id": authority["issuerId"], "type": authority["issuerType"]}:
            raise GateError("issuer is not the authority mapped to this gate")
        if evidence["verification"]["mechanism"] not in authority["mechanisms"]:
            raise GateError("signature mechanism is not approved for this authority")
        if evidence["environment"] != "production":
            raise GateError("production GateEvidence must target production")

        artifact = safe_artifact(args.artifact_root, evidence["evidence"]["artifact"])
        artifact_sha = hashlib.sha256(read_once(artifact)).hexdigest()
        if artifact_sha != evidence["evidence"]["sha256"]:
            raise GateError("evidence artifact SHA-256 mismatch")

        expected_idempotence = "sha256:" + hashlib.sha256(
            "|".join(
                [
                    evidence["gateId"],
                    evidence["repository"],
                    evidence["sourceCommit"],
                    evidence["imageDigest"],
                    evidence["environment"],
                    artifact_sha,
                ]
            ).encode()
        ).hexdigest()
        if evidence["idempotenceKey"] != expected_idempotence:
            raise GateError("invalid GateEvidence idempotence key")

        now = dt.datetime.fromtimestamp(
            args.now_epoch if args.now_epoch is not None else dt.datetime.now().timestamp(),
            tz=dt.timezone.utc,
        )
        issued = parse_time(evidence["issuedAt"], "issuedAt")
        expires = parse_time(evidence["expiresAt"], "expiresAt")
        if int(expires.timestamp()) != evidence["expiresAtEpoch"]:
            raise GateError("expiresAt and expiresAtEpoch diverge")
        if issued > now + dt.timedelta(seconds=policy["maximumFutureSkewSeconds"]):
            raise GateError("GateEvidence issuedAt is too far in the future")
        if expires <= now or expires <= issued:
            raise GateError("GateEvidence is expired or has an invalid time interval")
        if (expires - issued).total_seconds() > policy["maximumValiditySeconds"]:
            raise GateError("GateEvidence validity window is too large")

        if args.trust_dir:
            key_path = safe_artifact(args.trust_dir, authority["keyFile"])
            key_id = "sha256:" + hashlib.sha256(read_once(key_path)).hexdigest()
            if evidence["verification"]["keyId"] != key_id:
                raise GateError("keyId does not identify the mapped authority public key")
        print(evidence["idempotenceKey"])
        return 0
    except (GateError, OSError, KeyError, TypeError, ValueError) as exc:
        print(f"GateEvidence rejected: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
