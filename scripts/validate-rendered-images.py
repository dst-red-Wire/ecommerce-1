#!/usr/bin/env python3
"""Validate immutable images in final rendered Kubernetes workload PodSpecs."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml


IMMUTABLE_IMAGE = re.compile(
    r"^[a-z0-9.-]+(?::[0-9]+)?(?:/[a-z0-9._-]+)+@sha256:[0-9a-f]{64}$"
)


def pod_spec(document: dict) -> dict | None:
    kind = document.get("kind")
    spec = document.get("spec", {})
    if kind in {"Deployment", "StatefulSet", "DaemonSet"}:
        return spec.get("template", {}).get("spec")
    if kind == "Job":
        return spec.get("template", {}).get("spec")
    if kind == "CronJob":
        return spec.get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec")
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", nargs="?", type=Path)
    parser.add_argument("--environment", default="fixture")
    args = parser.parse_args()
    try:
        stream = args.manifest.read_text(encoding="utf-8") if args.manifest else sys.stdin.read()
        workload_count = 0
        image_count = 0
        errors: list[str] = []
        for document in yaml.safe_load_all(stream):
            if not isinstance(document, dict):
                continue
            spec = pod_spec(document)
            if spec is None:
                continue
            workload_count += 1
            identity = f"{document.get('kind')}/{document.get('metadata', {}).get('name', '<unnamed>')}"
            for collection in ("initContainers", "containers"):
                containers = spec.get(collection, [])
                if collection == "containers" and not containers:
                    errors.append(f"{identity} has no containers")
                for container in containers:
                    image_count += 1
                    image = container.get("image", "")
                    if not isinstance(image, str) or not IMMUTABLE_IMAGE.fullmatch(image):
                        errors.append(
                            f"{identity} {collection}/{container.get('name', '<unnamed>')} has non-immutable image: {image}"
                        )
        if errors:
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        if workload_count == 0:
            print(f"SKIPPED / NOT PROVEN: no deployable workload in {args.environment}")
            return 0
        print(
            f"validated {image_count} immutable rendered images across {workload_count} workloads in {args.environment}"
        )
        return 0
    except (OSError, yaml.YAMLError) as exc:
        print(f"rendered image validation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
