#!/usr/bin/env python3
"""Validate a preproduction lifecycle authorization without running Terraform."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("approval", type=Path)
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--backend-id", required=True)
    parser.add_argument("--lineage", required=True)
    parser.add_argument("--serial", required=True, type=int)
    parser.add_argument(
        "--schema",
        type=Path,
        default=Path("infrastructure/hetzner/preproduction/lifecycle.schema.json"),
    )
    args = parser.parse_args()
    try:
        approval = json.loads(args.approval.read_text(encoding="utf-8"))
        schema = json.loads(args.schema.read_text(encoding="utf-8"))
        errors = list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(approval))
        if errors:
            raise ValueError(errors[0].message)
        state = approval["terraformState"]
        bindings = [
            (approval["campaignId"], args.campaign_id, "campaign ID"),
            (approval["owner"], args.owner, "owner"),
            (state["backendId"], args.backend_id, "backend ID"),
            (state["expectedLineage"], args.lineage, "state lineage"),
            (state["expectedSerial"], args.serial, "state serial"),
        ]
        for actual, expected, label in bindings:
            if actual != expected:
                raise ValueError(f"{label} differs from the locked expectation")
        expires = dt.datetime.fromisoformat(approval["expiresAt"].replace("Z", "+00:00"))
        if expires <= dt.datetime.now(dt.timezone.utc):
            raise ValueError("campaign approval is expired")
        expected_confirmation = (
            f"DESTROY preproduction campaign {args.campaign_id} "
            f"at lineage {args.lineage} serial {args.serial}"
        )
        if approval["destruction"]["confirmation"] != expected_confirmation:
            raise ValueError("explicit destroy confirmation does not bind the locked state")
        print("preproduction lifecycle authorization is structurally bound; no Terraform command was run")
        return 0
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"preproduction lifecycle authorization rejected: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
