#!/usr/bin/env python3
"""Parse and evaluate S3 ListObjectVersions metadata without object payloads."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


def fail(message: str) -> None:
    raise SystemExit(f"S3 version history invalid: {message}")


def child_text(element: ET.Element, name: str, required: bool = True) -> str | None:
    child = next((item for item in element if item.tag.rsplit("}", 1)[-1] == name), None)
    if child is None or child.text is None:
        if required:
            fail(f"S3 XML element {name} is missing")
        return None
    return child.text


def parse_boolean(value: str | None, field: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    fail(f"{field} must be true or false")


def parse_xml(path: Path, exact_key: str) -> dict[str, Any]:
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError) as exc:
        fail(f"cannot parse ListObjectVersions XML: {exc}")
    if root.tag.rsplit("}", 1)[-1] != "ListVersionsResult":
        fail("unexpected S3 XML root")
    encoding = child_text(root, "EncodingType", required=False)

    def decode(value: str | None) -> str | None:
        if value is None:
            return None
        return urllib.parse.unquote(value) if encoding == "url" else value

    entries: list[dict[str, Any]] = []
    for element in root:
        kind = element.tag.rsplit("}", 1)[-1]
        if kind not in {"Version", "DeleteMarker"}:
            continue
        key = decode(child_text(element, "Key"))
        if key != exact_key:
            continue
        entries.append(
            {
                "key": key,
                "versionId": child_text(element, "VersionId"),
                "latest": parse_boolean(child_text(element, "IsLatest"), "IsLatest"),
                "deleteMarker": kind == "DeleteMarker",
                "lastModified": child_text(element, "LastModified"),
            }
        )
    return {
        "apiStatus": "OK",
        "isTruncated": parse_boolean(child_text(root, "IsTruncated"), "IsTruncated"),
        "nextKeyMarker": decode(child_text(root, "NextKeyMarker", required=False)),
        "nextVersionIdMarker": child_text(root, "NextVersionIdMarker", required=False),
        "entries": entries,
    }


def unknown_summary() -> dict[str, Any]:
    return {
        "verdict": "UNKNOWN",
        "apiComplete": False,
        "stateVersionCount": None,
        "deleteMarkerCount": None,
        "totalHistoryEntryCount": None,
        "entries": [],
    }


def evaluate(pages: list[Any], exact_key: str) -> dict[str, Any]:
    if not pages:
        return unknown_summary()
    entries: list[dict[str, Any]] = []
    seen: set[tuple[str, str, bool]] = set()
    for index, page in enumerate(pages):
        if not isinstance(page, dict) or page.get("apiStatus") != "OK":
            return unknown_summary()
        truncated = page.get("isTruncated")
        if not isinstance(truncated, bool) or not isinstance(page.get("entries"), list):
            return unknown_summary()
        if index < len(pages) - 1 and not truncated:
            return unknown_summary()
        if truncated and (
            not isinstance(page.get("nextKeyMarker"), str)
            or not page["nextKeyMarker"]
            or not isinstance(page.get("nextVersionIdMarker"), str)
            or not page["nextVersionIdMarker"]
        ):
            return unknown_summary()
        for entry in page["entries"]:
            if not isinstance(entry, dict) or entry.get("key") != exact_key:
                return unknown_summary()
            version_id = entry.get("versionId")
            last_modified = entry.get("lastModified")
            latest = entry.get("latest")
            delete_marker = entry.get("deleteMarker")
            if (
                not isinstance(version_id, str)
                or not version_id
                or not isinstance(last_modified, str)
                or not isinstance(latest, bool)
                or not isinstance(delete_marker, bool)
            ):
                return unknown_summary()
            try:
                dt.datetime.fromisoformat(last_modified.replace("Z", "+00:00"))
            except ValueError:
                return unknown_summary()
            identity = (exact_key, version_id, delete_marker)
            if identity in seen:
                return unknown_summary()
            seen.add(identity)
            entries.append(
                {
                    "key": exact_key,
                    "versionId": version_id,
                    "latest": latest,
                    "deleteMarker": delete_marker,
                    "lastModified": last_modified,
                }
            )
    if pages[-1].get("isTruncated"):
        return unknown_summary()
    entries.sort(key=lambda item: (item["lastModified"], item["versionId"]))
    state_versions = sum(not entry["deleteMarker"] for entry in entries)
    delete_markers = sum(entry["deleteMarker"] for entry in entries)
    return {
        "verdict": "ZERO_HISTORY" if not entries else "HISTORICAL_STATE_PRESENT",
        "apiComplete": True,
        "stateVersionCount": state_versions,
        "deleteMarkerCount": delete_markers,
        "totalHistoryEntryCount": len(entries),
        "entries": entries,
    }


parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(dest="command", required=True)
parse_parser = subparsers.add_parser("parse-xml")
parse_parser.add_argument("--input", type=Path, required=True)
parse_parser.add_argument("--key", required=True)
evaluate_parser = subparsers.add_parser("evaluate")
evaluate_parser.add_argument("--input", type=Path, required=True)
evaluate_parser.add_argument("--key", required=True)
args = parser.parse_args()

if args.command == "parse-xml":
    result = parse_xml(args.input, args.key)
else:
    try:
        pages = [json.loads(line) for line in args.input.read_text(encoding="utf-8").splitlines() if line]
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read normalized S3 pages: {exc}")
    result = evaluate(pages, args.key)
json.dump(result, sys.stdout, sort_keys=True, separators=(",", ":"))
sys.stdout.write("\n")
