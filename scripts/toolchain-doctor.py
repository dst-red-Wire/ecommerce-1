#!/usr/bin/env python3
"""Compare the workstation with the repository-owned toolchain lock.

The command is read-only. It never installs, upgrades or configures software.
Its JSON mode is stable enough for CI evidence and future drift reporting.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import shutil
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
LOCK = ROOT / "config/toolchain/toolchain.lock.json"
VERSION = re.compile(r"(?<!\d)(\d+\.\d+(?:\.\d+)?)(?!\d)")


def probe(tool: dict[str, object]) -> dict[str, object]:
    command = str(tool["command"])
    executable = shutil.which(command)
    expected = tool.get("version")
    result: dict[str, object] = {
        "id": tool["id"],
        "command": command,
        "expected": expected,
        "required": tool["required"],
        "scope": tool["scope"],
        "status": "MISSING",
        "observed": None,
    }
    if executable is None:
        return result

    version_args = [str(argument) for argument in tool.get("version_args", ["--version"])]
    completed = subprocess.run(
        [executable, *version_args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=15,
    )
    match = VERSION.search(completed.stdout)
    observed = match.group(1) if match else None
    result["observed"] = observed
    if completed.returncode != 0 or observed is None:
        result["status"] = "UNREADABLE"
    elif expected is None or observed == expected:
        result["status"] = "PASS"
    else:
        result["status"] = "MISMATCH"
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scope", choices=("ci", "full"), default="full")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()

    document = json.loads(LOCK.read_text(encoding="utf-8"))
    selected = [
        tool for tool in document["tools"]
        if args.scope == "full" or tool["scope"] == "ci"
    ]
    results = [probe(tool) for tool in selected]
    failures = [
        item for item in results
        if item["required"] and item["status"] != "PASS"
    ]
    report = {
        "schema_version": 1,
        "lock_status": document["status"],
        "scope": args.scope,
        "results": results,
        "summary": {
            "pass": sum(item["status"] == "PASS" for item in results),
            "failure": len(failures),
            "total": len(results),
        },
    }

    if args.format == "json":
        json.dump(report, sys.stdout, sort_keys=True, indent=2)
        sys.stdout.write("\n")
    else:
        for item in results:
            print(
                f"{item['status']:<10} {item['id']:<20} "
                f"expected={item['expected'] or 'present'} "
                f"observed={item['observed'] or '-'}"
            )
        print(
            "toolchain doctor: "
            f"{report['summary']['pass']} PASS, "
            f"{report['summary']['failure']} failure(s), "
            f"{report['summary']['total']} checked"
        )
    return 1 if args.strict and failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
