#!/usr/bin/env python3
"""Materialize an ignored Nx visualization workspace from canonical contracts."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess

ROOT = Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip())
OUT = ROOT / ".context/nx-workspace"


def yaml_json(path: str) -> dict:
    raw = subprocess.check_output(["yq", "-o=json", ".", path], cwd=ROOT, text=True)
    return json.loads(raw)


def name_service(service: str) -> str:
    return f"service-{service}"


def main() -> int:
    ownership = yaml_json("config/contracts/service-ownership.yaml")
    deps = yaml_json("config/contracts/dependency-map.yaml")
    public = yaml_json("config/contracts/public-api-contracts.yaml")
    services = sorted(ownership["services"])
    frontends = ["storefront", "admin"]

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "package.json").write_text(
        json.dumps({"name": "ecommerce-1-derived-nx-graph", "private": True}, indent=2) + "\n"
    )
    (OUT / "nx.json").write_text(json.dumps({"defaultBase": "main", "plugins": []}, indent=2) + "\n")

    for service in services:
        project = OUT / "projects" / name_service(service)
        project.mkdir(parents=True, exist_ok=True)
        internal = [d for d in deps["services"].get(service, {}).get("sync", []) if d in services]
        spec = {
            "name": name_service(service),
            "projectType": "application",
            "root": f"projects/{name_service(service)}",
            "sourceRoot": f"projects/{name_service(service)}",
            "implicitDependencies": [name_service(dep) for dep in internal],
            "targets": {},
            "tags": ["type:go-service", f"domain:{service}"],
        }
        (project / "project.json").write_text(json.dumps(spec, indent=2) + "\n")

    contracts = public.get("contracts", {})
    for frontend in frontends:
        dependencies = [name_service(svc) for svc, spec in contracts.items() if frontend in spec.get("audiences", [])]
        project = OUT / "projects" / f"frontend-{frontend}"
        project.mkdir(parents=True, exist_ok=True)
        spec = {
            "name": f"frontend-{frontend}",
            "projectType": "application",
            "root": f"projects/frontend-{frontend}",
            "sourceRoot": f"projects/frontend-{frontend}",
            "implicitDependencies": sorted(dependencies),
            "targets": {},
            "tags": ["type:frontend"],
        }
        (project / "project.json").write_text(json.dumps(spec, indent=2) + "\n")

    print(OUT.relative_to(ROOT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
