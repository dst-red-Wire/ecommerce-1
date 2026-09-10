#!/usr/bin/env python3
"""Generate only the repeatable skeleton of a canonical Go service.

Business behavior, contracts, migrations and external integrations are never
invented. During M2, non-Product creation is deliberately blocked until the
Product golden service has finished establishing those conventions.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import subprocess
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from contract_paths import machine_contract_path  # noqa: E402 - script-local path is established above
from yaml_loader import load_yaml  # noqa: E402


def canonical_services(root: Path) -> list[str]:
    return list(load_yaml(root / "architecture.lock.yaml").get("business", {}).get("services", []))


def current_milestone(root: Path) -> str:
    return str(load_yaml(machine_contract_path(root, "public_api_contracts")).get("current_milestone", ""))


def validate_service(root: Path, service: str) -> None:
    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", service):
        raise ValueError("service must be a canonical lowercase kebab-case name")
    if service not in canonical_services(root):
        raise ValueError(f"service is not canonical: {service}")
    if (root / "services" / service).exists():
        raise ValueError(f"service directory already exists: services/{service}")


def build_files(service: str) -> dict[str, str]:
    module = f"github.com/dst-red-Wire/ecommerce-1/services/{service}"
    return {
        f"services/{service}/go.mod": f"module {module}\n\ngo 1.25.0\n",
        f"services/{service}/cmd/{service}-api/main.go": f'''package main\n\nimport (\n\t"log"\n\t"net/http"\n\t"os"\n\t"time"\n)\n\nfunc main() {{\n\taddr := os.Getenv("{service.upper().replace("-", "_")}_HTTP_ADDR")\n\tif addr == "" {{\n\t\taddr = ":8080"\n\t}}\n\tmux := http.NewServeMux()\n\tmux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {{ w.WriteHeader(http.StatusOK) }})\n\tmux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {{ w.WriteHeader(http.StatusOK) }})\n\tserver := &http.Server{{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}}\n\tlog.Printf("{service} API listening on %s", addr)\n\tif err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {{\n\t\tlog.Fatal(err)\n\t}}\n}}\n''',
        f"services/{service}/internal/domain/doc.go": f"// Package domain owns {service} business invariants.\npackage domain\n",
        f"services/{service}/internal/application/doc.go": f"// Package application owns {service} use cases.\npackage application\n",
        f"services/{service}/internal/transport/doc.go": f"// Package transport maps {service} protocol requests to application use cases.\npackage transport\n",
        f"services/{service}/internal/infrastructure/doc.go": f"// Package infrastructure contains {service} outbound adapters.\npackage infrastructure\n",
        f"services/{service}/README.md": f"""# {service} service\n\nGenerated structural baseline only. Add business behavior only after its canonical contract and owning invariants are reviewed.\n\nValidation:\n\n```text\npython3 scripts/repoctl.py service {service}\n```\n""",
    }


def blocked_by_golden_milestone(root: Path) -> bool:
    return current_milestone(root).startswith("M2-")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--service", required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    root = Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip())
    try:
        validate_service(root, args.service)
    except ValueError as exc:
        print(f"FAIL servicegen: {exc}", file=sys.stderr)
        return 2

    files = build_files(args.service)
    if args.dry_run:
        print(f"DRY-RUN servicegen: {args.service}")
        print(f"current milestone: {current_milestone(root)}")
        for path in files:
            print(path)
        if blocked_by_golden_milestone(root):
            print("BLOCKED for mutation until M2 golden Product conventions are complete")
        return 0

    if blocked_by_golden_milestone(root):
        print(
            "FAIL servicegen: non-Product service mutation is blocked during M2 golden Product qualification; use --dry-run only",
            file=sys.stderr,
        )
        return 3

    for relative, content in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    subprocess.run(["go", "work", "use", f"./services/{args.service}"], cwd=root, check=True)
    print(f"PASS servicegen: created structural baseline for {args.service}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
