#!/usr/bin/env python3
"""Fast repository control plane for ecommerce-1.

This program replaces stateless shell wrappers. It performs no cloud deployment and
never becomes a CI authority: Tekton remains authoritative. Stateful workstation and
toolchain reconciliation belongs to platform/ansible/developer.yml.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))


def _missing_repository_delivery(*_args, **_kwargs):
    raise RuntimeError(
        "repository delivery helper unavailable: scripts/repository_delivery.py is required "
        "for delivery/evidence/Tekton commands"
    )


try:
    from repository_delivery import (
        bundle_deliver as isolated_bundle_deliver,
        compare_evidence,
        evidence_metrics,
        fetch_evidence,
        publish_evidence,
        publish_remote_status,
        REMOTE_STATUS_CONTEXT,
    )
except ModuleNotFoundError as exc:
    if exc.name != "repository_delivery":
        raise
    isolated_bundle_deliver = _missing_repository_delivery
    compare_evidence = _missing_repository_delivery
    evidence_metrics = _missing_repository_delivery
    fetch_evidence = _missing_repository_delivery
    publish_evidence = _missing_repository_delivery
    publish_remote_status = _missing_repository_delivery
    REMOTE_STATUS_CONTEXT = "tekton/ecommerce-affected"

ROOT = Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip())
os.environ["PATH"] = f"{Path.home() / '.local/bin'}:{os.environ.get('PATH', '')}"
PROJECT_COLLECTIONS = ROOT / ".ansible" / "collections"
# Every Ansible subprocess resolves collections from the project-owned path only.
# This prevents a user or distro installation from silently changing execution.
os.environ["ANSIBLE_COLLECTIONS_PATH"] = str(PROJECT_COLLECTIONS)
os.environ["ANSIBLE_CONFIG"] = str(ROOT / "platform" / "ansible" / "ansible.cfg")
CONTEXT = ROOT / ".context"


class MissingRunnerPrerequisite(RuntimeError):
    """A runner-owned primitive is absent; repository code must not install it."""


def fail(message: str, code: int = 2) -> int:
    print(f"FAIL {message}", file=sys.stderr)
    return code


def require(name: str) -> str:
    path = shutil.which(name)
    if not path:
        if name == "ruby":
            raise MissingRunnerPrerequisite(f"runner prerequisite missing: {name}")
        raise RuntimeError(f"required command missing: {name}")
    return path


def run(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    check: bool = True,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    p = subprocess.run(
        cmd,
        cwd=cwd or ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )
    if check and p.returncode:
        detail = (p.stderr or p.stdout or "").strip()
        raise RuntimeError(detail or f"command failed ({p.returncode}): {' '.join(cmd)}")
    return p


def output(cmd: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> str:
    return run(cmd, cwd=cwd, env=env, capture=True).stdout


def git(*args: str, check: bool = True) -> str:
    p = run(["git", *args], check=check, capture=True)
    return p.stdout


def ruby_yaml(path: str) -> dict:
    require("ruby")
    script = "require 'yaml'; require 'json'; d=YAML.safe_load(File.read(ARGV[0]), aliases: false) || {}; print JSON.generate(d)"
    return json.loads(output(["ruby", "-e", script, path]))


def pinned_versions() -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in (ROOT / "config" / "toolchain" / "versions.env").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def required_ansible_collections(requirements: Path | None = None) -> dict[str, str]:
    """Read the canonical Ansible collection lock without duplicating its pins."""
    source = requirements or ROOT / "platform" / "ansible" / "requirements.yml"
    result: dict[str, str] = {}
    name: str | None = None
    for raw in source.read_text(encoding="utf-8").splitlines():
        if match := re.match(r"\s*-\s+name:\s*([\w.]+)\s*$", raw):
            if name is not None:
                raise RuntimeError(f"missing version for Ansible collection {name} in {source}")
            name = match.group(1)
        elif match := re.match(r"\s+version:\s*([\w.-]+)\s*$", raw):
            if name is None or name in result:
                raise RuntimeError(f"invalid Ansible collection requirement in {source}")
            result[name] = match.group(1)
            name = None
    if name is not None or not result:
        raise RuntimeError(f"invalid Ansible collection requirements in {source}")
    return result


def resolved_ansible_collection_version(name: str, collections_root: Path = PROJECT_COLLECTIONS) -> str | None:
    """Return the version Ansible can resolve from its isolated project path."""
    namespace, collection = name.split(".", 1)
    manifest = collections_root / "ansible_collections" / namespace / collection / "MANIFEST.json"
    if not manifest.is_file():
        return None
    try:
        return str(json.loads(manifest.read_text(encoding="utf-8")).get("collection_info", {}).get("version"))
    except (OSError, json.JSONDecodeError):
        return None


def ansible_collections_check() -> int:
    rc = 0
    for name, expected in required_ansible_collections().items():
        actual = resolved_ansible_collection_version(name)
        if actual == expected:
            print(f"PASS ansible collection {name} {actual}")
        else:
            print(
                f"FAIL ansible collection {name}: expected {expected}, resolved {actual or 'missing'}", file=sys.stderr
            )
            rc = 1
    return rc


def ansible_collections_ready() -> bool:
    return all(
        resolved_ansible_collection_version(name) == expected
        for name, expected in required_ansible_collections().items()
    )


def reconcile_ansible_collections() -> None:
    """Reconcile the checkout-local pinned Galaxy collections only when missing or drifted."""
    if ansible_collections_ready():
        return
    require("ansible-playbook")
    require("ansible-galaxy")
    run(
        [
            "ansible-playbook",
            "-i",
            "localhost,",
            "-c",
            "local",
            "platform/ansible/developer.yml",
            "-e",
            f"repo_root={ROOT}",
            "--tags",
            "ansible_collections",
        ]
    )
    if not ansible_collections_ready():
        drift = []
        for name, expected in required_ansible_collections().items():
            actual = resolved_ansible_collection_version(name)
            if actual != expected:
                drift.append(f"{name}: expected {expected}, resolved {actual or 'missing'}")
        raise RuntimeError("project Ansible collection reconciliation incomplete: " + "; ".join(drift))
    print("PASS project-owned Ansible collections reconciled")


def developer_state_ready(tags: str) -> bool:
    """Fast-path: avoid Ansible startup when requested local state is already exact."""
    wanted = {tag.strip() for tag in tags.split(",") if tag.strip()}
    pins = pinned_versions()
    if "node" in wanted:
        node = shutil.which("node")
        corepack = shutil.which("corepack")
        if not node or not corepack:
            return False
        expected_node = (ROOT / "frontend" / ".node-version").read_text(encoding="utf-8").strip()
        got = run([node, "--version"], check=False, capture=True)
        if got.returncode or got.stdout.strip() != f"v{expected_node}":
            return False
    if "go" in wanted or "cgo" in wanted:
        go = shutil.which("go")
        gofmt = shutil.which("gofmt")
        if not go or not gofmt:
            return False
        got = run([go, "version"], check=False, capture=True)
        if got.returncode or f"go{pins.get('GO_VERSION', '')}" not in got.stdout:
            return False
    if "cgo" in wanted and not shutil.which("cc"):
        return False
    if "quality_tools" in wanted:
        for command, key in (("oxlint", "OXLINT_VERSION"), ("oxfmt", "OXFMT_VERSION"), ("ruff", "RUFF_VERSION")):
            executable = shutil.which(command)
            if not executable:
                return False
            got = run([executable, "--version"], check=False, capture=True)
            if got.returncode or pins.get(key, "") not in got.stdout:
                return False
    if "sqlc" in wanted:
        sqlc = shutil.which("sqlc")
        if not sqlc:
            return False
        got = run([sqlc, "version"], check=False, capture=True)
        expected = pins.get("SQLC_VERSION", "")
        if got.returncode or (expected not in got.stdout):
            return False
    if "docker" in wanted:
        docker = shutil.which("docker")
        if not docker or run([docker, "info"], check=False, capture=True).returncode != 0:
            return False
    return True


def canonical_services() -> list[str]:
    return [str(x) for x in ruby_yaml("architecture.lock.yaml").get("business", {}).get("services", [])]


def run_ruby_tests(paths: list[str]) -> None:
    require("ruby")
    for path in paths:
        run(["ruby", "-Itest", path])


def runtime_efficiency_check() -> int:
    require("ruby")
    run(["ruby", "scripts/validate-runtime-efficiency.rb"])
    run_ruby_tests(["tests/runtime_efficiency_test.rb", "tests/resource_sizing_test.rb"])
    print("PASS runtime efficiency checks completed")
    return 0


def governance() -> int:
    run([sys.executable, "scripts/architecture_authority.py"])
    run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_architecture_authority.py"])
    require("ruby")
    run(["ruby", "scripts/validate-architecture.rb"])
    run(["ruby", "scripts/validate-observability.rb"])
    run_ruby_tests(
        [
            "tests/architecture_validator_test.rb",
            "tests/observability_topology_test.rb",
            "tests/ci_authority_test.rb",
            "tests/ci_affected_test.rb",
        ]
    )
    if documentation_policy():
        return 1
    print("PASS governance checks completed")
    return 0


def bundle_openapi_with_common(spec: Path, common_spec: Path) -> dict:
    """Return a single-document OpenAPI spec with canonical common components merged.

    oapi-codegen treats local multi-file refs as external package refs and therefore
    requires import-mapping. ecommerce-1 deliberately keeps common REST components
    in a separate canonical document, but generated service bindings stay inside the
    service package. Bundling the canonical common components avoids fake Go package
    boundaries while preserving the repository's split source contracts.

    Only refs to the registry-declared common document are accepted here. Any other
    external ref fails closed so code generation cannot silently pull in an
    undeclared local/remote dependency.
    """
    service_doc = copy.deepcopy(ruby_yaml(str(spec)))
    common_doc = copy.deepcopy(ruby_yaml(str(common_spec)))
    common_components = common_doc.get("components") or {}
    if not isinstance(common_components, dict):
        raise RuntimeError(f"common OpenAPI components must be a mapping: {common_spec}")

    spec_abs = spec.resolve()
    common_abs = common_spec.resolve()
    service_components = service_doc.setdefault("components", {})
    if not isinstance(service_components, dict):
        raise RuntimeError(f"service OpenAPI components must be a mapping: {spec}")

    def resolve_external(ref: str) -> tuple[Path, str]:
        path_part, sep, fragment = ref.partition("#")
        if not sep or not fragment.startswith("/components/"):
            raise RuntimeError(f"unsupported external OpenAPI reference {ref!r} in {spec}")
        if "://" in path_part or path_part.startswith("//"):
            raise RuntimeError(f"remote OpenAPI reference forbidden during generation: {ref!r}")
        target = (spec_abs.parent / path_part).resolve()
        if target != common_abs:
            raise RuntimeError(
                f"external OpenAPI reference {ref!r} does not target canonical common components {common_spec}"
            )
        return target, fragment

    def rewrite_refs(node):
        if isinstance(node, dict):
            ref = node.get("$ref")
            if isinstance(ref, str) and not ref.startswith("#"):
                _, fragment = resolve_external(ref)
                node["$ref"] = f"#{fragment}"
            for value in node.values():
                rewrite_refs(value)
        elif isinstance(node, list):
            for value in node:
                rewrite_refs(value)

    # Merge canonical common components first. A service may intentionally expose a
    # same-name alias such as bearerAuth -> common.v1.yaml#/components/...; replace
    # that alias with the canonical definition. Real conflicting definitions fail.
    rel_common = Path(os.path.relpath(common_abs, spec_abs.parent)).as_posix()
    for group, common_values in common_components.items():
        if not isinstance(common_values, dict):
            raise RuntimeError(f"common component group {group!r} must be a mapping")
        target_group = service_components.setdefault(group, {})
        if not isinstance(target_group, dict):
            raise RuntimeError(f"service component group {group!r} must be a mapping")
        for key, common_value in common_values.items():
            current = target_group.get(key)
            expected_refs = {
                f"{rel_common}#/components/{group}/{key}",
                f"./{rel_common}#/components/{group}/{key}",
            }
            if current is None:
                target_group[key] = copy.deepcopy(common_value)
            elif isinstance(current, dict) and set(current) == {"$ref"} and current.get("$ref") in expected_refs:
                target_group[key] = copy.deepcopy(common_value)
            elif current != common_value:
                raise RuntimeError(f"service/common OpenAPI component collision at components/{group}/{key}")

    rewrite_refs(service_doc)

    # Generation must now be self-contained. Keep internal refs intact so named
    # service schemas retain stable generated Go/TypeScript type names.
    leftovers: list[str] = []

    def collect_external(node):
        if isinstance(node, dict):
            ref = node.get("$ref")
            if isinstance(ref, str) and not ref.startswith("#"):
                leftovers.append(ref)
            for value in node.values():
                collect_external(value)
        elif isinstance(node, list):
            for value in node:
                collect_external(value)

    collect_external(service_doc)
    if leftovers:
        raise RuntimeError(f"bundled OpenAPI still contains external refs: {sorted(set(leftovers))}")
    return service_doc


def api_generate(target: str = "all", service: str = "", check: bool = False) -> int:
    if target not in {"all", "go", "ts"}:
        return fail("api-generate target must be all, go, or ts")
    registry = ruby_yaml("config/contracts/public-api-contracts.yaml")
    contracts = registry.get("contracts", {})
    common_entry = registry.get("common_components")
    if not common_entry:
        return fail("api-generate registry must declare common_components")
    common_spec = ROOT / common_entry
    if not common_spec.is_file():
        return fail(f"api-generate missing common contract: {common_spec.relative_to(ROOT)}")
    selected = [(name, entry) for name, entry in contracts.items() if not service or name == service]
    if not selected:
        return fail(f"api-generate no registered service matched {service!r}")
    for name, entry in selected:
        spec = ROOT / entry["path"]
        if not spec.is_file():
            return fail(f"api-generate missing contract: {spec.relative_to(ROOT)}")
        bundled_doc = bundle_openapi_with_common(spec, common_spec)
        with tempfile.TemporaryDirectory(prefix=f"ecommerce-{name}-openapi-") as temp_dir:
            bundled_spec = Path(temp_dir) / f"{name}.bundled.json"
            bundled_spec.write_text(json.dumps(bundled_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            if target in {"all", "go"}:
                require("oapi-codegen")
                require("gofmt")
                module = ROOT / "services" / name
                out_dir = module / "api" / "generated"
                if not module.is_dir():
                    print(f"SKIP api-generate go {name}: service not implemented")
                else:
                    if not (module / "go.mod").is_file():
                        return fail(f"api-generate implemented service lacks go.mod: services/{name}/go.mod")
                    out_dir.mkdir(parents=True, exist_ok=True)
                    generated = out_dir / "openapi.gen.go"
                    config_path = Path(temp_dir) / f"{name}.oapi-codegen.yaml"
                    config_path.write_text(
                        f"package: generated\noutput: {generated}\ngenerate:\n  models: true\n  std-http-server: true\n  strict-server: true\n",
                        encoding="utf-8",
                    )
                    # Run from the owning Go module so oapi-codegen can resolve the
                    # module/runtime context instead of warning from repository root.
                    run(["oapi-codegen", "--config", str(config_path), str(bundled_spec)], cwd=module)
                    run(["gofmt", "-w", str(generated)], cwd=module)
            if target in {"all", "ts"}:
                require("corepack")
                require("oxfmt")
                out_dir = ROOT / "frontend" / "packages" / "api-client" / "src" / "generated"
                out_dir.mkdir(parents=True, exist_ok=True)
                generated = out_dir / f"{name}.ts"
                p = run(
                    ["corepack", "pnpm", "--dir", "frontend", "exec", "openapi-typescript", str(bundled_spec)],
                    capture=True,
                )
                candidate = Path(temp_dir) / f"{name}.generated.ts"
                candidate.write_text(p.stdout, encoding="utf-8")
                run(
                    [
                        "oxfmt",
                        "--config",
                        str(ROOT / "frontend" / ".oxfmtrc.json"),
                        "--write",
                        str(candidate),
                    ],
                    cwd=ROOT / "frontend",
                )
                canonical = candidate.read_text(encoding="utf-8")
                if check:
                    if not generated.is_file():
                        return fail(f"generated TypeScript API client is missing: {generated.relative_to(ROOT)}", 1)
                    current = generated.read_text(encoding="utf-8")
                    if current != canonical:
                        return fail(f"generated TypeScript API client is stale: {generated.relative_to(ROOT)}", 1)
                else:
                    generated.write_text(canonical, encoding="utf-8")
    print(f"PASS generated API bindings target={target}")
    return 0


def api_compat(base: str, head: str) -> int:
    require("oasdiff")
    args = ["diff", "--name-only", "--diff-filter=ACMRTUXB", base]
    if head != "WORKTREE":
        args.append(head)
    args += ["--", "contracts/openapi", "config/contracts/public-api-contracts.yaml"]
    changed = [x for x in git(*args).splitlines() if x]
    if not changed:
        print("SKIP OpenAPI compatibility: no API contract changes")
        return 0
    registry = ruby_yaml("config/contracts/public-api-contracts.yaml")
    common = registry.get("common_components")
    specs = [entry["path"] for entry in registry.get("contracts", {}).values()]
    with (
        tempfile.TemporaryDirectory(prefix="ecommerce-oas-old-") as old_s,
        tempfile.TemporaryDirectory(prefix="ecommerce-oas-new-") as new_s,
    ):
        old = Path(old_s)
        new = Path(new_s)
        for tree, ref in ((old, base), (new, head)):
            if ref == "WORKTREE":
                shutil.copytree(ROOT / "contracts" / "openapi", tree / "contracts" / "openapi", dirs_exist_ok=True)
                (tree / "config" / "contracts").mkdir(parents=True, exist_ok=True)
                shutil.copy2(
                    ROOT / "config" / "contracts" / "public-api-contracts.yaml",
                    tree / "config" / "contracts" / "public-api-contracts.yaml",
                )
            else:
                # git archive is binary; stream it directly to tar.
                proc1 = subprocess.Popen(
                    ["git", "archive", ref, "contracts/openapi", "config/contracts/public-api-contracts.yaml"],
                    cwd=ROOT,
                    stdout=subprocess.PIPE,
                )
                proc2 = subprocess.run(["tar", "-x", "-C", str(tree)], stdin=proc1.stdout)
                if proc1.stdout:
                    proc1.stdout.close()
                rc = proc1.wait()
                if rc or proc2.returncode:
                    raise RuntimeError(f"git archive failed for {ref}")
        common_changed = bool(common and common in changed)
        for spec in specs:
            if not common_changed and spec not in changed:
                continue
            if not (old / spec).is_file():
                print(f"SKIP OpenAPI compatibility: {spec} is new relative to {base}")
                continue
            print(f"CHECK OpenAPI compatibility: {spec}")
            run(["oasdiff", "breaking", "--fail-on", "ERR", str(old / spec), str(new / spec)])
    print("PASS OpenAPI compatibility checks completed")
    return 0


def contracts(base: str = "", head: str = "WORKTREE", generate: bool = False) -> int:
    require("ruby")
    run(["ruby", "scripts/validate-openapi.rb"])
    run(["ruby", "scripts/validate-contract-consistency.rb"])
    run_ruby_tests(["tests/openapi_validator_test.rb", "tests/contract_consistency_test.rb"])
    contract_changed = False
    if base:
        args = ["diff", "--name-only", "--diff-filter=ACMRTUXB", base]
        if head != "WORKTREE":
            args.append(head)
        args += ["--", "contracts/openapi", "config/contracts/public-api-contracts.yaml"]
        contract_changed = bool(git(*args).strip())
        api_compat(base, head)
    if generate or contract_changed:
        api_generate("all")
    print("PASS OpenAPI and cross-registry contract checks completed")
    return 0


def repository_shell_paths(root: Path = ROOT) -> list[str]:
    """Return Shell files that exist in the effective Git worktree.

    `git ls-files` alone reports paths that are still present in the index even when
    they have been deleted but not staged yet. The migration gate runs against
    WORKTREE before commit, so those intentional deletions must not be false
    positives. Include untracked, non-ignored files so newly introduced Shell
    automation still fails closed.
    """
    candidates = output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "--", "*.sh"],
        cwd=root,
    ).splitlines()
    return sorted(path for path in candidates if path and (root / path).is_file())


def automation_policy() -> int:
    # Shell source is forbidden repository-wide after the Ansible-first migration.
    shell_files = repository_shell_paths()
    if shell_files:
        print(
            "FAIL shell automation policy: repository *.sh files are forbidden after Ansible-first migration",
            file=sys.stderr,
        )
        for path in shell_files:
            print(f"  {path}", file=sys.stderr)
        return 1
    bad = []
    for path in (ROOT / "platform" / "tekton").rglob("*.yaml"):
        text = path.read_text(encoding="utf-8", errors="replace")
        if re.search(r"scripts/[^\s'\"]+\.sh\b", text) or "#!/bin/sh" in text or "#!/usr/bin/env bash" in text:
            bad.append(path)
    if bad:
        print("FAIL automation policy: Tekton must invoke native commands/Make, not shell wrappers", file=sys.stderr)
        for path in bad:
            print(f"  {path.relative_to(ROOT)}", file=sys.stderr)
        return 1
    build = ROOT / "BUILD.bazel"
    if build.is_file() and "sh_binary(" in build.read_text(encoding="utf-8"):
        return fail("automation policy: Bazel sh_binary is forbidden; use py_binary/native targets", 1)
    print("PASS automation policy: zero repository *.sh files and no Tekton shell wrappers")
    return 0


def documentation_policy() -> int:
    """Reject active documentation that contradicts the canonical automation model."""
    rules = {
        "AGENTS.md": [r"portable POSIX `sh`", r"repository shell helpers"],
        "README.md": [r"scripts/ci-\*\.sh"],
        "docs/project/CODEX_HANDOFFS.md": [r"shared POSIX `sh` helpers", r"shared repository scripts factored"],
        "docs/api/README.md": [r"bootstrap CI Woodpecker"],
    }
    failures: list[str] = []
    for relative, patterns in rules.items():
        text = (ROOT / relative).read_text(encoding="utf-8")
        for pattern in patterns:
            if re.search(pattern, text, flags=re.IGNORECASE):
                failures.append(f"{relative}: {pattern}")
    if failures:
        print("FAIL documentation policy: active legacy automation references found", file=sys.stderr)
        print("\n".join(f"  {item}" for item in failures), file=sys.stderr)
        return 1
    print("PASS documentation policy: active automation references are canonical")
    return 0


def frontend(action: str, scope: str) -> int:
    if action not in {"check", "lint", "test", "build"} or scope not in {"all", "storefront", "admin"}:
        return fail("frontend usage: action={check|lint|test|build} scope={all|storefront|admin}")
    ensure_developer("node,quality_tools")
    require("node")
    require("corepack")
    require("oxlint")
    package = json.loads((ROOT / "frontend" / "package.json").read_text(encoding="utf-8"))
    pm = package.get("packageManager", "")
    if not pm.startswith("pnpm@"):
        return fail(f"frontend packageManager must pin pnpm, got {pm!r}")
    expected = pm.split("@", 1)[1]
    actual = output(["corepack", "pnpm", "--version"], cwd=ROOT / "frontend").strip()
    if actual != expected:
        return fail(f"pnpm version mismatch: expected {expected}, got {actual}")
    run(["corepack", "pnpm", "install", "--frozen-lockfile", "--prefer-offline"], cwd=ROOT / "frontend")
    if action in {"check", "test", "build"}:
        if api_generate("ts", check=True):
            return 1

    def pnpm(*args: str) -> None:
        run(["corepack", "pnpm", *args], cwd=ROOT / "frontend")

    if action in {"check", "lint"}:
        lint_paths = ["apps", "packages"] if scope == "all" else [f"apps/{scope}", "packages/ui", "packages/api-client"]
        run(["oxlint", *lint_paths], cwd=ROOT / "frontend")
    if action in {"check", "test", "build"}:
        if scope == "all":
            pnpm("run", "typecheck")
        else:
            pnpm("--filter", "@noma/ui", "typecheck")
            pnpm("--filter", "@noma/api-client", "typecheck")
            pnpm("--filter", f"@noma/{scope}", "typecheck")
    if action in {"check", "test"}:
        if scope == "all":
            pnpm("run", "test")
        else:
            pnpm("--filter", f"@noma/{scope}", "test")
    if action in {"check", "build"}:
        if scope == "all":
            pnpm("run", "build")
        else:
            pnpm("--filter", f"@noma/{scope}", "build")
    print(f"PASS frontend {scope} {action} checks completed")
    return 0


def ensure_developer(tags: str) -> None:
    if developer_state_ready(tags):
        return
    require("ansible-playbook")
    run(
        [
            "ansible-playbook",
            "-i",
            "localhost,",
            "-c",
            "local",
            "platform/ansible/developer.yml",
            "-e",
            f"repo_root={ROOT}",
            "--tags",
            tags,
        ]
    )
    if not developer_state_ready(tags):
        raise RuntimeError(f"developer state reconciliation did not satisfy tags: {tags}")


def service_check(service: str) -> int:
    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", service or ""):
        return fail("SERVICE must be a canonical lowercase service name")
    if service not in canonical_services():
        return fail(f"service is not canonical: {service}")
    module = ROOT / "services" / service
    if not (module / "go.mod").is_file():
        return fail(f"service module does not exist: services/{service}/go.mod")
    ensure_developer("go,cgo,sqlc,docker")
    env = os.environ.copy()
    env["PATH"] = f"{Path.home() / '.local/bin'}:{env.get('PATH', '')}"
    env["CGO_ENABLED"] = "1"
    if (module / "sqlc.yaml").is_file():
        cfg = ruby_yaml(str(module / "sqlc.yaml"))
        out_dir = cfg["sql"][0]["gen"]["go"]["out"]
        with tempfile.TemporaryDirectory(prefix=f"{service}-sqlc-") as temp:
            tmp = Path(temp)
            shutil.copytree(module, tmp / service, dirs_exist_ok=True)
            run(["sqlc", "generate"], cwd=tmp / service, env=env)
            run(["sqlc", "vet"], cwd=tmp / service, env=env)
            diff = run(["diff", "-ru", str(module / out_dir), str(tmp / service / out_dir)], check=False, capture=True)
            if diff.returncode:
                print(diff.stdout)
                return fail(f"{service} sqlc generated code is stale")
    require("gofmt")
    go_files = [str(p) for p in module.rglob("*.go") if "vendor" not in p.parts]
    if go_files:
        p = run(["gofmt", "-l", *go_files], capture=True)
        if p.stdout.strip():
            print(p.stdout, file=sys.stderr)
            return fail(f"gofmt required for {service}", 1)
    run(["go", "test", "-race", "./..."], cwd=module, env=env)
    if (module / "internal" / "infrastructure" / "postgres").is_dir():
        run(
            ["go", "test", "-race", "-tags=integration", "./internal/infrastructure/postgres", "-count=1"],
            cwd=module,
            env=env,
        )
    run(["go", "vet", "./..."], cwd=module, env=env)
    run(["go", "build", "./..."], cwd=module, env=env)
    print(f"PASS {service} service checks completed")
    return 0


def security() -> int:
    require("gitleaks")
    if os.environ.get("HEAD", "").strip() == "WORKTREE":
        tree_sha = worktree_tree_sha()
        with tempfile.TemporaryDirectory(prefix="ecommerce-gitleaks-worktree-") as temp_dir:
            temp_root = Path(temp_dir)
            archive = temp_root / "tree.tar"
            scan_root = temp_root / "tree"
            scan_root.mkdir()
            run(["git", "archive", "--format=tar", "--output", str(archive), tree_sha])
            shutil.unpack_archive(str(archive), str(scan_root), "tar")
            run(["gitleaks", "dir", "--config", ".gitleaks.toml", "--redact", "--no-banner", str(scan_root)])
    elif run(["git", "rev-parse", "--verify", "HEAD"], check=False, capture=True).returncode == 0:
        run(["gitleaks", "git", "--config", ".gitleaks.toml", "--redact", "--no-banner", "."])
    else:
        run(["gitleaks", "dir", "--config", ".gitleaks.toml", "--redact", "--no-banner", "."])
    print("PASS secret scan completed")
    return 0


def terraform_check() -> int:
    tf_files = [p for p in ROOT.rglob("*.tf") if ".terraform" not in p.parts]
    if not tf_files:
        print("SKIP terraform: no Terraform files found")
        return 0
    tool = shutil.which("tofu") or shutil.which("terraform")
    if not tool:
        return fail("Terraform sources exist but neither tofu nor terraform is installed")
    run([tool, "fmt", "-check", "-recursive", "-diff"])
    for directory in sorted({p.parent for p in tf_files}):
        print(f"CHECK terraform: {directory.relative_to(ROOT)}")
        if "modules" in directory.parts and "platform" in directory.parts:
            with tempfile.TemporaryDirectory(prefix="tf-module-") as temp:
                shutil.copytree(directory, temp, dirs_exist_ok=True)
                run([tool, "init", "-backend=false", "-input=false"], cwd=Path(temp))
                run([tool, "validate"], cwd=Path(temp))
        else:
            run([tool, "init", "-backend=false", "-input=false"], cwd=directory)
            run([tool, "validate"], cwd=directory)
    print("PASS terraform checks completed")
    return 0


def ansible_check() -> int:
    reconcile_ansible_collections()
    require("ansible-lint")
    files = sorted(str(p.relative_to(ROOT)) for p in (ROOT / "platform" / "ansible").rglob("*.yml"))
    files += sorted(str(p.relative_to(ROOT)) for p in (ROOT / "platform" / "ansible").rglob("*.yaml"))
    if not files:
        print("SKIP ansible: no Ansible files found")
        return 0
    run(["ansible-lint", *files])
    run(
        [
            "ansible-playbook",
            "-i",
            "localhost,",
            "-c",
            "local",
            "platform/ansible/developer.yml",
            "--syntax-check",
            "-e",
            f"repo_root={ROOT}",
        ]
    )
    if ansible_collections_check():
        return 1
    print("PASS ansible checks completed")
    return 0


def system_check() -> int:
    tests = sorted(str(p.relative_to(ROOT)) for p in (ROOT / "tests").glob("*_test.rb"))
    run_ruby_tests(tests)
    for suite in [ROOT / "tests", ROOT / "tests" / "delivery", ROOT / "tests" / "context"]:
        if suite.is_dir() and any(suite.glob("test_*.py")):
            run([sys.executable, "-m", "unittest", "discover", "-s", str(suite.relative_to(ROOT)), "-p", "test_*.py"])
    print("PASS cross-system repository checks completed")
    return 0


def lint_all() -> int:
    if automation_policy():
        return 1
    go_files = [str(p) for p in (ROOT / "services").rglob("*.go") if "vendor" not in p.parts]
    if go_files:
        require("gofmt")
        p = run(["gofmt", "-l", *go_files], capture=True)
        if p.stdout.strip():
            print(p.stdout, file=sys.stderr)
            return 1
    python_files = sorted(str(path) for tree in (ROOT / "scripts", ROOT / "tests") for path in tree.rglob("*.py"))
    if python_files:
        require("ruff")
        run(["ruff", "check", *python_files])
    if (ROOT / "frontend" / "package.json").is_file():
        frontend("lint", "all")
    print("PASS lint checks completed")
    return 0


def test_all() -> int:
    system_check()
    for service in canonical_services():
        module = ROOT / "services" / service
        if (module / "go.mod").is_file():
            ensure_developer("go")
            run(["go", "test", "./..."], cwd=module)
            run(["go", "vet", "./..."], cwd=module)
    if (ROOT / "frontend" / "package.json").is_file():
        frontend("test", "all")
    print("PASS test checks completed")
    return 0


def changed_paths(base: str, head: str) -> list[str]:
    if head == "WORKTREE":
        tracked = git("diff", "--name-only", "--diff-filter=ACMRTUXB", base, "--").splitlines()
        untracked = git("ls-files", "--others", "--exclude-standard").splitlines()
        return sorted(set(filter(None, tracked + untracked)))
    return sorted(
        set(filter(None, git("diff", "--name-only", "--diff-filter=ACMRTUXB", base, head, "--").splitlines()))
    )


def worktree_tree_sha() -> str:
    """Hash the commit tree represented by the current worktree without mutating the real index."""
    index_path = Path(git("rev-parse", "--path-format=absolute", "--git-path", "index").strip())
    with tempfile.TemporaryDirectory(prefix="ecommerce-worktree-index-") as temp_dir:
        temporary_index = Path(temp_dir) / "index"
        env = os.environ.copy()
        env["GIT_INDEX_FILE"] = str(temporary_index)
        if index_path.is_file():
            shutil.copy2(index_path, temporary_index)
        else:
            run(["git", "read-tree", "--empty"], env=env)
        run(["git", "add", "-A", "--"], env=env)
        tree_sha = output(["git", "write-tree"], env=env).strip()
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", tree_sha):
        raise RuntimeError(f"invalid worktree tree SHA: {tree_sha!r}")
    return tree_sha


def _load_promotable_worktree_evidence(base_ref: str) -> dict | None:
    path = CONTEXT / "evidence" / "worktree.json"
    if not path.is_file():
        return None
    try:
        evidence = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    current_head = git("rev-parse", "HEAD").strip()
    base_sha = git("rev-parse", base_ref).strip()
    current_tree = worktree_tree_sha()
    if (
        evidence.get("schema_version", 0) < 4
        or evidence.get("evidence_kind") != "worktree"
        or evidence.get("status") != "PASS"
        or evidence.get("exact_commit_evidence") is not False
        or evidence.get("head_ref") != "WORKTREE"
        or evidence.get("head_sha") != current_head
        or evidence.get("source_head_sha") != current_head
        or evidence.get("source_tree_sha") != current_tree
        or evidence.get("base_sha") != base_sha
        or evidence.get("verification", {}).get("tree_stable") is not True
        or evidence.get("changed_paths") != changed_paths(base_ref, "WORKTREE")
        or not isinstance(evidence.get("gates"), list)
        or any(record.get("status") not in {"PASS", "SKIP"} for record in evidence.get("gates", []))
    ):
        return None
    return evidence


def _promote_worktree_evidence(base_ref: str, head: str, source: dict) -> Path | None:
    requested = git("rev-parse", head).strip()
    current = git("rev-parse", "HEAD").strip()
    if requested != current or git("status", "--porcelain", "--untracked-files=all").strip():
        return None
    base_sha = git("rev-parse", base_ref).strip()
    parents = git("rev-list", "--parents", "-n", "1", requested).split()
    source_head = str(source.get("source_head_sha", ""))
    source_tree = str(source.get("source_tree_sha", ""))
    commit_tree = git("rev-parse", f"{requested}^{{tree}}").strip()
    if (
        source.get("schema_version", 0) < 4
        or source.get("status") != "PASS"
        or source.get("exact_commit_evidence") is not False
        or source.get("base_sha") != base_sha
        or len(parents) != 2
        or parents[1] != source_head
        or commit_tree != source_tree
    ):
        return None

    records: list[dict] = []
    for record in source.get("gates", []):
        promoted = copy.deepcopy(record)
        if promoted.get("status") == "PASS":
            source_duration = float(
                promoted.get("source_duration_seconds", promoted.get("duration_seconds", 0.0)) or 0.0
            )
            promoted["source_duration_seconds"] = source_duration
            promoted["duration_seconds"] = 0.0
            promoted["promoted_from_worktree"] = True
            promoted["promotion_source_tree_sha"] = source_tree
        records.append(promoted)

    payload = copy.deepcopy(source)
    payload.update(
        {
            "schema_version": 4,
            "evidence_kind": "exact_commit",
            "head_ref": requested,
            "head_sha": requested,
            "exact_commit_evidence": True,
            "gates": records,
            "metrics": evidence_metrics(records),
            "verification": {
                "mode": "promoted-worktree",
                "source_head_sha": source_head,
                "source_tree_sha": source_tree,
                "commit_tree_sha": commit_tree,
            },
        }
    )
    destination = CONTEXT / "evidence" / f"{requested}.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    saved = float(payload["metrics"].get("estimated_saved_seconds", 0.0) or 0.0)
    print(f"PASS | promoted worktree evidence | {requested} | tree {commit_tree} | saved~{saved:.3f}s")
    return destination


def _valid_exact_evidence(base_ref: str, head: str) -> Path | None:
    requested = git("rev-parse", head).strip()
    if requested != git("rev-parse", "HEAD").strip():
        return None
    if git("status", "--porcelain", "--untracked-files=all").strip():
        return None
    path = CONTEXT / "evidence" / f"{requested}.json"
    if not path.is_file():
        return None
    try:
        evidence = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if (
        evidence.get("status") != "PASS"
        or evidence.get("exact_commit_evidence") is not True
        or evidence.get("head_sha") != requested
        or evidence.get("base_sha") != git("rev-parse", base_ref).strip()
    ):
        return None
    return path


def affected(base: str, head: str, *, strict_unknown: bool = False) -> list[str]:
    require("ruby")
    command = ["ruby", "scripts/ci-affected.rb", "--base", base, "--head", head, "--format", "json"]
    if strict_unknown:
        command.append("--strict-unknown")
    p = run(command, capture=True)
    return json.loads(p.stdout)


def _run_gate(name: str, command: list[str], records: list[dict], env: dict[str, str] | None = None) -> bool:
    logs = CONTEXT / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    log_path = logs / f"{name.replace(':', '-').replace('/', '-')}.log"
    start = time.monotonic()
    with log_path.open("w", encoding="utf-8") as log:
        p = subprocess.run(command, cwd=ROOT, env=env, text=True, stdout=log, stderr=subprocess.STDOUT)
    duration = round(time.monotonic() - start, 3)
    records.append(
        {
            "gate": name,
            "status": "PASS" if p.returncode == 0 else "FAIL",
            "exit_code": p.returncode,
            "duration_seconds": duration,
            "command": command,
            "log": str(log_path.relative_to(ROOT)),
        }
    )
    print(f"{'PASS' if p.returncode == 0 else 'FAIL'} {name} ({duration:.3f}s)")
    if p.returncode:
        print("\n".join(log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-60:]), file=sys.stderr)
    return p.returncode == 0


def _incremental_parent_evidence(base: str, head: str) -> tuple[str | None, dict | None]:
    """Return direct-parent evidence only when every exactness invariant holds."""
    if head == "WORKTREE":
        return None, None
    head_sha = git("rev-parse", head).strip()
    parents = git("rev-list", "--parents", "-n", "1", head_sha).split()
    if len(parents) != 2:
        return None, None
    parent_sha = parents[1]
    evidence_path = CONTEXT / "evidence" / f"{parent_sha}.json"
    if not evidence_path.is_file() and os.environ.get("CI_EVIDENCE_REPOSITORY", "").strip():
        try:
            fetch_evidence(ROOT, CONTEXT, parent_sha)
            print(f"INFO fetched authenticated parent evidence {parent_sha[:12]}")
        except RuntimeError as exc:
            print(f"INFO remote parent evidence unavailable; full verification required: {exc}", file=sys.stderr)
    if not evidence_path.is_file():
        return None, None
    try:
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None, None
    base_sha = git("rev-parse", base).strip()
    if (
        evidence.get("schema_version", 0) < 2
        or evidence.get("status") != "PASS"
        or evidence.get("exact_commit_evidence") is not True
        or evidence.get("head_sha") != parent_sha
        or evidence.get("base_sha") != base_sha
        or not isinstance(evidence.get("gates"), list)
    ):
        return None, None
    return parent_sha, evidence


def _reuse_gate(name: str, parent_sha: str, parent_evidence: dict, records: list[dict]) -> bool:
    source = next((gate for gate in parent_evidence.get("gates", []) if gate.get("gate") == name), None)
    if not source or source.get("status") != "PASS":
        return False
    source_duration = float(source.get("source_duration_seconds", source.get("duration_seconds", 0.0)) or 0.0)
    original_execution_sha = source.get("original_execution_sha") or source.get("reused_from_sha") or parent_sha
    records.append(
        {
            "gate": name,
            "status": "PASS",
            "exit_code": 0,
            "duration_seconds": 0.0,
            "reused_from_sha": parent_sha,
            "original_execution_sha": original_execution_sha,
            "source_duration_seconds": source_duration,
            "reuse_reason": "direct-parent exact PASS; strict delta has no affected inputs for this gate",
        }
    )
    print(f"PASS | reused {parent_sha} | {name} | saved~{source_duration:.3f}s")
    return True


def _controller_command(*args: str) -> list[str]:
    controller = os.environ.get("REPOCTL_TRUSTED_CONTROLLER", "scripts/repoctl.py").strip() or "scripts/repoctl.py"
    return [sys.executable, controller, *args]


def _require_clean_exact_checkout(command: str, head: str) -> tuple[str, str] | None:
    requested = git("rev-parse", head).strip()
    current = git("rev-parse", "HEAD").strip()
    if requested != current:
        fail(f"{command} head mismatch: requested {requested}, checked out {current}")
        return None
    if git("status", "--porcelain", "--untracked-files=all").strip():
        fail(f"{command} requires a clean exact-SHA checkout")
        return None
    return requested, current


def _normalized_component_gates(components: list[str]) -> list[str]:
    values = [component for component in components if component != "global"]
    both_frontends = "frontend:storefront" in values and "frontend:admin" in values
    if both_frontends:
        values = [component for component in values if not component.startswith("frontend:")]
        values.append("frontend:all")
    return sorted(set(values))


def _component_command(component: str) -> tuple[list[str] | None, str | None]:
    if component == "none":
        return None, "no affected component gate"
    if component.startswith("service:"):
        service = component.split(":", 1)[1]
        if not (ROOT / "services" / service / "go.mod").is_file():
            return None, "canonical service not implemented"
        return _controller_command("service", service), None
    if component.startswith("frontend:"):
        return _controller_command("frontend", "check", component.split(":", 1)[1]), None
    if component == "platform:terraform":
        return _controller_command("terraform"), None
    if component == "platform:ansible":
        return _controller_command("ansible"), None
    if component == "system":
        return _controller_command("system"), None
    raise RuntimeError(f"unsupported affected component: {component}")


def _global_gate_commands(base: str, head: str) -> list[tuple[str, list[str]]]:
    return [
        ("governance", _controller_command("governance")),
        ("runtime-efficiency", _controller_command("runtime-efficiency")),
        ("contracts", _controller_command("contracts", "--base", base, "--head", head)),
        ("automation", _controller_command("automation-policy")),
        ("security", _controller_command("security")),
    ]


def _record_delivery_wall(evidence_path: Path, evidence: dict, started: float) -> float:
    wall = round(time.monotonic() - started, 3)
    metrics = evidence.setdefault("metrics", evidence_metrics(evidence.get("gates", [])))
    metrics["deliver_wall_seconds"] = wall
    evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"DELIVER_METRICS wall={wall:.3f}s executed={metrics.get('executed_gates', 0)} reused={metrics.get('reused_gates', 0)}"
    )
    return wall


def _record_path(record_dir: Path, label: str) -> Path:
    record_dir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", label).strip("-") or "record"
    return record_dir / f"{safe}.json"


def _write_record(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def tekton_plan(base: str, head: str, record_dir: str, result_path: str) -> int:
    exact = _require_clean_exact_checkout("tekton-plan", head)
    if exact is None:
        return 2
    requested, current = exact
    base_sha = git("rev-parse", base).strip()
    components = affected(base, head)
    gates = _normalized_component_gates(components)
    parent_sha, parent_evidence = _incremental_parent_evidence(base, head)
    delta_components: set[str] = set()
    verification: dict = {"mode": "full"}
    reused: list[dict] = []
    execute: list[str] = []

    if parent_sha and parent_evidence:
        delta_paths = changed_paths(parent_sha, head)
        delta_components = set(affected(parent_sha, head, strict_unknown=True))
        verification = {
            "mode": "incremental",
            "parent_sha": parent_sha,
            "delta_paths": delta_paths,
            "delta_components": sorted(delta_components),
        }

    for gate in gates:
        delta_hit = gate in delta_components
        if gate == "frontend:all":
            delta_hit = bool({"frontend:storefront", "frontend:admin"} & delta_components)
        if parent_sha and parent_evidence and not delta_hit:
            if _reuse_gate(gate, parent_sha, parent_evidence, reused):
                continue
        execute.append(gate)

    directory = Path(record_dir)
    plan = {
        "schema_version": 1,
        "base_ref": base,
        "base_sha": base_sha,
        "head_ref": head,
        "head_sha": requested,
        "changed_paths": changed_paths(base, head),
        "affected_components": components,
        "component_gates": gates,
        "execute_components": execute,
        "reused_records": reused,
        "verification": verification,
    }
    _write_record(_record_path(directory, "plan"), plan)
    output_components = execute or ["none"]
    Path(result_path).write_text(json.dumps(output_components), encoding="utf-8")
    target = os.environ.get("CI_STATUS_TARGET_URL", "").strip()
    publish_remote_status(requested, "pending", "Tekton affected-only verification running", target)
    print(f"PASS tekton-plan exact {requested}: execute={len(execute)} reused={len(reused)}")
    return 0


def ci_global(base: str, head: str, record_dir: str) -> int:
    exact = _require_clean_exact_checkout("ci-global", head)
    if exact is None:
        return 2
    requested, _ = exact
    records: list[dict] = []
    env = os.environ.copy()
    env.update({"BASE": base, "HEAD": head})
    rc = 0
    for name, command in _global_gate_commands(base, head):
        if not _run_gate(name, command, records, env):
            rc = 1
            break
    _write_record(_record_path(Path(record_dir), "global"), {"head_sha": requested, "records": records})
    return rc


def ci_component(component: str, base: str, head: str, record_dir: str) -> int:
    exact = _require_clean_exact_checkout("ci-component", head)
    if exact is None:
        return 2
    requested, _ = exact
    command, reason = _component_command(component)
    records: list[dict] = []
    if command is None:
        records.append({"gate": component, "status": "SKIP", "reason": reason, "duration_seconds": 0.0})
        rc = 0
    else:
        env = os.environ.copy()
        env.update({"BASE": base, "HEAD": head})
        rc = 0 if _run_gate(component, command, records, env) else 1
    _write_record(_record_path(Path(record_dir), f"component-{component}"), {"head_sha": requested, "records": records})
    return rc


def ci_finalize(base: str, head: str, record_dir: str) -> int:
    directory = Path(record_dir)
    plan_path = _record_path(directory, "plan")
    exact = _require_clean_exact_checkout("ci-finalize", head)
    if exact is None:
        return 2
    requested, _ = exact
    base_sha = git("rev-parse", base).strip()
    target = os.environ.get("CI_STATUS_TARGET_URL", "").strip()
    if not plan_path.is_file():
        publish_remote_status(requested, "failure", "Tekton plan evidence is missing", target)
        return fail("Tekton finalizer missing plan record", 1)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    if plan.get("head_sha") != requested or plan.get("base_sha") != base_sha:
        publish_remote_status(requested, "failure", "Tekton plan SHA/base mismatch", target)
        return fail("Tekton plan does not bind the exact head/base", 1)

    records: list[dict] = []
    global_path = _record_path(directory, "global")
    if global_path.is_file():
        records.extend(json.loads(global_path.read_text(encoding="utf-8")).get("records", []))
    records.extend(plan.get("reused_records", []))
    for path in sorted(directory.glob("component-*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        for record in payload.get("records", []):
            if record.get("gate") != "none":
                records.append(record)

    expected = {name for name, _ in _global_gate_commands(base, head)} | set(plan.get("component_gates", []))
    by_gate: dict[str, dict] = {}
    duplicates: set[str] = set()
    for record in records:
        gate = str(record.get("gate", ""))
        if not gate:
            continue
        if gate in by_gate:
            duplicates.add(gate)
        by_gate[gate] = record
    missing = expected - set(by_gate)
    bad = sorted(
        gate for gate, record in by_gate.items() if gate in expected and record.get("status") not in {"PASS", "SKIP"}
    )
    if missing or duplicates or bad:
        description = f"Tekton incomplete/failed: missing={len(missing)} duplicate={len(duplicates)} failed={len(bad)}"
        publish_remote_status(requested, "failure", description[:140], target)
        return fail(description, 1)

    evidence = write_evidence(
        base,
        head,
        list(plan.get("changed_paths", [])),
        list(plan.get("affected_components", [])),
        [by_gate[name] for name in sorted(expected)],
        dict(plan.get("verification", {"mode": "full"})),
    )
    if os.environ.get("CI_EVIDENCE_REPOSITORY", "").strip():
        published = publish_evidence(ROOT, evidence)
        print(f"PASS evidence published {published['digest_reference']}")
    metrics = json.loads(evidence.read_text(encoding="utf-8")).get("metrics", {})
    publish_remote_status(
        requested,
        "success",
        f"PASS: {metrics.get('executed_gates', 0)} executed, {metrics.get('reused_gates', 0)} reused",
        target,
    )
    return 0


def evidence_publish_command(path: str) -> int:
    result = publish_evidence(ROOT, Path(path))
    print(json.dumps(result, sort_keys=True))
    return 0


def evidence_fetch_command(sha: str) -> int:
    path = fetch_evidence(ROOT, CONTEXT, sha)
    print(path.relative_to(ROOT))
    return 0


def evidence_compare_command(full_path: str, incremental_path: str) -> int:
    result = compare_evidence(Path(full_path), Path(incremental_path))
    destination = (
        CONTEXT
        / f"evidence-comparison-{str(result.get('full_head_sha'))[:12]}-{str(result.get('incremental_head_sha'))[:12]}.json"
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    print(f"EVIDENCE_COMPARISON {destination.relative_to(ROOT)}")
    return 0


def github_exact_ci_status(gh: str, head_sha: str) -> str:
    response = run(
        [gh, "api", f"repos/{{owner}}/{{repo}}/commits/{head_sha}/status"],
        check=False,
        capture=True,
    )
    if response.returncode:
        return "no remote CI status present"
    try:
        payload = json.loads(response.stdout or "{}")
    except json.JSONDecodeError:
        return "no remote CI status present"
    statuses = [status for status in payload.get("statuses", []) if status.get("context") == REMOTE_STATUS_CONTEXT]
    if not statuses:
        return "no remote CI status present"
    latest = statuses[0]
    return f"{latest.get('state', 'unknown')} | {REMOTE_STATUS_CONTEXT} | {head_sha}"


def write_evidence(
    base: str, head: str, paths: list[str], components: list[str], records: list[dict], verification: dict | None = None
) -> Path:
    base_sha = git("rev-parse", base).strip()
    current_head_sha = git("rev-parse", "HEAD").strip()
    head_sha = current_head_sha if head == "WORKTREE" else git("rev-parse", head).strip()
    clean = not git("status", "--porcelain", "--untracked-files=all").strip()
    exact = head != "WORKTREE" and clean and current_head_sha == head_sha
    verification_data = verification or {"mode": "full"}
    payload = {
        "schema_version": 4,
        "evidence_kind": "worktree" if head == "WORKTREE" else "exact_commit",
        "base_ref": base,
        "base_sha": base_sha,
        "head_ref": head,
        "head_sha": head_sha,
        "exact_commit_evidence": exact,
        "status": "FAIL" if any(r["status"] == "FAIL" for r in records) else "PASS",
        "changed_paths": paths,
        "affected_components": components,
        "gates": records,
        "metrics": evidence_metrics(records),
        "verification": verification_data,
    }
    if head == "WORKTREE":
        payload["source_head_sha"] = verification_data.get("source_head_sha", current_head_sha)
        payload["source_tree_sha"] = verification_data.get("source_tree_sha")
    identity = head_sha if head != "WORKTREE" else "worktree"
    destination = CONTEXT / "evidence" / f"{identity}.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"EVIDENCE {destination.relative_to(ROOT)}")
    return destination


def verify_change(base: str, head: str) -> int:
    source_head_sha: str | None = None
    source_tree_sha: str | None = None
    if head != "WORKTREE":
        requested_head_sha = git("rev-parse", head).strip()
        current_head_sha = git("rev-parse", "HEAD").strip()
        if requested_head_sha != current_head_sha:
            return fail(f"verify-change head mismatch: requested {requested_head_sha}, checked out {current_head_sha}")
        if git("status", "--porcelain", "--untracked-files=all").strip():
            return fail("verify-change exact head requires a clean worktree")
    else:
        source_head_sha = git("rev-parse", "HEAD").strip()
        source_tree_sha = worktree_tree_sha()

    paths = changed_paths(base, head)
    components = affected(base, head)
    records: list[dict] = []
    env = os.environ.copy()
    env.update({"BASE": base, "HEAD": head})

    def run_stable_gate(name: str, command: list[str]) -> bool:
        before_tree = worktree_tree_sha() if head == "WORKTREE" else ""
        ok = _run_gate(name, command, records, env)
        if head != "WORKTREE":
            return ok
        after_tree = worktree_tree_sha()
        if after_tree == before_tree:
            return ok
        mutated_paths = git("diff", "--name-only", before_tree, after_tree).splitlines()
        if records and records[-1].get("gate") == name:
            records[-1]["status"] = "FAIL"
            records[-1]["exit_code"] = 1
            records[-1]["reason"] = "gate mutated worktree"
            records[-1]["mutated_paths"] = mutated_paths
        print(f"FAIL {name} mutated worktree: {mutated_paths}", file=sys.stderr)
        return False

    parent_sha, parent_evidence = _incremental_parent_evidence(base, head)
    delta_components: set[str] = set()
    verification: dict = {"mode": "full"}
    if head == "WORKTREE":
        verification = {
            "mode": "worktree",
            "source_head_sha": source_head_sha,
            "source_tree_sha": source_tree_sha,
        }
    elif parent_sha and parent_evidence:
        delta_paths = changed_paths(parent_sha, head)
        delta_components = set(affected(parent_sha, head, strict_unknown=True))
        verification = {
            "mode": "incremental",
            "parent_sha": parent_sha,
            "delta_paths": delta_paths,
            "delta_components": sorted(delta_components),
        }
        print(f"INFO incremental verification from exact parent {parent_sha[:12]}")

    global_commands = _global_gate_commands(base, head)
    for name, command in global_commands:
        if not run_stable_gate(name, command):
            write_evidence(base, head, paths, components, records, verification)
            return 1

    combined = "frontend:storefront" in components and "frontend:admin" in components
    if combined:
        frontend_delta = bool({"frontend:storefront", "frontend:admin"} & delta_components)
        reused = bool(
            parent_evidence
            and parent_sha
            and not frontend_delta
            and _reuse_gate("frontend:all", parent_sha, parent_evidence, records)
        )
        if not reused and not _run_gate("frontend:all", _controller_command("frontend", "check", "all"), records, env):
            write_evidence(base, head, paths, components, records, verification)
            return 1

    for component in components:
        if component == "global" or (combined and component.startswith("frontend:")):
            continue
        command, skip_reason = _component_command(component)
        if command is None:
            records.append({"gate": component, "status": "SKIP", "reason": skip_reason, "duration_seconds": 0.0})
            continue
        if parent_evidence and parent_sha and component not in delta_components:
            if _reuse_gate(component, parent_sha, parent_evidence, records):
                continue
        if not run_stable_gate(component, command):
            write_evidence(base, head, paths, components, records, verification)
            return 1

    if head == "WORKTREE":
        final_tree_sha = worktree_tree_sha()
        verification["final_tree_sha"] = final_tree_sha
        verification["tree_stable"] = final_tree_sha == source_tree_sha
        if final_tree_sha != source_tree_sha:
            records.append(
                {
                    "gate": "worktree-stability",
                    "status": "FAIL",
                    "exit_code": 1,
                    "duration_seconds": 0.0,
                    "reason": "tracked/untracked commit tree changed during verification",
                }
            )
            write_evidence(base, head, paths, components, records, verification)
            return fail("worktree changed during verification; evidence is not promotable", 1)

    ev = write_evidence(base, head, paths, components, records, verification)
    if head != "WORKTREE" and git("status", "--porcelain", "--untracked-files=all").strip():
        return fail(f"exact evidence requires a clean tree: {ev.relative_to(ROOT)}", 2)
    return 0


def diff_context(base: str) -> int:
    CONTEXT.mkdir(exist_ok=True)
    paths = changed_paths(base, "WORKTREE")
    stat = git("diff", "--stat", base)
    diff = git("diff", "--unified=2", base, "--")
    out = CONTEXT / "diff.md"
    out.write_text(
        "# Diff context\n\n## Files\n"
        + "\n".join(f"- `{p}`" for p in paths)
        + "\n\n## Stat\n```text\n"
        + stat[:12000]
        + "\n```\n\n## Diff\n```diff\n"
        + diff[:28000]
        + "\n```\n",
        encoding="utf-8",
    )
    print(out.relative_to(ROOT))
    return 0


def failure_context(gate: str, component: str) -> int:
    if component:
        if component.startswith("service:"):
            cmd = [sys.executable, "scripts/repoctl.py", "service", component.split(":", 1)[1]]
        elif component.startswith("frontend:"):
            cmd = [sys.executable, "scripts/repoctl.py", "frontend", "check", component.split(":", 1)[1]]
        elif component == "platform:terraform":
            cmd = [sys.executable, "scripts/repoctl.py", "terraform"]
        elif component == "platform:ansible":
            cmd = [sys.executable, "scripts/repoctl.py", "ansible"]
        else:
            return fail(f"unsupported COMPONENT: {component}")
        name = component.replace(":", "-")
    else:
        allowed = {
            "governance",
            "runtime-efficiency",
            "contracts",
            "lint",
            "test",
            "security",
            "terraform",
            "ansible",
            "system",
            "automation-policy",
        }
        if gate not in allowed:
            return fail(f"unsupported GATE: {gate}")
        cmd = [sys.executable, "scripts/repoctl.py", gate]
        name = gate
    p = run(cmd, check=False, capture=True)
    text = (p.stdout or "") + (p.stderr or "")
    lines = text.splitlines()
    keywords = re.compile(r"FAIL|FAILED|ERROR|error:|fatal:|panic:|cannot use|undefined|make: \*\*\*", re.I)
    hits = [i for i, line in enumerate(lines) if keywords.search(line)]
    chosen: set[int] = set()
    for i in hits:
        chosen.update(range(max(0, i - 3), min(len(lines), i + 4)))
    relevant = [lines[i] for i in sorted(chosen)] if chosen else lines[-120:]
    CONTEXT.mkdir(exist_ok=True)
    path = CONTEXT / f"failure-{name}.md"
    path.write_text(
        f"# Failure context\nGATE: {name}\nSTATUS: {'PASS' if p.returncode == 0 else 'FAIL'}\nEXIT_CODE: {p.returncode}\n\n## Relevant output\n```text\n"
        + "\n".join(relevant[:220])
        + "\n```\n",
        encoding="utf-8",
    )
    print(path.relative_to(ROOT))
    return p.returncode


def doctor() -> int:
    expected = [
        "git",
        "make",
        "go",
        "gofmt",
        "python3",
        "pipx",
        "pre-commit",
        "ansible",
        "ansible-lint",
        "molecule",
        "terraform",
        "tflint",
        "trivy",
        "checkov",
        "gitleaks",
        "ggshield",
        "semgrep",
        "syft",
        "cosign",
        "oras",
        "rg",
        "fd",
        "yq",
        "ast-grep",
        "kubeconform",
        "conftest",
        "opa",
        "kubectl",
        "helm",
        "kustomize",
        "docker",
        "bazel",
        "bazelisk",
        "nx",
        "oasdiff",
        "oapi-codegen",
        "oxlint",
        "oxfmt",
        "ruff",
    ]
    rc = 0
    for cmd in expected:
        path = shutil.which(cmd)
        print(f"{'PASS' if path else 'FAIL'} {cmd:24} {path or 'missing'}")
        rc |= 0 if path else 1
    if shutil.which("docker") and run(["docker", "info"], check=False, capture=True).returncode == 0:
        print("PASS docker-daemon reachable")
    else:
        print("FAIL docker-daemon unreachable")
        rc = 1
    rc |= ansible_collections_check()
    return rc


def git_sync() -> int:
    branch = git("branch", "--show-current").strip()
    if not branch:
        return fail("git-sync detached HEAD")
    if git("status", "--porcelain", "--untracked-files=all").strip():
        return fail("git-sync requires clean tree")
    run(["git", "fetch", "origin", "--prune"])
    run(["git", "merge", "--ff-only", f"origin/{branch}"])
    print(f"PASS git-sync {branch}")
    return 0


def publish(base: str, message: str) -> int:
    branch = git("branch", "--show-current").strip()
    if not branch or branch in {"main", "master"}:
        return fail("publish refuses detached/default branch")
    run(["git", "fetch", "origin", "--prune"])
    base_ref = base if base.startswith("origin/") else f"origin/{base}"
    if run(["git", "merge-base", "--is-ancestor", base_ref, "HEAD"], check=False).returncode:
        return fail(f"branch is not based on current {base_ref}")

    dirty = bool(git("status", "--porcelain", "--untracked-files=all").strip())
    promotable = _load_promotable_worktree_evidence(base_ref) if dirty else None
    if dirty:
        if not message:
            return fail("dirty tree requires MSG/TITLE")
        if promotable:
            print("INFO exact worktree PASS matches current parent/base/tree; commit will attempt evidence promotion")
        else:
            print("INFO no promotable worktree evidence; exact-SHA verification will run after commit")
        run(["git", "add", "-A"])
        commit_env = os.environ.copy()
        commit_env["SKIP"] = ",".join(filter(None, [commit_env.get("SKIP", ""), "affected-precommit"]))
        run(["git", "commit", "-m", message], env=commit_env)

    head = git("rev-parse", "HEAD").strip()
    exact_evidence: Path | None = None
    if promotable is not None:
        exact_evidence = _promote_worktree_evidence(base_ref, head, promotable)
        if exact_evidence is None:
            print("INFO worktree evidence promotion invariants changed; falling back to exact-SHA verification")
    if exact_evidence is None:
        exact_evidence = _valid_exact_evidence(base_ref, head)
        if exact_evidence is not None:
            print(f"PASS publish: reusing existing exact evidence {exact_evidence.relative_to(ROOT)}")
    if exact_evidence is None and verify_change(base_ref, head):
        return 1

    run(["git", "push", "-u", "origin", "HEAD"])
    print(f"PASS publish: pushed {branch} at {head} without force")
    return 0


def deliver(base: str, title: str, message: str) -> int:
    deliver_started = time.monotonic()
    review_policy = ruby_yaml("config/contracts/review-policy.yaml")
    review_forge = (review_policy.get("pull_request_review") or {}).get("forge")
    if review_forge != "github":
        return fail(f"review-policy forge must be github for delivery; got {review_forge!r}")
    if publish(base, message or title):
        return 1
    gh = shutil.which("gh") or shutil.which("gh.exe")
    if not gh:
        return fail("GitHub CLI missing")
    branch = git("branch", "--show-current").strip()
    head = git("rev-parse", "HEAD").strip()
    evidence = CONTEXT / "evidence" / f"{head}.json"
    if not evidence.is_file():
        return fail(f"exact evidence missing for {head}")
    if not title:
        title = git("log", "-1", "--pretty=%s").strip()
    changed = (
        git("diff", "--name-only", f"origin/{base}...HEAD")
        if not base.startswith("origin/")
        else git("diff", "--name-only", f"{base}...HEAD")
    )
    stat = (
        git("diff", "--stat", f"origin/{base}...HEAD")
        if not base.startswith("origin/")
        else git("diff", "--stat", f"{base}...HEAD")
    )
    ev = json.loads(evidence.read_text(encoding="utf-8"))
    metrics = ev.get("metrics") or evidence_metrics(ev.get("gates", []))
    remote_ci = github_exact_ci_status(gh, head)
    body = CONTEXT / "pr-body.md"
    body.parent.mkdir(exist_ok=True)

    def gate_source(gate: dict) -> str:
        if gate.get("promoted_from_worktree"):
            return "promoted from validated worktree tree"
        if gate.get("reused_from_sha"):
            return f"reused `{gate['reused_from_sha'][:12]}`"
        if gate.get("status") == "SKIP":
            return gate.get("reason", "not applicable")
        return "executed"

    rows = "\n".join(
        f"| `{g['gate']}` | {g['status']} | {g.get('duration_seconds', 0)} | {gate_source(g)} |" for g in ev["gates"]
    )
    body.write_text(
        f"## Summary\n\n{title}\n\n## Scope\n\n```text\n{changed}```\n\n## Diff stat\n\n```text\n{stat}```\n\n## Deterministic validation\n\n| Gate | Status | Duration (s) | Source |\n| --- | --- | ---: | --- |\n{rows}\n\n## Review evidence\n\n- Base: `{base}` / `{ev['base_sha']}`\n- Head branch: `{branch}`\n- Head SHA: `{head}`\n- Verification mode: `{ev.get('verification', {}).get('mode', 'full')}`\n- Exact commit evidence cache: `.context/evidence/{head}.json` (not committed)\n- Executed gates: {metrics.get('executed_gates', 0)}\n- Reused gates: {metrics.get('reused_gates', 0)}\n- Gate execution time: {metrics.get('executed_seconds', 0)} s\n- Estimated reused time: {metrics.get('estimated_saved_seconds', 0)} s\n- Remote CI exact SHA: {remote_ci}\n\n## Safety\n\nThis automation creates or refreshes the pull request only. It does not approve, merge, force-push, bypass branch protection, or mutate infrastructure.\n",
        encoding="utf-8",
    )
    existing = output(
        [
            gh,
            "pr",
            "list",
            "--head",
            branch,
            "--base",
            base.replace("origin/", ""),
            "--state",
            "open",
            "--json",
            "number,url",
            "--jq",
            '.[0] | select(.) | "\\(.number) \\(.url)"',
        ]
    ).strip()
    if existing:
        num, url = existing.split(" ", 1)
        run(
            [
                gh,
                "api",
                "--method",
                "PATCH",
                f"repos/{{owner}}/{{repo}}/pulls/{num}",
                "--raw-field",
                f"title={title}",
                "--raw-field",
                f"body={body.read_text(encoding='utf-8')}",
            ]
        )
        actual = output([gh, "api", f"repos/{{owner}}/{{repo}}/pulls/{num}", "--jq", ".head.sha"]).strip()
        if actual != head:
            return fail(f"PR head mismatch: expected {head}, got {actual}")
        _record_delivery_wall(evidence, ev, deliver_started)
        print(f"PASS deliver: refreshed PR {url} at {head}")
        return 0
    p = run(
        [
            gh,
            "pr",
            "create",
            "--base",
            base.replace("origin/", ""),
            "--head",
            branch,
            "--title",
            title,
            "--body-file",
            str(body),
        ],
        capture=True,
    )
    _record_delivery_wall(evidence, ev, deliver_started)
    print(f"PASS deliver: created PR {p.stdout.strip()} at {head}")
    return 0


def precommit() -> int:
    return verify_change("HEAD", "WORKTREE")


def prepush() -> int:
    head = git("rev-parse", "HEAD").strip()
    ev = CONTEXT / "evidence" / f"{head}.json"
    base_sha = git("rev-parse", "origin/main").strip()
    if ev.is_file():
        data = json.loads(ev.read_text(encoding="utf-8"))
        if (
            data.get("status") == "PASS"
            and data.get("exact_commit_evidence") is True
            and data.get("head_sha") == head
            and data.get("base_sha") == base_sha
        ):
            print(f"PASS prepush: reusing exact evidence {ev.relative_to(ROOT)} for base {base_sha}")
            return 0
    return verify_change("origin/main", head)


def tekton_trigger_readiness_command(runtime_config: str, evidence: str) -> int:
    """Run live trigger prerequisite checks without mutating Kubernetes state."""
    if not runtime_config.strip():
        return fail("tekton-trigger-readiness requires RUNTIME_CONFIG/--runtime-config")
    from tekton_trigger_readiness import run_readiness

    return run_readiness(ROOT, ruby_yaml(runtime_config), Path(evidence))


def main() -> int:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in [
        "governance",
        "runtime-efficiency",
        "automation-policy",
        "lint",
        "test",
        "security",
        "terraform",
        "ansible",
        "system",
        "doctor",
        "git-sync",
        "precommit",
        "prepush",
    ]:
        sub.add_parser(name)
    c = sub.add_parser("contracts")
    c.add_argument("--base", default=os.environ.get("BASE", ""))
    c.add_argument("--head", default=os.environ.get("HEAD", "WORKTREE"))
    c.add_argument("--generate", action="store_true")
    f = sub.add_parser("frontend")
    f.add_argument("action")
    f.add_argument("scope")
    s = sub.add_parser("service")
    s.add_argument("service")
    a = sub.add_parser("affected")
    a.add_argument("--base", default=os.environ.get("BASE", "origin/main"))
    a.add_argument("--head", default=os.environ.get("HEAD", "WORKTREE"))
    a.add_argument("--json", action="store_true")
    v = sub.add_parser("verify-change")
    v.add_argument("--base", default=os.environ.get("BASE", "origin/main"))
    v.add_argument("--head", default=os.environ.get("HEAD", "WORKTREE"))
    d = sub.add_parser("diff-context")
    d.add_argument("--base", default=os.environ.get("BASE", "origin/main"))
    fc = sub.add_parser("failure-context")
    fc.add_argument("--gate", default=os.environ.get("GATE", ""))
    fc.add_argument("--component", default=os.environ.get("COMPONENT", ""))
    ctx = sub.add_parser("context")
    ctx.add_argument("task", nargs="?", default="")
    gen = sub.add_parser("api-generate")
    gen.add_argument("--target", default="all")
    gen.add_argument("--service", default="")
    gen.add_argument("--check", action="store_true")
    mock = sub.add_parser("api-mock")
    mock.add_argument("--service", default="product")
    mock.add_argument("--port", type=int, default=4010)
    nx = sub.add_parser("nx-graph")
    sg = sub.add_parser("service-new")
    sg.add_argument("--service", required=True)
    sg.add_argument("--dry-run", action="store_true")
    pub = sub.add_parser("publish")
    pub.add_argument("--base", default=os.environ.get("BASE", "origin/main"))
    pub.add_argument("--message", default=os.environ.get("MSG", ""))
    dlv = sub.add_parser("deliver")
    dlv.add_argument("--base", default=os.environ.get("BASE", "main"))
    dlv.add_argument("--title", default=os.environ.get("TITLE", ""))
    dlv.add_argument("--message", default=os.environ.get("MSG", ""))
    bdlv = sub.add_parser("bundle-deliver")
    bdlv.add_argument("--bundle", required=True)
    bdlv.add_argument("--expected-head", required=True)
    bdlv.add_argument("--title", required=True)
    bdlv.add_argument("--base", default=os.environ.get("BASE", "main"))
    trr = sub.add_parser("tekton-trigger-readiness")
    trr.add_argument("--runtime-config", required=True)
    trr.add_argument(
        "--evidence",
        default=os.environ.get("TEKTON_TRIGGER_READINESS_EVIDENCE", ".context/runtime/tekton-trigger-readiness.json"),
    )
    tp = sub.add_parser("tekton-plan")
    tp.add_argument("--base", required=True)
    tp.add_argument("--head", required=True)
    tp.add_argument("--record-dir", required=True)
    tp.add_argument("--result-path", required=True)
    cg = sub.add_parser("ci-global")
    cg.add_argument("--base", required=True)
    cg.add_argument("--head", required=True)
    cg.add_argument("--record-dir", required=True)
    cc = sub.add_parser("ci-component")
    cc.add_argument("--component", required=True)
    cc.add_argument("--base", required=True)
    cc.add_argument("--head", required=True)
    cc.add_argument("--record-dir", required=True)
    cf = sub.add_parser("ci-finalize")
    cf.add_argument("--base", required=True)
    cf.add_argument("--head", required=True)
    cf.add_argument("--record-dir", required=True)
    ep = sub.add_parser("evidence-publish")
    ep.add_argument("--path", required=True)
    ef = sub.add_parser("evidence-fetch")
    ef.add_argument("--sha", required=True)
    ec = sub.add_parser("evidence-compare")
    ec.add_argument("--full", required=True)
    ec.add_argument("--incremental", required=True)
    args = p.parse_args()
    try:
        if args.cmd == "governance":
            return governance()
        if args.cmd == "runtime-efficiency":
            return runtime_efficiency_check()
        if args.cmd == "contracts":
            return contracts(args.base, args.head, args.generate)
        if args.cmd == "automation-policy":
            return automation_policy()
        if args.cmd == "lint":
            return lint_all()
        if args.cmd == "test":
            return test_all()
        if args.cmd == "security":
            return security()
        if args.cmd == "terraform":
            return terraform_check()
        if args.cmd == "ansible":
            return ansible_check()
        if args.cmd == "system":
            return system_check()
        if args.cmd == "frontend":
            return frontend(args.action, args.scope)
        if args.cmd == "service":
            return service_check(args.service)
        if args.cmd == "affected":
            comps = affected(args.base, args.head)
            print(json.dumps(comps) if args.json else "\n".join(comps))
            return 0
        if args.cmd == "verify-change":
            return verify_change(args.base, args.head)
        if args.cmd == "diff-context":
            return diff_context(args.base)
        if args.cmd == "failure-context":
            return failure_context(args.gate, args.component)
        if args.cmd == "context":
            return run(
                [sys.executable, "scripts/context-pack.py", "--task", args.task], check=False
            ).returncode
        if args.cmd == "api-generate":
            return api_generate(args.target, args.service, args.check)
        if args.cmd == "api-mock":
            spec = (
                ruby_yaml("config/contracts/public-api-contracts.yaml")
                .get("contracts", {})
                .get(args.service, {})
                .get("path")
            )
            if not spec:
                return fail(f"api-mock service not registered: {args.service}")
            env = os.environ.copy()
            env["SCARF_ANALYTICS"] = "false"
            return run(
                [
                    "corepack",
                    "pnpm",
                    "exec",
                    "prism",
                    "mock",
                    f"../{spec}",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(args.port),
                    "--dynamic",
                ],
                cwd=ROOT / "frontend",
                env=env,
            ).returncode
        if args.cmd == "nx-graph":
            materialize = run([sys.executable, "scripts/nx-graph.py"], check=False)
            if materialize.returncode:
                return materialize.returncode
            out = ROOT / ".context/nx-workspace"
            return run(
                ["nx", "graph", "--file", str(ROOT / ".context/nx-graph.html"), "--focus", "frontend-admin"], cwd=out
            ).returncode
        if args.cmd == "service-new":
            cmd = [sys.executable, "scripts/servicegen.py", "--service", args.service] + (
                ["--dry-run"] if args.dry_run else []
            )
            return run(cmd, check=False).returncode
        if args.cmd == "doctor":
            return doctor()
        if args.cmd == "git-sync":
            return git_sync()
        if args.cmd == "publish":
            return publish(args.base, args.message)
        if args.cmd == "deliver":
            return deliver(args.base, args.title, args.message)
        if args.cmd == "bundle-deliver":
            return isolated_bundle_deliver(
                ROOT, Path(__file__).resolve(), args.bundle, args.expected_head, args.title, args.base, sys.executable
            )
        if args.cmd == "tekton-trigger-readiness":
            return tekton_trigger_readiness_command(args.runtime_config, args.evidence)
        if args.cmd == "tekton-plan":
            return tekton_plan(args.base, args.head, args.record_dir, args.result_path)
        if args.cmd == "ci-global":
            return ci_global(args.base, args.head, args.record_dir)
        if args.cmd == "ci-component":
            return ci_component(args.component, args.base, args.head, args.record_dir)
        if args.cmd == "ci-finalize":
            return ci_finalize(args.base, args.head, args.record_dir)
        if args.cmd == "evidence-publish":
            return evidence_publish_command(args.path)
        if args.cmd == "evidence-fetch":
            return evidence_fetch_command(args.sha)
        if args.cmd == "evidence-compare":
            return evidence_compare_command(args.full, args.incremental)
        if args.cmd == "precommit":
            return precommit()
        if args.cmd == "prepush":
            return prepush()
    except MissingRunnerPrerequisite as exc:
        print(f"BLOCKED {exc}", file=sys.stderr)
        return 1
    except (RuntimeError, KeyError, ValueError, json.JSONDecodeError) as exc:
        return fail(str(exc), 1)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
