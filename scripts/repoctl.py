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

ROOT = Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip())
os.environ["PATH"] = f"{Path.home() / '.local/bin'}:{os.environ.get('PATH', '')}"
CONTEXT = ROOT / ".context"


def fail(message: str, code: int = 2) -> int:
    print(f"FAIL {message}", file=sys.stderr)
    return code


def require(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise RuntimeError(f"required command missing: {name}")
    return path


def run(cmd: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None,
        check: bool = True, capture: bool = False) -> subprocess.CompletedProcess[str]:
    p = subprocess.run(cmd, cwd=cwd or ROOT, env=env, text=True,
                       stdout=subprocess.PIPE if capture else None,
                       stderr=subprocess.PIPE if capture else None)
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


def developer_state_ready(tags: str) -> bool:
    """Fast-path: avoid Ansible startup when requested local state is already exact."""
    wanted = {tag.strip() for tag in tags.split(",") if tag.strip()}
    pins = pinned_versions()
    if "node" in wanted:
        node = shutil.which("node"); corepack = shutil.which("corepack")
        if not node or not corepack:
            return False
        expected_node = (ROOT / "frontend" / ".node-version").read_text(encoding="utf-8").strip()
        got = run([node, "--version"], check=False, capture=True)
        if got.returncode or got.stdout.strip() != f"v{expected_node}":
            return False
    if "go" in wanted or "cgo" in wanted:
        go = shutil.which("go"); gofmt = shutil.which("gofmt")
        if not go or not gofmt:
            return False
        got = run([go, "version"], check=False, capture=True)
        if got.returncode or f"go{pins.get('GO_VERSION', '')}" not in got.stdout:
            return False
    if "cgo" in wanted and not shutil.which("cc"):
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


def governance() -> int:
    require("ruby")
    run(["ruby", "scripts/validate-architecture.rb"])
    run_ruby_tests(["tests/architecture_validator_test.rb", "tests/ci_authority_test.rb", "tests/ci_affected_test.rb"])
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
                raise RuntimeError(
                    f"service/common OpenAPI component collision at components/{group}/{key}"
                )

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


def api_generate(target: str = "all", service: str = "") -> int:
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
                out_dir = ROOT / "frontend" / "packages" / "api-client" / "src" / "generated"
                out_dir.mkdir(parents=True, exist_ok=True)
                generated = out_dir / f"{name}.ts"
                p = run(
                    ["corepack", "pnpm", "--dir", "frontend", "exec", "openapi-typescript", str(bundled_spec)],
                    capture=True,
                )
                generated.write_text(p.stdout, encoding="utf-8")
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
    with tempfile.TemporaryDirectory(prefix="ecommerce-oas-old-") as old_s, tempfile.TemporaryDirectory(prefix="ecommerce-oas-new-") as new_s:
        old = Path(old_s); new = Path(new_s)
        for tree, ref in ((old, base), (new, head)):
            if ref == "WORKTREE":
                shutil.copytree(ROOT / "contracts" / "openapi", tree / "contracts" / "openapi", dirs_exist_ok=True)
                (tree / "config" / "contracts").mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / "config" / "contracts" / "public-api-contracts.yaml", tree / "config" / "contracts" / "public-api-contracts.yaml")
            else:
                # git archive is binary; stream it directly to tar.
                proc1 = subprocess.Popen(["git", "archive", ref, "contracts/openapi", "config/contracts/public-api-contracts.yaml"], cwd=ROOT, stdout=subprocess.PIPE)
                proc2 = subprocess.run(["tar", "-x", "-C", str(tree)], stdin=proc1.stdout)
                if proc1.stdout: proc1.stdout.close()
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
        print("FAIL shell automation policy: repository *.sh files are forbidden after Ansible-first migration", file=sys.stderr)
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


def frontend(action: str, scope: str) -> int:
    if action not in {"check", "lint", "test", "build"} or scope not in {"all", "storefront", "admin"}:
        return fail("frontend usage: action={check|lint|test|build} scope={all|storefront|admin}")
    ensure_developer("node")
    require("node"); require("corepack")
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
        api_generate("ts")
    def pnpm(*args: str) -> None:
        run(["corepack", "pnpm", *args], cwd=ROOT / "frontend")
    if action in {"check", "lint"}:
        if scope == "all": pnpm("run", "lint")
        else: pnpm("exec", "eslint", f"apps/{scope}", "packages/ui", "packages/api-client")
    if action in {"check", "test", "build"}:
        if scope == "all": pnpm("run", "typecheck")
        else:
            pnpm("--filter", "@noma/ui", "typecheck"); pnpm("--filter", "@noma/api-client", "typecheck"); pnpm("--filter", f"@noma/{scope}", "typecheck")
    if action in {"check", "test"}:
        if scope == "all": pnpm("run", "test")
        else: pnpm("--filter", f"@noma/{scope}", "test")
    if action in {"check", "build"}:
        if scope == "all": pnpm("run", "build")
        else: pnpm("--filter", f"@noma/{scope}", "build")
    print(f"PASS frontend {scope} {action} checks completed")
    return 0


def ensure_developer(tags: str) -> None:
    if developer_state_ready(tags):
        return
    require("ansible-playbook")
    run(["ansible-playbook", "-i", "localhost,", "-c", "local", "platform/ansible/developer.yml",
         "-e", f"repo_root={ROOT}", "--tags", tags])
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
    env = os.environ.copy(); env["PATH"] = f"{Path.home() / '.local/bin'}:{env.get('PATH','')}"; env["CGO_ENABLED"] = "1"
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
            print(p.stdout, file=sys.stderr); return fail(f"gofmt required for {service}", 1)
    run(["go", "test", "-race", "./..."], cwd=module, env=env)
    if (module / "internal" / "infrastructure" / "postgres").is_dir():
        run(["go", "test", "-race", "-tags=integration", "./internal/infrastructure/postgres", "-count=1"], cwd=module, env=env)
    run(["go", "vet", "./..."], cwd=module, env=env)
    run(["go", "build", "./..."], cwd=module, env=env)
    print(f"PASS {service} service checks completed")
    return 0


def security() -> int:
    require("gitleaks")
    if run(["git", "rev-parse", "--verify", "HEAD"], check=False, capture=True).returncode == 0:
        run(["gitleaks", "git", "--config", ".gitleaks.toml", "--redact", "--no-banner", "."])
    else:
        run(["gitleaks", "dir", "--config", ".gitleaks.toml", "--redact", "--no-banner", "."])
    print("PASS secret scan completed")
    return 0


def terraform_check() -> int:
    tf_files = [p for p in ROOT.rglob("*.tf") if ".terraform" not in p.parts]
    if not tf_files:
        print("SKIP terraform: no Terraform files found"); return 0
    tool = shutil.which("tofu") or shutil.which("terraform")
    if not tool: return fail("Terraform sources exist but neither tofu nor terraform is installed")
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
    require("ansible-lint")
    files = sorted(str(p.relative_to(ROOT)) for p in (ROOT / "platform" / "ansible").rglob("*.yml"))
    files += sorted(str(p.relative_to(ROOT)) for p in (ROOT / "platform" / "ansible").rglob("*.yaml"))
    if not files: print("SKIP ansible: no Ansible files found"); return 0
    run(["ansible-lint", *files])
    run(["ansible-playbook", "-i", "localhost,", "-c", "local", "platform/ansible/developer.yml", "--syntax-check", "-e", f"repo_root={ROOT}"])
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
    if automation_policy(): return 1
    go_files = [str(p) for p in (ROOT / "services").rglob("*.go") if "vendor" not in p.parts]
    if go_files:
        require("gofmt")
        p = run(["gofmt", "-l", *go_files], capture=True)
        if p.stdout.strip(): print(p.stdout, file=sys.stderr); return 1
    if (ROOT / "frontend" / "package.json").is_file(): frontend("lint", "all")
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
    if (ROOT / "frontend" / "package.json").is_file(): frontend("test", "all")
    print("PASS test checks completed")
    return 0


def changed_paths(base: str, head: str) -> list[str]:
    if head == "WORKTREE":
        tracked = git("diff", "--name-only", "--diff-filter=ACMRTUXB", base, "--").splitlines()
        untracked = git("ls-files", "--others", "--exclude-standard").splitlines()
        return sorted(set(filter(None, tracked + untracked)))
    return sorted(set(filter(None, git("diff", "--name-only", "--diff-filter=ACMRTUXB", base, head, "--").splitlines())))


def affected(base: str, head: str) -> list[str]:
    p = run(["ruby", "scripts/ci-affected.rb", "--base", base, "--head", head, "--format", "json"], capture=True)
    return json.loads(p.stdout)


def _run_gate(name: str, command: list[str], records: list[dict], env: dict[str, str] | None = None) -> bool:
    logs = CONTEXT / "logs"; logs.mkdir(parents=True, exist_ok=True)
    log_path = logs / f"{name.replace(':','-').replace('/','-')}.log"
    start = time.monotonic()
    with log_path.open("w", encoding="utf-8") as log:
        p = subprocess.run(command, cwd=ROOT, env=env, text=True, stdout=log, stderr=subprocess.STDOUT)
    duration = round(time.monotonic() - start, 3)
    records.append({"gate": name, "status": "PASS" if p.returncode == 0 else "FAIL", "exit_code": p.returncode,
                    "duration_seconds": duration, "command": command, "log": str(log_path.relative_to(ROOT))})
    print(f"{'PASS' if p.returncode == 0 else 'FAIL'} {name} ({duration:.3f}s)")
    if p.returncode:
        print("\n".join(log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-60:]), file=sys.stderr)
    return p.returncode == 0


def write_evidence(base: str, head: str, paths: list[str], components: list[str], records: list[dict]) -> Path:
    base_sha = git("rev-parse", base).strip(); head_sha = git("rev-parse", "HEAD" if head == "WORKTREE" else head).strip()
    clean = not git("status", "--porcelain", "--untracked-files=all").strip()
    exact = head != "WORKTREE" and clean and head_sha == git("rev-parse", head).strip()
    payload = {"schema_version": 2, "base_ref": base, "base_sha": base_sha, "head_ref": head, "head_sha": head_sha,
               "exact_commit_evidence": exact, "status": "FAIL" if any(r["status"] == "FAIL" for r in records) else "PASS",
               "changed_paths": paths, "affected_components": components, "gates": records}
    identity = head_sha if head != "WORKTREE" else "worktree"
    destination = CONTEXT / "evidence" / f"{identity}.json"; destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"EVIDENCE {destination.relative_to(ROOT)}")
    return destination


def verify_change(base: str, head: str) -> int:
    paths = changed_paths(base, head); components = affected(base, head); records: list[dict] = []
    env = os.environ.copy(); env.update({"BASE": base, "HEAD": head})
    global_commands = [
        ("governance", [sys.executable, "scripts/repoctl.py", "governance"]),
        ("contracts", [sys.executable, "scripts/repoctl.py", "contracts", "--base", base, "--head", head]),
        ("automation", [sys.executable, "scripts/repoctl.py", "automation-policy"]),
        ("security", [sys.executable, "scripts/repoctl.py", "security"]),
    ]
    for name, command in global_commands:
        if not _run_gate(name, command, records, env): write_evidence(base, head, paths, components, records); return 1
    combined = "frontend:storefront" in components and "frontend:admin" in components
    if combined and not _run_gate("frontend:all", [sys.executable, "scripts/repoctl.py", "frontend", "check", "all"], records, env):
        write_evidence(base, head, paths, components, records); return 1
    for component in components:
        if component == "global" or (combined and component.startswith("frontend:")): continue
        if component.startswith("service:"):
            service = component.split(":", 1)[1]
            if not (ROOT / "services" / service / "go.mod").is_file():
                records.append({"gate": component, "status": "SKIP", "reason": "canonical service not implemented", "duration_seconds": 0.0}); continue
            command = [sys.executable, "scripts/repoctl.py", "service", service]
        elif component.startswith("frontend:"): command = [sys.executable, "scripts/repoctl.py", "frontend", "check", component.split(":",1)[1]]
        elif component == "platform:terraform": command = [sys.executable, "scripts/repoctl.py", "terraform"]
        elif component == "platform:ansible": command = [sys.executable, "scripts/repoctl.py", "ansible"]
        elif component == "system": command = [sys.executable, "scripts/repoctl.py", "system"]
        else: raise RuntimeError(f"unsupported affected component: {component}")
        if not _run_gate(component, command, records, env): write_evidence(base, head, paths, components, records); return 1
    ev = write_evidence(base, head, paths, components, records)
    if head != "WORKTREE" and git("status", "--porcelain", "--untracked-files=all").strip():
        return fail(f"exact evidence requires a clean tree: {ev.relative_to(ROOT)}", 2)
    return 0


def diff_context(base: str) -> int:
    CONTEXT.mkdir(exist_ok=True)
    paths = changed_paths(base, "WORKTREE")
    stat = git("diff", "--stat", base)
    diff = git("diff", "--unified=2", base, "--")
    out = CONTEXT / "diff.md"
    out.write_text("# Diff context\n\n## Files\n" + "\n".join(f"- `{p}`" for p in paths) + "\n\n## Stat\n```text\n" + stat[:12000] + "\n```\n\n## Diff\n```diff\n" + diff[:28000] + "\n```\n", encoding="utf-8")
    print(out.relative_to(ROOT)); return 0


def failure_context(gate: str, component: str) -> int:
    if component:
        if component.startswith("service:"): cmd = [sys.executable, "scripts/repoctl.py", "service", component.split(":",1)[1]]
        elif component.startswith("frontend:"): cmd = [sys.executable, "scripts/repoctl.py", "frontend", "check", component.split(":",1)[1]]
        elif component == "platform:terraform": cmd = [sys.executable, "scripts/repoctl.py", "terraform"]
        elif component == "platform:ansible": cmd = [sys.executable, "scripts/repoctl.py", "ansible"]
        else: return fail(f"unsupported COMPONENT: {component}")
        name = component.replace(":", "-")
    else:
        allowed = {"governance", "contracts", "lint", "test", "security", "terraform", "ansible", "system", "automation-policy"}
        if gate not in allowed: return fail(f"unsupported GATE: {gate}")
        cmd = [sys.executable, "scripts/repoctl.py", gate]; name = gate
    p = run(cmd, check=False, capture=True)
    text = (p.stdout or "") + (p.stderr or "")
    lines = text.splitlines(); keywords = re.compile(r"FAIL|FAILED|ERROR|error:|fatal:|panic:|cannot use|undefined|make: \*\*\*", re.I)
    hits = [i for i, line in enumerate(lines) if keywords.search(line)]
    chosen: set[int] = set()
    for i in hits: chosen.update(range(max(0, i-3), min(len(lines), i+4)))
    relevant = [lines[i] for i in sorted(chosen)] if chosen else lines[-120:]
    CONTEXT.mkdir(exist_ok=True); path = CONTEXT / f"failure-{name}.md"
    path.write_text(f"# Failure context\nGATE: {name}\nSTATUS: {'PASS' if p.returncode == 0 else 'FAIL'}\nEXIT_CODE: {p.returncode}\n\n## Relevant output\n```text\n" + "\n".join(relevant[:220]) + "\n```\n", encoding="utf-8")
    print(path.relative_to(ROOT)); return p.returncode


def doctor() -> int:
    expected = ["git","make","go","gofmt","python3","pipx","pre-commit","ansible","ansible-lint","molecule","terraform","tflint","trivy","checkov","gitleaks","ggshield","semgrep","syft","cosign","rg","fd","yq","ast-grep","kubeconform","conftest","opa","kubectl","helm","kustomize","docker","bazel","bazelisk","nx","oasdiff","oapi-codegen"]
    rc = 0
    for cmd in expected:
        path = shutil.which(cmd)
        print(f"{'PASS' if path else 'FAIL'} {cmd:24} {path or 'missing'}")
        rc |= 0 if path else 1
    if shutil.which("docker") and run(["docker","info"], check=False, capture=True).returncode == 0: print("PASS docker-daemon reachable")
    else: print("FAIL docker-daemon unreachable"); rc = 1
    return rc


def git_sync() -> int:
    branch = git("branch", "--show-current").strip()
    if not branch: return fail("git-sync detached HEAD")
    if git("status", "--porcelain", "--untracked-files=all").strip(): return fail("git-sync requires clean tree")
    run(["git","fetch","origin","--prune"])
    run(["git","merge","--ff-only",f"origin/{branch}"])
    print(f"PASS git-sync {branch}"); return 0


def publish(base: str, message: str) -> int:
    branch = git("branch","--show-current").strip()
    if not branch or branch in {"main","master"}: return fail("publish refuses detached/default branch")
    run(["git","fetch","origin","--prune"])
    base_ref = base if base.startswith("origin/") else f"origin/{base}"
    if run(["git","merge-base","--is-ancestor",base_ref,"HEAD"],check=False).returncode:
        return fail(f"branch is not based on current {base_ref}")
    if git("status","--porcelain","--untracked-files=all").strip():
        if not message: return fail("dirty tree requires MSG/TITLE")
        run(["git","add","-A"])
        commit_env = os.environ.copy()
        # publish performs the stronger exact-SHA affected gate immediately after
        # commit; avoid replaying the worktree pre-commit gate for the same change.
        commit_env["SKIP"] = ",".join(filter(None, [commit_env.get("SKIP", ""), "affected-precommit"]))
        run(["git","commit","-m",message], env=commit_env)
    head = git("rev-parse","HEAD").strip()
    if verify_change(base_ref, head): return 1
    run(["git","push","-u","origin","HEAD"])
    print(f"PASS publish: pushed {branch} at {head} without force"); return 0


def deliver(base: str, title: str, message: str) -> int:
    if publish(base, message or title): return 1
    gh = shutil.which("gh") or shutil.which("gh.exe")
    if not gh: return fail("GitHub CLI missing")
    branch = git("branch","--show-current").strip(); head = git("rev-parse","HEAD").strip()
    evidence = CONTEXT / "evidence" / f"{head}.json"
    if not evidence.is_file(): return fail(f"exact evidence missing for {head}")
    if not title: title = git("log","-1","--pretty=%s").strip()
    changed = git("diff","--name-only",f"origin/{base}...HEAD") if not base.startswith("origin/") else git("diff","--name-only",f"{base}...HEAD")
    stat = git("diff","--stat",f"origin/{base}...HEAD") if not base.startswith("origin/") else git("diff","--stat",f"{base}...HEAD")
    ev = json.loads(evidence.read_text(encoding="utf-8"))
    body = CONTEXT / "pr-body.md"; body.parent.mkdir(exist_ok=True)
    rows = "\n".join(f"| `{g['gate']}` | {g['status']} | {g.get('duration_seconds',0)} |" for g in ev["gates"])
    body.write_text(f"## Summary\n\n{title}\n\n## Scope\n\n```text\n{changed}```\n\n## Diff stat\n\n```text\n{stat}```\n\n## Deterministic validation\n\n| Gate | Status | Duration (s) |\n| --- | --- | ---: |\n{rows}\n\n## Review evidence\n\n- Base: `{base}` / `{ev['base_sha']}`\n- Head branch: `{branch}`\n- Head SHA: `{head}`\n- Exact commit evidence: `.context/evidence/{head}.json` (local generated artifact, not committed)\n\n## Safety\n\nThis automation creates or refreshes the pull request only. It does not approve, merge, force-push, bypass branch protection, or mutate infrastructure.\n", encoding="utf-8")
    existing = output([gh,"pr","list","--head",branch,"--base",base.replace("origin/",""),"--state","open","--json","number,url","--jq",'.[0] | select(.) | "\\(.number) \\(.url)"']).strip()
    if existing:
        num, url = existing.split(" ",1)
        run([gh,"api","--method","PATCH",f"repos/{{owner}}/{{repo}}/pulls/{num}","--raw-field",f"title={title}","--raw-field",f"body={body.read_text(encoding='utf-8')}"])
        actual = output([gh,"api",f"repos/{{owner}}/{{repo}}/pulls/{num}","--jq",".head.sha"]).strip()
        if actual != head: return fail(f"PR head mismatch: expected {head}, got {actual}")
        print(f"PASS deliver: refreshed PR {url} at {head}"); return 0
    p = run([gh,"pr","create","--base",base.replace("origin/",""),"--head",branch,"--title",title,"--body-file",str(body)],capture=True)
    print(f"PASS deliver: created PR {p.stdout.strip()} at {head}"); return 0


def precommit() -> int:
    return verify_change("HEAD", "WORKTREE")


def prepush() -> int:
    head = git("rev-parse","HEAD").strip(); ev = CONTEXT / "evidence" / f"{head}.json"
    base_sha = git("rev-parse", "origin/main").strip()
    if ev.is_file():
        data = json.loads(ev.read_text(encoding="utf-8"))
        if (data.get("status") == "PASS" and data.get("exact_commit_evidence") is True
                and data.get("head_sha") == head and data.get("base_sha") == base_sha):
            print(f"PASS prepush: reusing exact evidence {ev.relative_to(ROOT)} for base {base_sha}"); return 0
    return verify_change("origin/main", head)


def main() -> int:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ["governance","automation-policy","lint","test","security","terraform","ansible","system","doctor","git-sync","precommit","prepush"]: sub.add_parser(name)
    c = sub.add_parser("contracts"); c.add_argument("--base",default=os.environ.get("BASE","")); c.add_argument("--head",default=os.environ.get("HEAD","WORKTREE")); c.add_argument("--generate",action="store_true")
    f = sub.add_parser("frontend"); f.add_argument("action"); f.add_argument("scope")
    s = sub.add_parser("service"); s.add_argument("service")
    a = sub.add_parser("affected"); a.add_argument("--base",default=os.environ.get("BASE","origin/main")); a.add_argument("--head",default=os.environ.get("HEAD","WORKTREE")); a.add_argument("--json",action="store_true")
    v = sub.add_parser("verify-change"); v.add_argument("--base",default=os.environ.get("BASE","origin/main")); v.add_argument("--head",default=os.environ.get("HEAD","WORKTREE"))
    d = sub.add_parser("diff-context"); d.add_argument("--base",default=os.environ.get("BASE","origin/main"))
    fc = sub.add_parser("failure-context"); fc.add_argument("--gate",default=os.environ.get("GATE","")); fc.add_argument("--component",default=os.environ.get("COMPONENT",""))
    ctx = sub.add_parser("context"); ctx.add_argument("task",nargs="?",default="")
    gen = sub.add_parser("api-generate"); gen.add_argument("--target",default="all"); gen.add_argument("--service",default="")
    mock = sub.add_parser("api-mock"); mock.add_argument("--service",default="product"); mock.add_argument("--port",type=int,default=4010)
    nx = sub.add_parser("nx-graph")
    sg = sub.add_parser("service-new"); sg.add_argument("--service",required=True); sg.add_argument("--dry-run",action="store_true")
    pub = sub.add_parser("publish"); pub.add_argument("--base",default=os.environ.get("BASE","origin/main")); pub.add_argument("--message",default=os.environ.get("MSG",""))
    dlv = sub.add_parser("deliver"); dlv.add_argument("--base",default=os.environ.get("BASE","main")); dlv.add_argument("--title",default=os.environ.get("TITLE","")); dlv.add_argument("--message",default=os.environ.get("MSG",""))
    args = p.parse_args()
    try:
        if args.cmd == "governance": return governance()
        if args.cmd == "contracts": return contracts(args.base,args.head,args.generate)
        if args.cmd == "automation-policy": return automation_policy()
        if args.cmd == "lint": return lint_all()
        if args.cmd == "test": return test_all()
        if args.cmd == "security": return security()
        if args.cmd == "terraform": return terraform_check()
        if args.cmd == "ansible": return ansible_check()
        if args.cmd == "system": return system_check()
        if args.cmd == "frontend": return frontend(args.action,args.scope)
        if args.cmd == "service": return service_check(args.service)
        if args.cmd == "affected":
            comps=affected(args.base,args.head); print(json.dumps(comps) if args.json else "\n".join(comps)); return 0
        if args.cmd == "verify-change": return verify_change(args.base,args.head)
        if args.cmd == "diff-context": return diff_context(args.base)
        if args.cmd == "failure-context": return failure_context(args.gate,args.component)
        if args.cmd == "context": return run([sys.executable,"scripts/context-pack.py","--task",args.task]).returncode
        if args.cmd == "api-generate": return api_generate(args.target,args.service)
        if args.cmd == "api-mock":
            spec=ruby_yaml("config/contracts/public-api-contracts.yaml").get("contracts",{}).get(args.service,{}).get("path")
            if not spec: return fail(f"api-mock service not registered: {args.service}")
            env=os.environ.copy(); env["SCARF_ANALYTICS"]="false"
            return run(["corepack","pnpm","exec","prism","mock",f"../{spec}","--host","127.0.0.1","--port",str(args.port),"--dynamic"],cwd=ROOT/"frontend",env=env).returncode
        if args.cmd == "nx-graph":
            run([sys.executable,"scripts/nx-graph.py"]); out=ROOT/".context/nx-workspace"; return run(["nx","graph","--file",str(ROOT/".context/nx-graph.html"),"--focus","frontend-admin"],cwd=out).returncode
        if args.cmd == "service-new":
            cmd=[sys.executable,"scripts/servicegen.py","--service",args.service]+(["--dry-run"] if args.dry_run else []); return run(cmd,check=False).returncode
        if args.cmd == "doctor": return doctor()
        if args.cmd == "git-sync": return git_sync()
        if args.cmd == "publish": return publish(args.base,args.message)
        if args.cmd == "deliver": return deliver(args.base,args.title,args.message)
        if args.cmd == "precommit": return precommit()
        if args.cmd == "prepush": return prepush()
    except (RuntimeError, KeyError, ValueError, json.JSONDecodeError) as exc:
        return fail(str(exc),1)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
