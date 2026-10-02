"""Deterministic credential boundary tests for PR-head qualification."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import qualification_isolation as isolation

_VALIDATOR_SOURCE = """
import json
import os
import sys
from pathlib import Path

if sys.argv[1:] != ["qualification-proof-validate-only", "--base", os.environ["BASE"]]:
    raise SystemExit(2)
if any(name in os.environ for name in (
    "GH_TOKEN", "GITHUB_TOKEN", "OPENAI_API_KEY",
    "CHATGPT_REVIEW_TRANSPORT_CREDENTIAL",
)):
    raise SystemExit(3)
if os.environ["HOME"] != "/tmp/qualification-home":
    raise SystemExit(4)
if Path(".context/local-services/credentials.json").exists():
    raise SystemExit(5)
if Path(".env").exists() or Path("/home/dev/.local/bin").exists():
    raise SystemExit(7)
if Path("/home/dev/.local/share/ecommerce-1").exists():
    raise SystemExit(8)
if "fixture-only" in Path(".git/config").read_text():
    raise SystemExit(9)
head = os.environ["HEAD"]
proof = json.loads((Path(".context/evidence") / f"{head}.json").read_text())
audit = json.loads((Path(".context/performance") / f"{head}.json").read_text())
if proof["gates"][0]["gate"] != "test-gate" or audit["head_sha"] != head:
    raise SystemExit(6)
Path(".context/validator-probe").write_text("ran")
"""


class QualificationIsolationTests(unittest.TestCase):
    BASE = "a" * 40
    HEAD = "b" * 40

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="qualification-isolation-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.target = self.root / "target"
        self.target.mkdir()
        (self.target / ".gitignore").write_text(
            ".context/\n.env\n.codex/\n.venv/\n", encoding="utf-8"
        )
        scripts = self.target / "scripts"
        scripts.mkdir()
        (scripts / "repository_delivery.py").write_text("# trusted fixture\\n")
        (scripts / "repoctl.py").write_text(_VALIDATOR_SOURCE, encoding="utf-8")
        subprocess.run(
            ["git", "init", "-q", str(self.target)],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(self.target), "add", ".gitignore", "scripts"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(self.target),
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-q",
                "-m",
                "fixture",
            ],
            check=True,
            capture_output=True,
        )
        self.BASE = self.HEAD = subprocess.check_output(
            ["git", "-C", str(self.target), "rev-parse", "HEAD"],
            text=True,
        ).strip()
        self.marker = self.target / "child-ran"

    def _require_outer_namespace(self) -> None:
        # The qualification launcher disables nested user namespaces. These
        # integration probes run in the outer deterministic suite; unit checks
        # remain active in the inner system gate.
        if os.environ.get("ECOMMERCE_QUALIFICATION_SANDBOX") == "1":
            self.skipTest("outer namespace probe runs before PR-head qualification")

    def _write_command(self) -> list[str]:
        return [
            sys.executable,
            "-I",
            "-c",
            "from pathlib import Path; Path('child-ran').write_text('ran')",
        ]

    def _run(
        self, command: list[str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        return isolation.run_isolated_qualification(
            command or self._write_command(),
            target_root=self.target,
            base_sha=self.BASE,
            head_sha=self.HEAD,
            force_full=True,
            capture=True,
        )

    def test_missing_pin_blocks_before_child(self) -> None:
        with (
            mock.patch.dict(os.environ, {}, clear=True),
            self.assertRaisesRegex(
                isolation.QualificationIsolationError, "not configured"
            ),
        ):
            self._run()
        self.assertFalse(self.marker.exists())

    def test_bad_digest_blocks_before_child(self) -> None:
        self._require_outer_namespace()
        bwrap = shutil.which("bwrap")
        if bwrap is None:
            self.skipTest("bubblewrap is unavailable")
        with (
            mock.patch.dict(
                os.environ,
                {
                    "ECOMMERCE_QUALIFICATION_BWRAP_PATH": str(Path(bwrap).resolve()),
                    "ECOMMERCE_QUALIFICATION_BWRAP_SHA256": "0" * 64,
                },
                clear=True,
            ),
            self.assertRaisesRegex(
                isolation.QualificationIsolationError, "digest differs"
            ),
        ):
            self._run()
        self.assertFalse(self.marker.exists())

    def test_real_namespace_hides_parent_identity_and_remounts_trust_ro(self) -> None:
        self._require_outer_namespace()
        bwrap = shutil.which("bwrap")
        if bwrap is None:
            self.skipTest("bubblewrap is unavailable")
        bwrap_path = Path(bwrap).resolve()
        digest = hashlib.sha256(bwrap_path.read_bytes()).hexdigest()

        trusted = self._make_trusted_clone()
        scripts = trusted / "scripts"
        wrapper = scripts / "repository_delivery.py"
        controller = scripts / "repoctl.py"
        wrapper.write_text("# verified fixture\\n", encoding="utf-8")
        controller.write_text(
            "# qualification-proof-validate-only availability fixture\\n",
            encoding="utf-8",
        )
        local_services = self.target / ".context/local-services"
        (local_services / "tls").mkdir(parents=True, exist_ok=True)
        (local_services / "data/secret").mkdir(parents=True)
        (local_services / "credentials.json").write_text(
            '{"token":"fixture-only"}', encoding="utf-8"
        )
        (local_services / "tls/service.key").write_text(
            "fixture-only", encoding="utf-8"
        )
        (local_services / "data/secret/value").write_text(
            "fixture-only", encoding="utf-8"
        )
        git_dir = self.target / ".git"
        (git_dir / "config").write_text(
            '[remote "origin"]\n\turl = https://fixture-only@example.invalid/repo\n',
            encoding="utf-8",
        )
        for hidden_dir, hidden_file in (
            ("hooks", "post-checkout"),
            ("info", "exclude"),
            ("logs", "HEAD"),
        ):
            directory = git_dir / hidden_dir
            directory.mkdir(exist_ok=True)
            (directory / hidden_file).write_text("fixture-only", encoding="utf-8")
        (git_dir / "FETCH_HEAD").write_text("fixture-only", encoding="utf-8")
        (self.target / ".env").write_text("fixture-only", encoding="utf-8")
        self.assertEqual(
            0,
            subprocess.run(
                ["git", "-C", str(self.target), "check-ignore", "-q", ".env"],
                check=False,
            ).returncode,
        )
        with tempfile.NamedTemporaryFile(
            prefix=".qualification-isolation-canary-",
            dir="/home/dev/.local/bin",
            delete=False,
        ) as tool_fixture:
            tool_fixture.write(b"fixture-only")
        self.addCleanup(Path(tool_fixture.name).unlink)
        codex_dir = self.target / ".codex"
        codex_dir.mkdir()
        (codex_dir / "config.toml").write_text(
            'token = "fixture-only"\n', encoding="utf-8"
        )

        owner_home = self.root / "owner-home"
        gh_dir = owner_home / ".config/gh"
        gh_dir.mkdir(parents=True)
        (gh_dir / "hosts.yml").write_text(
            "oauth_token: fixture-only\n", encoding="utf-8"
        )

        # This parent is *started* with the canary. /proc/<pid>/environ does not
        # reliably reflect variables injected later through mock.patch.dict.
        child_code = r"""
import json
import os
import sys
from pathlib import Path

host_parent_pid, host_home, trusted_file = sys.argv[1:]
try:
    Path(trusted_file).write_text("tampered", encoding="utf-8")
    trusted_write_denied = False
except OSError:
    trusted_write_denied = True
try:
    Path("child-ran").write_text("ran", encoding="utf-8")
    target_write_denied = False
except OSError:
    target_write_denied = True
try:
    Path(".git/config").write_text("tampered", encoding="utf-8")
    git_config_write_denied = False
except OSError:
    git_config_write_denied = True
Path(".context/probe").write_text("ran", encoding="utf-8")
fd_secret_visible = False
fd_stage_path_visible = False
for process in ("self", "1"):
    try:
        descriptors = tuple(Path(f"/proc/{process}/fd").iterdir())
    except OSError:
        continue
    for descriptor in descriptors:
        try:
            link = os.readlink(descriptor)
        except OSError:
            continue
        if "ecommerce-qualification-context-" in link:
            fd_stage_path_visible = True
        for suffix in (
            ".context/local-services/credentials.json",
            "local-services/credentials.json",
        ):
            try:
                if b"fixture-only" in (descriptor / suffix).read_bytes():
                    fd_secret_visible = True
            except (OSError, ValueError):
                pass
try:
    proc_one = Path("/proc/1/environ").read_bytes()
except OSError:
    proc_one = b""
print(json.dumps({
    "canary_absent": "CANARY_CREDENTIAL" not in os.environ,
    "gh_token_absent": "GH_TOKEN" not in os.environ,
    "github_token_absent": "GITHUB_TOKEN" not in os.environ,
    "openai_token_absent": "OPENAI_API_KEY" not in os.environ,
    "gitea_token_absent": "GITEA_TOKEN" not in os.environ,
    "cosign_key_absent": "CI_EVIDENCE_COSIGN_KEY" not in os.environ,
    "ssh_agent_absent": "SSH_AUTH_SOCK" not in os.environ,
    "xdg_runtime_absent": "XDG_RUNTIME_DIR" not in os.environ,
    "transport_absent": not any(k.startswith("CHATGPT_REVIEW_") for k in os.environ),
    "sandbox_pin_absent": not any(
        k.startswith("ECOMMERCE_QUALIFICATION_BWRAP_") for k in os.environ
    ),
    "private_home": os.environ["HOME"] == "/tmp/qualification-home",
    "sandbox_marker": os.environ.get("ECOMMERCE_QUALIFICATION_SANDBOX") == "1",
    "private_gh_empty": not any(Path(os.environ["GH_CONFIG_DIR"]).iterdir()),
    "host_gh_config_not_selected": os.environ["GH_CONFIG_DIR"] != str(Path(host_home) / ".config/gh"),
    "host_home_hidden": not Path(host_home).exists(),
    "host_mnt_hidden": not Path("/mnt").exists(),
    "host_run_hidden": not Path("/run").exists(),
    "host_gh_hidden": not Path("/home/dev/.config/gh").exists(),
    "parent_proc_hidden": not Path(f"/proc/{host_parent_pid}/environ").exists(),
    "proc_one_canary_absent": b"fixture-only" not in proc_one,
    "trusted_write_denied": trusted_write_denied,
    "target_write_denied": target_write_denied,
    "git_config_write_denied": git_config_write_denied,
    "context_writable": Path(".context/probe").read_text() == "ran",
    "context_credentials_hidden": not Path(".context/local-services/credentials.json").exists(),
    "context_tls_key_hidden": not Path(".context/local-services/tls/service.key").exists(),
    "context_secret_data_hidden": not Path(".context/local-services/data/secret/value").exists(),
    "host_context_fd_hidden": not fd_secret_visible,
    "host_stage_fd_hidden": not fd_stage_path_visible,
    "git_inline_credential_hidden": "fixture-only" not in Path(".git/config").read_text(),
    "git_config_synthetic": "[core]" in Path(".git/config").read_text(),
    "git_hooks_hidden": not Path(".git/hooks/post-checkout").exists(),
    "git_info_hidden": not Path(".git/info/exclude").exists(),
    "git_logs_hidden": not Path(".git/logs/HEAD").exists(),
    "fetch_head_hidden": not Path(".git/FETCH_HEAD").exists(),
    "ignored_env_hidden": not Path(".env").exists(),
    "owner_tool_bin_hidden": not Path("/home/dev/.local/bin").exists(),
    "owner_tool_share_hidden": not Path("/home/dev/.local/share/ecommerce-1").exists(),
    "codex_config_hidden": not Path(".codex/config.toml").exists(),
    "host_etc_ssh_hidden": not Path("/etc/ssh").exists(),
    "network_namespace": Path("/proc/self/ns/net").readlink()
        != Path(f"/proc/{host_parent_pid}/ns/net").readlink()
        if Path(f"/proc/{host_parent_pid}/ns/net").exists() else True,
}, sort_keys=True))
"""
        helper_code = r"""
import importlib.util
import os
import sys
from pathlib import Path

module_path, target, base_sha, head_sha, home, controller, child_code = sys.argv[1:]
spec = importlib.util.spec_from_file_location("qualification_isolation", module_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
command = ["/usr/bin/python3", "-I", "-c", child_code, str(os.getpid()), home, controller]
result = module.run_isolated_qualification(
    command, target_root=Path(target), base_sha=base_sha, head_sha=head_sha,
    force_full=True, capture=True,
)
if result.stdout:
    print(result.stdout, end="")
if result.stderr:
    print(result.stderr, end="", file=sys.stderr)
raise SystemExit(result.returncode)
"""
        environment = {
            **os.environ,
            "ECOMMERCE_QUALIFICATION_BWRAP_PATH": str(bwrap_path),
            "ECOMMERCE_QUALIFICATION_BWRAP_SHA256": digest,
            "CANARY_CREDENTIAL": "fixture-only",
            "GH_TOKEN": "fixture-only",
            "GITHUB_TOKEN": "fixture-only",
            "OPENAI_API_KEY": "fixture-only",
            "GITEA_TOKEN": "fixture-only",
            "CI_EVIDENCE_COSIGN_KEY": "fixture-only",
            "SSH_AUTH_SOCK": str(owner_home / "agent.sock"),
            "XDG_RUNTIME_DIR": str(owner_home / "runtime"),
            "CHATGPT_REVIEW_TRANSPORT_CREDENTIAL": "fixture-only",
            "HOME": str(owner_home),
            "XDG_CONFIG_HOME": str(owner_home / ".config"),
            "GH_CONFIG_DIR": str(gh_dir),
            "REPOCTL_TRUSTED_WRAPPER": str(wrapper),
            "REPOCTL_TRUSTED_CONTROLLER": str(controller),
            "REPOCTL_TRUSTED_POLICY_ROOT": str(trusted),
            "REPOCTL_TRUSTED_TARGET_ROOT": str(self.target),
            "REPOCTL_TRUSTED_BASE_SHA": self.BASE,
            "REPOCTL_TRUSTED_HEAD_SHA": "c" * 40,
            "REPOCTL_TRUSTED_PR_NUMBER": "185",
        }
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                "-c",
                helper_code,
                str(ROOT / "scripts/qualification_isolation.py"),
                str(self.target),
                self.BASE,
                self.HEAD,
                str(owner_home),
                str(controller),
                child_code,
            ],
            cwd=self.target,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        observed = json.loads(completed.stdout)
        self.assertTrue(all(observed.values()), observed)
        self.assertIn(
            "qualification-proof-validate-only",
            controller.read_text(encoding="utf-8"),
        )
        self.assertFalse(self.marker.exists())
        self.assertFalse((self.target / ".context/probe").exists())
        self.assertEqual(
            '{"token":"fixture-only"}',
            (local_services / "credentials.json").read_text(encoding="utf-8"),
        )

    def test_setup_failure_is_authority_error_but_gate_failure_is_result(self) -> None:
        self._require_outer_namespace()
        bwrap = shutil.which("bwrap")
        if bwrap is None:
            self.skipTest("bubblewrap is unavailable")
        bwrap_path = Path(bwrap).resolve()
        digest = hashlib.sha256(bwrap_path.read_bytes()).hexdigest()
        pin = {
            "ECOMMERCE_QUALIFICATION_BWRAP_PATH": str(bwrap_path),
            "ECOMMERCE_QUALIFICATION_BWRAP_SHA256": digest,
        }
        original = isolation._sandbox_command

        def broken_mount(*args):
            command = original(*args)
            index = command.index("--chdir")
            return [
                *command[:index],
                "--ro-bind",
                str(self.root / "absent-source"),
                "/absent-destination",
                *command[index:],
            ]

        with (
            mock.patch.dict(os.environ, pin, clear=True),
            mock.patch.object(isolation, "_sandbox_command", side_effect=broken_mount),
            self.assertRaisesRegex(
                isolation.QualificationIsolationError, "did not start"
            ),
        ):
            self._run(
                [
                    "/usr/bin/python3",
                    "-c",
                    "from pathlib import Path; Path('child-ran').touch()",
                ]
            )
        self.assertFalse(self.marker.exists())

        with mock.patch.dict(os.environ, pin, clear=True):
            result = self._run(["/usr/bin/python3", "-c", "raise SystemExit(17)"])
        self.assertEqual(17, result.returncode)

    def test_checkout_venv_interpreter_is_rejected(self) -> None:
        interpreter = self.target / ".venv/qualification/bin/python3"
        interpreter.parent.mkdir(parents=True)
        interpreter.write_text("#!/bin/sh\\nexit 0\\n", encoding="ascii")
        interpreter.chmod(0o755)
        with self.assertRaisesRegex(
            isolation.QualificationIsolationError,
            "outside target checkout",
        ):
            isolation._verified_system_interpreter([str(interpreter)], self.target)
        self.assertEqual(
            "/usr/bin/python3",
            isolation._verified_system_interpreter(["/usr/bin/python3"], self.target),
        )

    def test_user_owned_sandbox_executable_is_rejected(self) -> None:
        command = self.root / "bwrap"
        command.write_text("#!/bin/sh\\nexit 0\\n", encoding="ascii")
        command.chmod(0o755)
        pin = {
            "ECOMMERCE_QUALIFICATION_BWRAP_PATH": str(command),
            "ECOMMERCE_QUALIFICATION_BWRAP_SHA256": hashlib.sha256(
                command.read_bytes()
            ).hexdigest(),
        }
        with (
            mock.patch.dict(os.environ, pin, clear=True),
            self.assertRaisesRegex(isolation.QualificationIsolationError, "root-owned"),
        ):
            self._run()
        self.assertFalse(self.marker.exists())

    def _make_trusted_clone(self) -> Path:
        trusted = self.target / ".context/trusted-base"
        trusted.mkdir(parents=True)
        shutil.copytree(self.target / ".git", trusted / ".git")
        shutil.copytree(self.target / "scripts", trusted / "scripts")
        shutil.copy2(self.target / ".gitignore", trusted / ".gitignore")
        return trusted

    def _trusted_pin(self) -> dict[str, str]:
        bwrap = shutil.which("bwrap")
        if bwrap is None:
            self.skipTest("bubblewrap is unavailable")
        path = Path(bwrap).resolve()
        trusted = self._make_trusted_clone()
        scripts = trusted / "scripts"
        wrapper = scripts / "repository_delivery.py"
        controller = scripts / "repoctl.py"
        local_services = self.target / ".context/local-services"
        local_services.mkdir(parents=True)
        (local_services / "credentials.json").write_text("fixture-only")
        (self.target / ".env").write_text("fixture-only", encoding="utf-8")
        (self.target / ".git/config").write_text(
            '[remote "origin"]\n\turl = https://fixture-only@example.invalid/repo\n',
            encoding="utf-8",
        )
        return {
            "GH_TOKEN": "fixture-only",
            "GITHUB_TOKEN": "fixture-only",
            "OPENAI_API_KEY": "fixture-only",
            "CHATGPT_REVIEW_TRANSPORT_CREDENTIAL": "fixture-only",
            "ECOMMERCE_QUALIFICATION_BWRAP_PATH": str(path),
            "ECOMMERCE_QUALIFICATION_BWRAP_SHA256": hashlib.sha256(
                path.read_bytes()
            ).hexdigest(),
            "REPOCTL_TRUSTED_WRAPPER": str(wrapper),
            "REPOCTL_TRUSTED_CONTROLLER": str(controller),
            "REPOCTL_TRUSTED_POLICY_ROOT": str(scripts.parent),
            "REPOCTL_TRUSTED_PR_NUMBER": "185",
        }

    def _pair_command(self, evidence: dict, audit: dict) -> list[str]:
        child = """
import os
import sys
from pathlib import Path
if any(name in os.environ for name in (
    "GH_TOKEN", "GITHUB_TOKEN", "OPENAI_API_KEY",
    "CHATGPT_REVIEW_TRANSPORT_CREDENTIAL",
)):
    raise SystemExit(21)
if os.environ["HOME"] != "/tmp/qualification-home":
    raise SystemExit(22)
if Path(".context/local-services/credentials.json").exists():
    raise SystemExit(23)
if Path(".env").exists() or Path("/home/dev/.local/bin").exists():
    raise SystemExit(24)
if Path("/home/dev/.local/share/ecommerce-1").exists():
    raise SystemExit(25)
if "fixture-only" in Path(".git/config").read_text():
    raise SystemExit(26)
context = Path(".context")
for directory, data in (("evidence", sys.argv[2]), ("performance", sys.argv[3])):
    destination = context / directory
    destination.mkdir()
    (destination / (sys.argv[1] + ".json")).write_text(data)
(context / "unapproved-output").write_text("fixture-only")
"""
        return [
            "/usr/bin/python3",
            "-c",
            child,
            self.HEAD,
            json.dumps(evidence),
            json.dumps(audit),
        ]

    def _full_pair(self) -> tuple[dict, dict]:
        evidence = {
            "schema_version": 5,
            "evidence_kind": "exact_commit",
            "exact_commit_evidence": True,
            "status": "PASS",
            "base_ref": self.BASE,
            "base_sha": self.BASE,
            "head_ref": self.HEAD,
            "head_sha": self.HEAD,
            "head_tree_sha": "c" * 40,
            "qualification_identity": "d" * 64,
            "created_at_epoch": time.time(),
            "changed_paths": ["README.md"],
            "affected_components": ["global"],
            "gates": [
                {
                    "gate": "test-gate",
                    "status": "PASS",
                    "exit_code": 0,
                    "duration_seconds": 1.0,
                    "execution": "fresh",
                    "scope": "global",
                    "command": ["/usr/bin/true"],
                    "log": ".context/logs/test-gate.log",
                }
            ],
            "metrics": {"executed_gates": 1, "reused_gates": 0, "skipped_gates": 0},
            "verification": {
                "mode": "full",
                "execution_profile": "full",
                "runtime_scope": [],
                "execution_plan": [
                    {"gate": "test-gate", "scope": "global", "action": "run"}
                ],
            },
        }
        audit = {
            "schema_version": 1,
            "evidence_status": "PASS",
            "base_sha": self.BASE,
            "head_sha": self.HEAD,
            "verification_mode": "full",
            "inventory": {
                "executed_gates": 1,
                "reused_gates": 0,
                "skipped_gates": 0,
                "failed_gates": 0,
                "execution_counts": {"fresh": 1},
            },
            "safety": {
                "content_cache_authorizes_pass_reuse": False,
                "verdict_reuse_policy": "exact-direct-parent-only",
                "unknown_impact_behavior": "fail-closed/full-execution",
                "tekton_remains_ci_authority": True,
            },
            "critical_path": {},
            "amdahl_priorities": [],
            "cache_layers": [],
            "recommendations": [],
        }
        return evidence, audit

    def test_only_bound_exact_proof_and_audit_are_promoted(self) -> None:
        self._require_outer_namespace()
        pin = self._trusted_pin()
        evidence, audit = self._full_pair()
        with (
            mock.patch.dict(os.environ, pin, clear=True),
            mock.patch.object(
                isolation, "_git_exact_metadata", return_value=("c" * 40, ["README.md"])
            ),
        ):
            result = self._run(self._pair_command(evidence, audit))
        self.assertEqual(0, result.returncode, result.stderr)
        evidence_path = self.target / ".context/evidence" / f"{self.HEAD}.json"
        audit_path = self.target / ".context/performance" / f"{self.HEAD}.json"
        self.assertEqual(self.HEAD, json.loads(evidence_path.read_text())["head_sha"])
        self.assertEqual(self.HEAD, json.loads(audit_path.read_text())["head_sha"])
        self.assertFalse((self.target / ".context/unapproved-output").exists())
        receipt = result.qualification_isolation_receipt
        self.assertEqual(self.BASE, receipt["base_sha"])
        self.assertEqual(self.HEAD, receipt["head_sha"])
        self.assertEqual("c" * 40, receipt["head_tree_sha"])
        self.assertEqual(
            hashlib.sha256(evidence_path.read_bytes()).hexdigest(),
            receipt["evidence_sha256"],
        )
        self.assertEqual(
            hashlib.sha256(audit_path.read_bytes()).hexdigest(), receipt["audit_sha256"]
        )
        self.assertTrue(receipt["namespace_witness"])
        self.assertTrue(receipt["validator_namespace_witness"])
        self.assertGreater(receipt["validator_child_pid"], 0)
        self.assertEqual("trusted-base-validate-only-v1", receipt["validation"])
        self.assertFalse((self.target / ".context/validator-probe").exists())

    def test_fully_shaped_forgery_fails_trusted_second_pass(self) -> None:
        self._require_outer_namespace()
        pin = self._trusted_pin()
        evidence, audit = self._full_pair()
        evidence["gates"][0]["gate"] = "forged-gate"
        evidence["verification"]["execution_plan"][0]["gate"] = "forged-gate"
        original = isolation._run_sandbox_pass
        calls: list[list[str]] = []

        def observed(command: list[str], **kwargs):
            calls.append(command)
            return original(command, **kwargs)

        with (
            mock.patch.dict(os.environ, pin, clear=True),
            mock.patch.object(isolation, "_run_sandbox_pass", side_effect=observed),
            self.assertRaisesRegex(
                isolation.QualificationIsolationError,
                "trusted qualification proof validation failed",
            ),
        ):
            self._run(self._pair_command(evidence, audit))
        self.assertEqual(2, len(calls))
        self.assertEqual(calls[0][0], calls[1][0])
        self.assertEqual("-I", calls[1][1])
        self.assertIn("qualification-proof-validate-only", calls[1])
        self.assertFalse(
            (self.target / ".context/evidence" / f"{self.HEAD}.json").exists()
        )
        self.assertFalse(
            (self.target / ".context/performance" / f"{self.HEAD}.json").exists()
        )

    def test_old_trusted_base_fails_before_qualification(self) -> None:
        pin = self._trusted_pin()
        Path(pin["REPOCTL_TRUSTED_CONTROLLER"]).write_text("# old base\\n")
        with (
            mock.patch.dict(os.environ, pin, clear=True),
            self.assertRaisesRegex(
                isolation.QualificationIsolationError,
                "lacks validate-only capability",
            ),
        ):
            self._run(
                [
                    "/usr/bin/python3",
                    "-c",
                    "from pathlib import Path; Path('.context/ran').touch()",
                ]
            )
        self.assertFalse((self.target / ".context/ran").exists())

    def test_minimal_structure_rejected_without_nested_namespace(self) -> None:
        with self.assertRaises(isolation.QualificationIsolationError):
            isolation._validate_promotion_pair(
                {
                    "schema_version": 5,
                    "evidence_kind": "exact_commit",
                    "exact_commit_evidence": True,
                    "status": "PASS",
                    "base_sha": self.BASE,
                    "head_sha": self.HEAD,
                },
                {
                    "schema_version": 1,
                    "evidence_status": "PASS",
                    "base_sha": self.BASE,
                    "head_sha": self.HEAD,
                },
                base_sha=self.BASE,
                head_sha=self.HEAD,
                tree_sha="c" * 40,
                changed_paths=[],
                started_epoch=time.time(),
                force_full=True,
            )

    def test_minimal_synthetic_pass_is_not_promoted(self) -> None:
        self._require_outer_namespace()
        pin = self._trusted_pin()
        evidence = {
            "schema_version": 5,
            "evidence_kind": "exact_commit",
            "exact_commit_evidence": True,
            "status": "PASS",
            "base_sha": self.BASE,
            "head_sha": self.HEAD,
        }
        audit = {
            "schema_version": 1,
            "evidence_status": "PASS",
            "base_sha": self.BASE,
            "head_sha": self.HEAD,
        }
        with (
            mock.patch.dict(os.environ, pin, clear=True),
            mock.patch.object(
                isolation, "_git_exact_metadata", return_value=("c" * 40, ["README.md"])
            ),
            self.assertRaises(isolation.QualificationIsolationError),
        ):
            self._run(self._pair_command(evidence, audit))
        self.assertFalse(
            (self.target / ".context/evidence" / f"{self.HEAD}.json").exists()
        )
        self.assertFalse(
            (self.target / ".context/performance" / f"{self.HEAD}.json").exists()
        )

    def test_unbound_local_qualification_cannot_promote_proof(self) -> None:
        self._require_outer_namespace()
        pin = {
            key: value
            for key, value in self._trusted_pin().items()
            if not key.startswith("REPOCTL_TRUSTED_")
        }
        evidence = {"base_sha": self.BASE, "head_sha": self.HEAD}
        audit = {"base_sha": self.BASE, "head_sha": self.HEAD}
        with (
            mock.patch.dict(os.environ, pin, clear=True),
            self.assertRaisesRegex(
                isolation.QualificationIsolationError, "unbound local qualification"
            ),
        ):
            self._run(self._pair_command(evidence, audit))
        self.assertFalse(
            (self.target / ".context/evidence" / f"{self.HEAD}.json").exists()
        )

    def test_symlinked_staged_proof_is_rejected(self) -> None:
        self._require_outer_namespace()
        bwrap = shutil.which("bwrap")
        if bwrap is None:
            self.skipTest("bubblewrap is unavailable")
        bwrap_path = Path(bwrap).resolve()
        pin = {
            "ECOMMERCE_QUALIFICATION_BWRAP_PATH": str(bwrap_path),
            "ECOMMERCE_QUALIFICATION_BWRAP_SHA256": hashlib.sha256(
                bwrap_path.read_bytes()
            ).hexdigest(),
        }
        child = """
import json, os
from pathlib import Path
context = Path(".context")
evidence = context / "evidence"
audit = context / "performance"
evidence.mkdir()
audit.mkdir()
head = os.environ["HEAD"]
(audit / f"{head}.json").write_text(json.dumps({
    "schema_version": 1, "evidence_status": "PASS",
    "head_sha": head, "base_sha": os.environ["BASE"],
}))
(evidence / f"{head}.json").symlink_to(
    Path("..") / "performance" / f"{head}.json"
)
"""
        with (
            mock.patch.dict(os.environ, pin, clear=True),
            self.assertRaises(isolation.QualificationIsolationError),
        ):
            self._run(["/usr/bin/python3", "-c", child])
        self.assertFalse(
            (self.target / ".context/evidence" / f"{self.HEAD}.json").exists()
        )

    def test_trusted_binding_uses_requested_head(self) -> None:
        trusted = self.target / ".context/trusted-base"
        scripts = trusted / "scripts"
        scripts.mkdir(parents=True)
        wrapper = scripts / "repository_delivery.py"
        controller = scripts / "repoctl.py"
        wrapper.write_text("", encoding="utf-8")
        controller.write_text("", encoding="utf-8")
        with mock.patch.dict(
            os.environ,
            {
                "REPOCTL_TRUSTED_WRAPPER": str(wrapper),
                "REPOCTL_TRUSTED_CONTROLLER": str(controller),
                "REPOCTL_TRUSTED_POLICY_ROOT": str(trusted),
                "REPOCTL_TRUSTED_PR_NUMBER": "185",
                "REPOCTL_TRUSTED_HEAD_SHA": "c" * 40,
            },
            clear=True,
        ):
            mounted, child_env = isolation._trusted_checkout(
                self.target, self.BASE, self.HEAD
            )
        self.assertEqual(trusted, mounted)
        self.assertEqual(self.HEAD, child_env["REPOCTL_TRUSTED_HEAD_SHA"])
        self.assertEqual(self.BASE, child_env["REPOCTL_TRUSTED_BASE_SHA"])
        self.assertEqual(str(self.target), child_env["REPOCTL_TRUSTED_TARGET_ROOT"])


if __name__ == "__main__":
    unittest.main()
