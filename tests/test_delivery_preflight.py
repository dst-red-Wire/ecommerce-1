import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

from scripts import delivery_preflight as preflight

ROOT = Path(__file__).resolve().parents[1]


class DeliveryPreflightTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        environment = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("REPOCTL_TRUSTED_", "GIT_"))
        }
        patcher = mock.patch.dict(os.environ, environment, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.policy = yaml.safe_load(
            (ROOT / "config/contracts/qualification-execution-policy.yaml").read_text(
                encoding="utf-8"
            )
        )
        self.policy_path = (
            self.root / "config/contracts/qualification-execution-policy.yaml"
        )
        self.policy_path.parent.mkdir(parents=True)
        self.policy_path.write_text(yaml.safe_dump(self.policy), encoding="utf-8")
        (self.root / "source.txt").write_text("one\n", encoding="utf-8")
        (self.root / ".gitignore").write_text(".context/\n", encoding="utf-8")
        self.git("init", "-q")
        self.git("switch", "-q", "-c", "feat/test-preflight")
        self.git("add", ".")
        self.git(
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "fixture",
        )
        self.head = self.git("rev-parse", "HEAD")
        self.base = self.head
        self.git("update-ref", "refs/remotes/origin/main", self.base)
        self.branch = self.git("branch", "--show-current")

    def git(self, *args):
        return subprocess.run(
            ["git", *args],
            cwd=self.root,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()

    def run_preflight(self, capabilities=None, parameters=None, **changes):
        args = {
            "expected_head_sha": self.head,
            "expected_base_sha": self.base,
            "expected_branch": self.branch,
            "required_capabilities": capabilities or [],
            "capability_parameters": parameters or {},
        }
        args.update(changes)
        return preflight.run_preflight(self.root, **args)

    def bound_result(self, capabilities=None, parameters=None):
        result = self.run_preflight(capabilities, parameters)
        self.assertEqual("PASS", result["status"])
        result.update(
            work_package_id="wp-170",
            work_package_digest="sha256:" + "a" * 64,
            work_item_issue=170,
            milestone="M2.5",
        )
        return result

    def verify_persisted(self, capabilities=None):
        return preflight.verify_preflight(
            self.root,
            expected_head_sha=self.head,
            expected_base_sha=self.base,
            expected_branch=self.branch,
            expected_package_id="wp-170",
            expected_package_digest="sha256:" + "a" * 64,
            expected_issue=170,
            expected_milestone="M2.5",
            expected_capabilities=capabilities or [],
        )

    def rewrite_evidence(self, path, payload):
        unsigned = {
            key: value for key, value in payload.items() if key != "evidence_digest"
        }
        payload["evidence_digest"] = (
            "sha256:"
            + hashlib.sha256(
                json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode(
                    "utf-8"
                )
            ).hexdigest()
        )
        path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")

    def commit_policy(self, policy):
        self.policy_path.write_text(yaml.safe_dump(policy), encoding="utf-8")
        self.git("add", str(self.policy_path.relative_to(self.root)))
        self.git(
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "change policy",
        )
        self.head = self.git("rev-parse", "HEAD")

    def base_checkout(self):
        directory = self.root / ".context/trusted-base"
        directory.parent.mkdir(parents=True, exist_ok=True)
        self.git("worktree", "add", "--detach", "--quiet", str(directory), self.base)
        return directory

    def test_head_only_command_capability_is_rejected_before_any_probe(self):
        marker = self.root / ".context/HEAD_COMMAND_EXECUTED"
        policy = copy.deepcopy(self.policy)
        evil = copy.deepcopy(
            policy["runtime_orchestration"]["capabilities"]["ansible-runtime"]
        )
        evil["parameters"] = {"command": ["touch", str(marker)]}
        policy["runtime_orchestration"]["capabilities"]["evil"] = evil
        self.commit_policy(policy)
        base_root = self.base_checkout()
        with (
            mock.patch.dict(
                os.environ,
                {
                    "REPOCTL_TRUSTED_POLICY_ROOT": str(base_root),
                    "REPOCTL_TRUSTED_BASE_SHA": self.base,
                    "REPOCTL_TRUSTED_TARGET_ROOT": str(self.root),
                    "REPOCTL_TRUSTED_HEAD_SHA": self.head,
                },
            ),
            mock.patch.object(
                preflight.runtime.BuiltinCapabilityDriver, "capture"
            ) as capture,
        ):
            result = self.run_preflight(["evil"])
        self.assertEqual("FAIL", result["status"])
        self.assertIn("unknown required capability", result["reason"])
        capture.assert_not_called()
        self.assertFalse(marker.exists())
        self.assertEqual("", self.git("status", "--porcelain"))

    def test_cli_rejects_head_command_from_clean_git_checkout(self):
        marker = self.root / ".context/HEAD_COMMAND_EXECUTED"
        policy = copy.deepcopy(self.policy)
        evil = copy.deepcopy(
            policy["runtime_orchestration"]["capabilities"]["ansible-runtime"]
        )
        evil["parameters"] = {"command": ["touch", str(marker)]}
        policy["runtime_orchestration"]["capabilities"]["evil"] = evil
        self.commit_policy(policy)
        base_root = self.base_checkout()
        for trusted in (False, True):
            environment = dict(os.environ)
            if trusted:
                environment.update(
                    REPOCTL_TRUSTED_POLICY_ROOT=str(base_root),
                    REPOCTL_TRUSTED_BASE_SHA=self.base,
                    REPOCTL_TRUSTED_TARGET_ROOT=str(self.root),
                    REPOCTL_TRUSTED_HEAD_SHA=self.head,
                )
            with self.subTest(trusted=trusted):
                completed = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "scripts.delivery_preflight",
                        "--root",
                        str(self.root),
                        "--head-sha",
                        self.head,
                        "--base-sha",
                        self.base,
                        "--branch",
                        self.branch,
                        "--capability",
                        "evil",
                    ],
                    cwd=ROOT,
                    env=environment,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(1, completed.returncode, completed.stderr)
                payload = json.loads(completed.stdout)
                self.assertEqual("FAIL", payload["status"])
                self.assertIn("unknown required capability", payload["reason"])
                self.assertFalse(marker.exists())

    def test_authorized_base_command_ignores_head_registry_replacement(self):
        marker = self.root / ".context/HEAD_COMMAND_EXECUTED"
        policy = copy.deepcopy(self.policy)
        policy["runtime_orchestration"]["capabilities"]["ansible-runtime"][
            "parameters"
        ] = {
            "command": ["touch", str(marker)],
        }
        self.commit_policy(policy)
        base_root = self.base_checkout()
        with (
            mock.patch.dict(
                os.environ,
                {
                    "REPOCTL_TRUSTED_POLICY_ROOT": str(base_root),
                    "REPOCTL_TRUSTED_BASE_SHA": self.base,
                    "REPOCTL_TRUSTED_TARGET_ROOT": str(self.root),
                    "REPOCTL_TRUSTED_HEAD_SHA": self.head,
                },
            ),
            mock.patch.object(
                preflight.runtime.BuiltinCapabilityDriver,
                "_run",
                return_value=subprocess.CompletedProcess(
                    ["ansible-playbook", "--version"], 0, "", ""
                ),
            ) as run,
        ):
            result = self.run_preflight(["ansible-runtime"])
        self.assertEqual("PASS", result["status"])
        run.assert_called_once_with(["ansible-playbook", "--version"], timeout=15)
        self.assertFalse(marker.exists())

    def test_local_diagnostic_reads_exact_base_blob_not_head_policy(self):
        policy = copy.deepcopy(self.policy)
        policy["runtime_orchestration"]["capabilities"]["cpu-capacity"]["handler"] = (
            "command"
        )
        policy["runtime_orchestration"]["capabilities"]["cpu-capacity"][
            "parameters"
        ] = {
            "command": ["touch", str(self.root / ".context/HEAD_COMMAND_EXECUTED")],
        }
        self.commit_policy(policy)
        with mock.patch.object(
            preflight.runtime.BuiltinCapabilityDriver, "_run"
        ) as run:
            result = self.run_preflight(
                ["cpu-capacity"], {"cpu-capacity": {"minimum_count": 1}}
            )
        self.assertEqual("PASS", result["status"])
        run.assert_not_called()

    def test_head_cannot_supply_executable_probe_parameters(self):
        for key in ("command", "commands", "handler", "operations", "timeout_seconds"):
            with (
                self.subTest(key=key),
                mock.patch.object(
                    preflight.runtime.BuiltinCapabilityDriver, "capture"
                ) as capture,
            ):
                result = self.run_preflight(
                    ["ansible-runtime"], {"ansible-runtime": {key: "evil"}}
                )
                self.assertEqual("FAIL", result["status"])
                capture.assert_not_called()

    def test_invalid_trusted_binding_never_falls_back_to_local_base(self):
        base_root = self.base_checkout()
        for binding in (
            {"REPOCTL_TRUSTED_POLICY_ROOT": str(base_root)},
            {"REPOCTL_TRUSTED_BASE_SHA": self.base},
            {"REPOCTL_TRUSTED_TARGET_ROOT": str(self.root)},
            {"REPOCTL_TRUSTED_NATIVE_UAC": "1"},
            {
                "REPOCTL_TRUSTED_POLICY_ROOT": str(base_root),
                "REPOCTL_TRUSTED_BASE_SHA": "f" * 40,
            },
        ):
            with self.subTest(binding=binding), mock.patch.dict(os.environ, binding):
                result = self.run_preflight()
                self.assertEqual("FAIL", result["status"])
                self.assertIn("binding", result["reason"])

    def test_trusted_policy_symlink_and_modified_bytes_are_rejected(self):
        base_root = self.base_checkout()
        path = base_root / "config/contracts/qualification-execution-policy.yaml"
        original = path.read_bytes()
        with mock.patch.dict(
            os.environ,
            {
                "REPOCTL_TRUSTED_POLICY_ROOT": str(base_root),
                "REPOCTL_TRUSTED_BASE_SHA": self.base,
            },
        ):
            path.write_bytes(original + b"\n")
            self.assertEqual("FAIL", self.run_preflight()["status"])
            path.unlink()
            path.symlink_to(self.policy_path)
            self.assertEqual("FAIL", self.run_preflight()["status"])

    def test_parameters_reject_unbounded_values_and_unknown_types(self):
        for parameters in (
            {"minimum_count": True},
            {"minimum_count": 2**63},
            {"minimum_count": []},
            {"minimum_count": "1"},
        ):
            with self.subTest(parameters=parameters):
                self.assertEqual(
                    "FAIL",
                    self.run_preflight(["cpu-capacity"], {"cpu-capacity": parameters})[
                        "status"
                    ],
                )
        for value in ("x" * 4097, "x\x00y", "x\ny"):
            with self.subTest(value=value):
                self.assertEqual(
                    "FAIL",
                    self.run_preflight(
                        ["ssh-identity"], {"ssh-identity": {"path": value}}
                    )["status"],
                )
        policy = copy.deepcopy(self.policy)
        policy["runtime_orchestration"]["capabilities"]["cpu-capacity"][
            "parameter_types"
        ] = {
            "minimum_count": "arbitrary-object",
        }
        self.commit_policy(policy)
        self.base = self.head
        self.git("update-ref", "refs/remotes/origin/main", self.base)
        self.assertEqual(
            "FAIL",
            self.run_preflight(
                ["cpu-capacity"], {"cpu-capacity": {"minimum_count": 1}}
            )["status"],
        )

    def test_sufficient_capacity_pass_and_machine_readable(self):
        result = self.run_preflight(
            ["cpu-capacity"],
            {"cpu-capacity": {"minimum_count": 1}},
        )
        self.assertEqual("PASS", result["status"])
        self.assertEqual("PASS", result["capacity"])
        self.assertEqual(self.head, result["source_sha"])
        self.assertFalse(result["mutation_performed"])
        path = preflight.write_preflight(self.root, result)
        stored = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual("PASS", stored["status"])
        self.assertRegex(stored["evidence_digest"], r"^sha256:[0-9a-f]{64}$")

    def test_insufficient_capacity_is_blocked_runtime(self):
        result = self.run_preflight(
            ["cpu-capacity"],
            {"cpu-capacity": {"minimum_count": 10**9}},
        )
        self.assertEqual("BLOCKED_RUNTIME", result["status"])
        self.assertEqual("BLOCKED_RUNTIME", result["capacity"])
        self.assertFalse(result["mutation_performed"])

    def test_wrong_head_base_branch_and_dirty_tree_fail(self):
        for field in ("expected_head_sha", "expected_base_sha"):
            with self.subTest(field=field):
                result = self.run_preflight(**{field: "f" * 40})
                self.assertEqual("FAIL", result["status"])
        self.assertEqual(
            "FAIL",
            self.run_preflight(expected_branch="other-feature")["status"],
        )
        (self.root / "source.txt").write_text("changed\n", encoding="utf-8")
        self.assertEqual("FAIL", self.run_preflight()["status"])

    def test_unknown_capability_and_unrequested_parameters_fail(self):
        self.assertEqual(
            "FAIL",
            self.run_preflight(["nonexistent-capability"])["status"],
        )
        self.assertEqual(
            "FAIL",
            self.run_preflight(parameters={"cpu-capacity": {"minimum_count": 1}})[
                "status"
            ],
        )

    def test_missing_special_probe_evidence_is_blocked(self):
        result = self.run_preflight(
            ["virtualbox-backend"],
            {
                "virtualbox-backend": {
                    "evidence_path": ".context/backend.json",
                    "sha256": "sha256:" + "a" * 64,
                    "backend": "NATIVE_VTX",
                }
            },
        )
        self.assertEqual("BLOCKED_RUNTIME", result["status"])
        self.assertEqual("BLOCKED_RUNTIME", result["environment"])

    def test_persisted_preflight_proof_requires_exact_identity_and_digest(self):
        path = preflight.write_preflight(self.root, self.bound_result())
        stored = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(stored, self.verify_persisted())
        tampered = copy.deepcopy(stored)
        tampered["status"] = "FAIL"
        path.write_text(json.dumps(tampered) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            self.verify_persisted()
        for field, replacement in (
            ("source_sha", "f" * 40),
            ("base_sha", "f" * 40),
            ("branch", "feat/other"),
            ("work_package_id", "wp-other"),
            ("work_package_digest", "sha256:" + "b" * 64),
            ("work_item_issue", 171),
            ("milestone", "M2.6"),
            ("required_capabilities", ["network"]),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(stored)
                changed[field] = replacement
                self.rewrite_evidence(path, changed)
                with self.assertRaisesRegex(ValueError, field):
                    self.verify_persisted()

    def test_persisted_preflight_requires_every_check_to_pass(self):
        path = preflight.write_preflight(self.root, self.bound_result())
        stored = json.loads(path.read_text(encoding="utf-8"))
        for mutate in (
            lambda value: value["checks"].pop("worktree"),
            lambda value: value["checks"].update(head="FAIL"),
            lambda value: value["checks"].update(extra="BLOCKED_RUNTIME"),
            lambda value: value.update(capacity="BLOCKED_RUNTIME"),
            lambda value: value.update(environment="FAIL"),
            lambda value: value.update(mutation_performed=True),
            lambda value: value.update(status="BLOCKED_RUNTIME"),
        ):
            with self.subTest(mutate=mutate):
                changed = copy.deepcopy(stored)
                mutate(changed)
                self.rewrite_evidence(path, changed)
                with self.assertRaises(ValueError):
                    self.verify_persisted()

    def test_persisted_preflight_requires_declared_capability_check(self):
        result = self.bound_result(
            ["cpu-capacity"], {"cpu-capacity": {"minimum_count": 1}}
        )
        path = preflight.write_preflight(self.root, result)
        self.assertEqual(
            "PASS", self.verify_persisted(["cpu-capacity"])["checks"]["cpu-capacity"]
        )
        changed = json.loads(path.read_text(encoding="utf-8"))
        changed["checks"].pop("cpu-capacity")
        self.rewrite_evidence(path, changed)
        with self.assertRaisesRegex(ValueError, "checks"):
            self.verify_persisted(["cpu-capacity"])

    def test_persisted_preflight_rejects_dirty_current_source(self):
        preflight.write_preflight(self.root, self.bound_result())
        (self.root / "source.txt").write_text("changed\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "worktree"):
            self.verify_persisted()

    def test_replacing_same_head_archives_previous_bytes(self):
        first = self.bound_result()
        path = preflight.write_preflight(self.root, first)
        original = path.read_bytes()
        second = copy.deepcopy(first)
        second["observed_at"] = "2026-09-30T12:00:00Z"
        preflight.write_preflight(self.root, second)
        history = (
            self.root
            / ".context/evidence/preflight/history"
            / self.head
            / (hashlib.sha256(original).hexdigest() + ".json")
        )
        self.assertEqual(original, history.read_bytes())
        self.assertNotEqual(original, path.read_bytes())
        self.assertEqual("PASS", self.verify_persisted()["status"])
        preflight.write_preflight(self.root, second)
        self.assertEqual(1, len(list(history.parent.glob("*.json"))))

    def test_runtime_driver_prepare_is_never_called(self):
        class Driver:
            def __init__(self):
                self.calls = []

            def capture(self, capability):
                self.calls.append("capture")
                return {"available_count": 0}

            def preflight(self, capability, initial_state):
                self.calls.append("preflight")
                raise preflight.runtime.RuntimeBlocked("capacity unavailable")

            def prepare(self, *_args):
                raise AssertionError("preflight must not mutate")

        driver = Driver()
        result = self.run_preflight(
            ["cpu-capacity"],
            {"cpu-capacity": {"minimum_count": 1}},
            driver=driver,
        )
        self.assertEqual("BLOCKED_RUNTIME", result["status"])
        self.assertEqual(["capture", "preflight"], driver.calls)


if __name__ == "__main__":
    unittest.main()
