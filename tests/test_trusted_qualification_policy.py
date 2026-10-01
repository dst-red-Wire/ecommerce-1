import copy
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import yaml

from scripts import runtime_orchestration as runtime
from scripts import trusted_qualification_policy as trusted


ROOT = Path(__file__).resolve().parents[1]
BASE_POLICY = {
    "version": 1,
    "kind": "QualificationExecutionPolicy",
    "status": "enforced",
    "architecture_authority": "architecture.lock.yaml",
    "runtime_orchestration": {
        "capabilities": {
            "approved-probe": {
                "handler": "command",
                "requires": [],
                "mutation_class": "none",
                "timeout_seconds": 2,
                "parameters": {"command": ["/usr/bin/printf", "approved"]},
                "operations": {},
                "evidence_fields": ["satisfied"],
                "required_parameters": [],
                "parameter_types": {},
            },
            "cpu-capacity": {
                "handler": "cpu",
                "requires": [],
                "mutation_class": "none",
                "timeout_seconds": 2,
                "operations": {},
                "evidence_fields": ["available_count"],
                "required_parameters": ["minimum_count"],
                "parameter_types": {"minimum_count": "positive-integer"},
            },
        },
    },
    "work_item_preflight": {
        "additional_capabilities": {
            "toolchain-pinned": {
                "required_parameters": ["sha256"],
                "parameter_types": {"sha256": "sha256-digest"},
            },
        },
    },
}


class TrustedQualificationPolicyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.workspace = Path(temporary.name)
        self.base = self.workspace / "base"
        self.target = self.workspace / "target"
        self.base.mkdir()
        self._git(self.base, "init", "-q")
        self._git(self.base, "switch", "-q", "-c", "main")
        self._write_policy(self.base, BASE_POLICY)
        self._git(self.base, "add", ".")
        self._commit(self.base, "trusted policy")
        self.base_sha = self._git(self.base, "rev-parse", "HEAD")
        subprocess.run(
            ["git", "clone", "-q", "--local", str(self.base), str(self.target)],
            check=True,
            capture_output=True,
            text=True,
        )
        self._git(self.target, "switch", "-q", "-c", "feat/malicious")
        self.head_sha = self._git(self.target, "rev-parse", "HEAD")

    @staticmethod
    def _git(root, *arguments):
        result = subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()

    def _commit(self, root, message):
        self._git(
            root,
            "-c",
            "commit.gpgsign=false",
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-q",
            "-m",
            message,
        )

    @staticmethod
    def _write_policy(root, policy):
        path = root / "config/contracts/qualification-execution-policy.yaml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(policy, sort_keys=True), encoding="utf-8")

    def load(self):
        return trusted.load_trusted_execution_policy(
            self.base, self.target, self.base_sha, self.head_sha
        )

    def _malicious_head_policy(self):
        malicious = copy.deepcopy(BASE_POLICY)
        malicious["runtime_orchestration"]["capabilities"]["approved-probe"][
            "parameters"
        ]["command"] = ["/bin/sh", "-c", "arbitrary-command"]
        malicious["runtime_orchestration"]["capabilities"]["head-only"] = {
            **copy.deepcopy(
                malicious["runtime_orchestration"]["capabilities"]["approved-probe"]
            ),
            "handler": "command",
        }
        self._write_policy(self.target, malicious)
        self._git(self.target, "add", ".")
        self._commit(self.target, "malicious head policy")
        self.head_sha = self._git(self.target, "rev-parse", "HEAD")

    def test_head_command_is_ignored_and_only_trusted_argv_is_selected(self):
        self._malicious_head_policy()
        policy = self.load()
        self.assertEqual(
            ["/usr/bin/printf", "approved"],
            policy["runtime_orchestration"]["capabilities"]["approved-probe"][
                "parameters"
            ]["command"],
        )
        requests = trusted.validate_trusted_capability_requests(
            policy, ["approved-probe"], {}
        )
        plan = runtime.RuntimePlanner(policy["runtime_orchestration"]).resolve(
            [
                runtime.CapabilityRequest(name, values)
                for name, values in requests.items()
            ]
        )
        with mock.patch.object(
            runtime.BuiltinCapabilityDriver,
            "_run",
            return_value=subprocess.CompletedProcess(
                ["/usr/bin/printf", "approved"], 0, "approved", ""
            ),
        ) as command:
            runtime.BuiltinCapabilityDriver().capture(plan[0])
        command.assert_called_once_with(["/usr/bin/printf", "approved"], timeout=2)
        self.assertNotIn("/bin/sh", command.call_args.args[0])

    def test_head_only_capability_and_executable_parameters_are_rejected(self):
        self._malicious_head_policy()
        policy = self.load()
        with self.assertRaisesRegex(trusted.TrustedQualificationPolicyError, "unknown"):
            trusted.validate_trusted_capability_requests(policy, ["head-only"], {})
        for forbidden in ("handler", "command", "commands", "argv"):
            with self.subTest(forbidden=forbidden):
                with self.assertRaisesRegex(
                    trusted.TrustedQualificationPolicyError, "executable policy"
                ):
                    trusted.validate_trusted_capability_requests(
                        policy,
                        ["approved-probe"],
                        {
                            "approved-probe": {
                                forbidden: ["/bin/sh", "-c", "arbitrary-command"]
                            }
                        },
                    )

    def test_bounded_parameters_follow_only_the_trusted_schema(self):
        policy = self.load()
        self.assertEqual(
            {"cpu-capacity": {"minimum_count": 4}},
            trusted.validate_trusted_capability_requests(
                policy,
                ["cpu-capacity"],
                {"cpu-capacity": {"minimum_count": 4}},
            ),
        )
        digest = "sha256:" + "a" * 64
        self.assertEqual(
            {"toolchain-pinned": {"sha256": digest}},
            trusted.validate_trusted_capability_requests(
                policy,
                ["toolchain-pinned"],
                {"toolchain-pinned": {"sha256": digest}},
            ),
        )
        for value in (True, 0, 2**31, "4"):
            with self.subTest(value=value):
                with self.assertRaises(trusted.TrustedQualificationPolicyError):
                    trusted.validate_trusted_capability_requests(
                        policy,
                        ["cpu-capacity"],
                        {"cpu-capacity": {"minimum_count": value}},
                    )
        with self.assertRaises(trusted.TrustedQualificationPolicyError):
            trusted.validate_trusted_capability_requests(
                policy,
                ["toolchain-pinned"],
                {"toolchain-pinned": {"sha256": "sha256:" + "z" * 64}},
            )

    def test_exact_clean_checkouts_are_required(self):
        with self.assertRaisesRegex(
            trusted.TrustedQualificationPolicyError, "exact SHA"
        ):
            trusted.load_trusted_execution_policy(
                self.base, self.target, "f" * 40, self.head_sha
            )
        (self.target / "untracked.txt").write_text("dirty", encoding="utf-8")
        with self.assertRaisesRegex(trusted.TrustedQualificationPolicyError, "dirty"):
            self.load()
        (self.target / "untracked.txt").unlink()
        (self.base / "untracked.txt").write_text("dirty", encoding="utf-8")
        with self.assertRaisesRegex(trusted.TrustedQualificationPolicyError, "dirty"):
            self.load()

    def test_trusted_policy_must_be_regular_not_a_symlink(self):
        policy = self.base / "config/contracts/qualification-execution-policy.yaml"
        alternate = policy.with_name("trusted.yaml")
        policy.rename(alternate)
        policy.symlink_to(alternate.name)
        self._git(self.base, "add", ".")
        self._commit(self.base, "symlink policy")
        self.base_sha = self._git(self.base, "rev-parse", "HEAD")
        self._git(self.target, "fetch", "-q", str(self.base))
        self._git(self.target, "merge", "-q", "--ff-only", self.base_sha)
        self.head_sha = self._git(self.target, "rev-parse", "HEAD")
        with self.assertRaisesRegex(
            trusted.TrustedQualificationPolicyError, "not regular"
        ):
            self.load()

    def test_current_repository_policy_registry_is_accepted(self):
        policy = yaml.safe_load(
            (ROOT / "config/contracts/qualification-execution-policy.yaml").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            {},
            trusted.validate_trusted_capability_requests(policy, [], {}),
        )


if __name__ == "__main__":
    unittest.main()
