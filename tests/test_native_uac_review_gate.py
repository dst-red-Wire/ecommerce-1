"""One dynamically resolved PR and exact owner evidence must precede native UAC."""

from __future__ import annotations

import contextlib
import hashlib
import tarfile
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import exact_pr_binding
import managed_gh
import repository_delivery
import repoctl


CAMPAIGN = "20260929T163821Z-9da62296f3d5"
SHA = "a" * 40
SHA_ALT = "c" * 40
BASE_SHA = "b" * 40
VM_ID = "e80d60f3-a12e-4734-a654-0cd24dce0fa1"
OWNER = "dst-red-Wire"
REPOSITORY = "dst-red-Wire/ecommerce-1"
TRUSTED_ROOT = "/tmp/exact-base-test"
PINNED_GH = (
    "/home/dev/.local/share/ecommerce-1/tools/gh-2.101.0/bin/gh",
    "2.101.0",
    "e" * 64,
)


def marker(kind: str, *, sha: str = SHA, status: str = "PASS",
           findings: int = 0) -> str:
    payload = {
        "provider": "ChatGPT", "kind": kind, "head_sha": sha,
        "status": status, "blocking_findings": findings,
    }
    return "<!-- chatgpt-exact-sha-review:v1 " + json.dumps(
        payload, separators=(",", ":")) + " -->"


def issue_comment(identifier: int, author: str, body: str, minute: int,
                  association: str = "OWNER") -> dict:
    timestamp = f"2026-09-30T02:{minute:02d}:00Z"
    return {
        "id": identifier, "user": {"login": author}, "author_association": association,
        "body": body, "created_at": timestamp, "updated_at": timestamp,
    }


class NativeUacReviewGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.configure_pr(169, SHA)

    def configure_pr(self, pr_number: int, sha: str) -> None:
        self.binding = exact_pr_binding.ExactPRBinding(
            REPOSITORY, pr_number, "main", BASE_SHA, "fix/vm-lifecycle-runtime-proof", sha)
        self.remote_binding = self.binding
        self.code = issue_comment(101, OWNER, "CODE: PASS\n" + marker("code", sha=sha), 1)
        self.security = issue_comment(
            102, OWNER, "SECURITY: PASS\n" + marker("security", sha=sha), 2)
        self.owner = issue_comment(
            103, OWNER,
            f"NATIVE-UAC-V1 PR={pr_number} SHA={sha} CAMPAIGN={CAMPAIGN} VM={VM_ID} "
            "CODE=101 SECURITY=102 APPROVED", 3)
        self.comments = [self.code, self.security, self.owner]

    def gate(self) -> tuple[bool, str]:
        def issue_comments_only(_gh: str, endpoint: str) -> list[dict]:
            self.assertEqual(
                endpoint,
                f"repos/{REPOSITORY}/issues/{self.binding.pr_number}/comments?per_page=100")
            return self.comments

        def revalidate(binding, *, gh: str):
            self.assertEqual(gh, PINNED_GH[0])
            if binding != self.remote_binding:
                raise exact_pr_binding.ExactPRBindingChanged("PR_CHANGED")
            return binding

        with (mock.patch.object(exact_pr_binding, "revalidate_exact_open_pr",
                                side_effect=revalidate),
              mock.patch.object(repoctl, "_native_uac_paginated_comments",
                                side_effect=issue_comments_only)):
            return repoctl._native_uac_review_gate(
                PINNED_GH[0], self.binding, CAMPAIGN, VM_ID)

    def test_pr_169_and_170_pass_with_their_own_sha_and_owner_markers(self) -> None:
        self.assertTrue(self.gate()[0])
        self.configure_pr(170, SHA_ALT)
        self.assertTrue(self.gate()[0])
        self.comments.append(issue_comment(
            104, "chatgpt-codex-connector[bot]", "Codex historical finding", 4,
            association="NONE"))
        self.assertTrue(self.gate()[0])

    def test_remote_pr_identity_or_unavailable_api_fails_closed(self) -> None:
        for change in (
            {"pr_number": 170}, {"base": "other"}, {"base_sha": SHA_ALT},
            {"head_sha": SHA_ALT}, {"head_branch": "other-branch"},
            {"repository": "attacker/repo"},
        ):
            with self.subTest(change=change):
                self.remote_binding = replace(self.binding, **change)
                self.assertFalse(self.gate()[0])
        self.remote_binding = self.binding
        with mock.patch.object(exact_pr_binding, "revalidate_exact_open_pr",
                               side_effect=RuntimeError("offline")):
            self.assertFalse(repoctl._native_uac_review_gate(
                PINNED_GH[0], self.binding, CAMPAIGN, VM_ID)[0])

    def test_missing_blocked_wrong_sha_or_ambiguous_marker_fails_closed(self) -> None:
        for body in (
            marker("security", status="BLOCKED", findings=1),
            marker("security", status="PASS", findings=1),
            marker("security", sha=SHA_ALT),
            "<!-- chatgpt-exact-sha-review:v1 {bad JSON} -->",
            marker("security") + "\n" + marker("security"),
        ):
            with self.subTest(body=body[:48]):
                self.security["body"] = body
                self.assertFalse(self.gate()[0])
        self.security["body"] = marker("security")
        self.comments = [self.code, self.owner]
        self.assertFalse(self.gate()[0])

    def test_latest_review_revokes_prior_authorization(self) -> None:
        self.comments.append(issue_comment(
            104, OWNER, marker("security", status="BLOCKED", findings=1), 4))
        self.assertIn("not clean", self.gate()[1])
        self.comments.append(issue_comment(105, OWNER, marker("security"), 5))
        self.assertFalse(self.gate()[0])
        self.comments.append(issue_comment(
            106, OWNER,
            f"NATIVE-UAC-V1 PR=169 SHA={SHA} CAMPAIGN={CAMPAIGN} VM={VM_ID} "
            "CODE=101 SECURITY=105 APPROVED", 6))
        self.assertTrue(self.gate()[0])

    def test_security_review_before_latest_code_fails_closed(self) -> None:
        self.security["created_at"] = self.code["created_at"]
        self.security["updated_at"] = self.security["created_at"]
        self.code["id"] = 104
        self.owner["body"] = self.owner["body"].replace("CODE=101", "CODE=104")
        self.assertIn("SECURITY review must follow", self.gate()[1])

    def test_only_immutable_owner_comments_have_authority(self) -> None:
        self.code["user"]["login"] = "other-user"
        self.assertFalse(self.gate()[0])
        self.code["user"]["login"] = OWNER
        self.code["author_association"] = "CONTRIBUTOR"
        self.assertFalse(self.gate()[0])
        self.code["author_association"] = "OWNER"
        self.code["updated_at"] = "2026-09-30T02:04:00Z"
        self.assertFalse(self.gate()[0])
        self.code["updated_at"] = self.code["created_at"]
        self.owner["author_association"] = "CONTRIBUTOR"
        self.assertFalse(self.gate()[0])
        self.owner["author_association"] = "OWNER"
        self.owner["updated_at"] = "2026-09-30T02:04:00Z"
        self.assertFalse(self.gate()[0])

    def test_owner_marker_wrong_pr_sha_order_or_review_id_fails(self) -> None:
        self.owner["created_at"] = "2026-09-30T02:01:30Z"
        self.owner["updated_at"] = self.owner["created_at"]
        self.assertFalse(self.gate()[0])
        self.owner["created_at"] = "2026-09-30T02:03:00Z"
        self.owner["updated_at"] = self.owner["created_at"]
        for before, after in (("CODE=101", "CODE=999"),
                              ("PR=169", "PR=170"),
                              (f"SHA={SHA}", f"SHA={SHA_ALT}")):
            with self.subTest(after=after):
                original = self.owner["body"]
                self.owner["body"] = original.replace(before, after)
                self.assertFalse(self.gate()[0])
                self.owner["body"] = original
        self.comments.append(issue_comment(
            104, OWNER, "NATIVE-UAC-V1 PR=170 SHA=" + SHA_ALT + " REVOKED", 4))
        self.assertFalse(self.gate()[0])

    def test_paginated_owner_comments_reject_malformed_payload(self) -> None:
        one = issue_comment(1, OWNER, "old", 1)
        two = issue_comment(2, OWNER, "new", 2)
        response = subprocess.CompletedProcess([], 0, json.dumps([one]) + "\n" + json.dumps([two]), "")
        endpoint = f"repos/{REPOSITORY}/issues/169/comments?per_page=100"
        with mock.patch.object(repoctl, "run", return_value=response) as run:
            self.assertEqual(repoctl._native_uac_paginated_comments(PINNED_GH[0], endpoint),
                             [one, two])
        self.assertEqual(run.call_args.args[0], [PINNED_GH[0], "api", "--paginate", endpoint])
        with (mock.patch.object(
                  repoctl, "run", return_value=subprocess.CompletedProcess([], 0, "{}", "")),
              self.assertRaises(RuntimeError)):
            repoctl._native_uac_paginated_comments("gh", endpoint)

    def _boot_context(self, *, head_reads: list[str] | None = None,
                      gate_results: list[tuple[bool, str]] | None = None):
        heads = iter(head_reads or [self.binding.head_sha] * 4)

        def git_value(*args):
            if args[0] == "status":
                return ""
            if args[0] == "rev-parse":
                return next(heads)
            if args[0] == "symbolic-ref":
                return self.binding.head_branch
            raise AssertionError(args)

        results = iter(gate_results or [(True, "clean")] * 3)
        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch.object(repoctl, "git", side_effect=git_value))
        context = {
            "trusted_root": Path(TRUSTED_ROOT), "target_root": repoctl.ROOT,
            "base_sha": self.binding.base_sha, "head_sha": self.binding.head_sha,
            "pr_number": self.binding.pr_number,
        }
        stack.enter_context(mock.patch.object(
            repoctl, "_native_uac_trusted_context", return_value=context))
        stack.enter_context(mock.patch.object(
            repoctl, "_require_trusted_pr_execution", return_value=context))
        stack.enter_context(mock.patch.object(
            repoctl, "_native_uac_runner_manifest",
            return_value={name: "f" * 64 for name in repoctl._NATIVE_UAC_RUNNER_NAMES}))
        stack.enter_context(mock.patch.object(repository_delivery, "_native_verify_base_tree"))
        stack.enter_context(mock.patch.object(
            repoctl, "_native_uac_pinned_gh", return_value=PINNED_GH))
        stack.enter_context(mock.patch.object(repoctl.os.path, "isfile", return_value=True))
        stack.enter_context(mock.patch.object(repoctl.os, "access", return_value=True))
        stack.enter_context(mock.patch.object(Path, "is_file", return_value=True))
        stack.enter_context(mock.patch.dict(repoctl.os.environ, {
            "WSL_DISTRO_NAME": "Ubuntu-24.04",
        }))
        token = repoctl._NATIVE_UAC_RUNTIME_LOCK_HELD.set(True)
        stack.callback(repoctl._NATIVE_UAC_RUNTIME_LOCK_HELD.reset, token)
        stack.enter_context(mock.patch.object(exact_pr_binding, "resolve_exact_open_pr",
                                              return_value=self.binding))
        stack.enter_context(mock.patch.object(repoctl, "_native_uac_qualification_matches",
                                              return_value=(True, "qualified")))
        gate = stack.enter_context(mock.patch.object(repoctl, "_native_uac_review_gate",
                                                   side_effect=lambda *_args: next(results)))
        prepare = stack.enter_context(mock.patch.object(repoctl, "lab_network_native_prepare",
                                                      return_value=0))
        bootstrap = stack.enter_context(mock.patch.object(repoctl, "_native_bootstrap_script",
                                                        return_value="safe"))
        stack.enter_context(mock.patch.object(repoctl, "_native_boot_elevation_command",
                                              return_value=["powershell"]))
        stack.enter_context(mock.patch.object(repoctl, "output", return_value=
                                              "\\\\wsl.localhost\\Ubuntu-24.04\\home\\dev\\ecommerce-1"))
        run = stack.enter_context(mock.patch.object(repoctl, "run", return_value=
                                                    subprocess.CompletedProcess([], 0, "", "")))
        stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
        return stack, gate, prepare, bootstrap, run

    def test_prepare_and_selftest_refuse_before_staging_or_bootstrap(self) -> None:
        for action in ("Prepare", "SelfTest"):
            with self.subTest(action=action):
                stack, gate, prepare, bootstrap, run = self._boot_context(
                    gate_results=[(False, "denied")])
                with stack:
                    self.assertNotEqual(
                        repoctl.lab_network_native_boot(
                            action, CAMPAIGN, VM_ID, TRUSTED_ROOT), 0)
                self.assertEqual(gate.call_count, 1)
                prepare.assert_not_called()
                bootstrap.assert_not_called()
                run.assert_not_called()

    def test_missing_exact_qualification_refuses_before_review_or_staging(self) -> None:
        stack, gate, prepare, _bootstrap, run = self._boot_context()
        with stack, mock.patch.object(repoctl, "_native_uac_qualification_matches",
                                      return_value=(False, "no exact proof")):
            self.assertNotEqual(repoctl.lab_network_native_boot(
                "Prepare", CAMPAIGN, VM_ID, TRUSTED_ROOT), 0)
        gate.assert_not_called()
        prepare.assert_not_called()
        run.assert_not_called()

    def test_qualification_uses_bound_head_and_base(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "trusted"
            scripts = root / "scripts"
            scripts.mkdir(parents=True)
            (scripts / "repoctl.py").write_text("base controller\n", encoding="utf-8")
            (scripts / "repository_delivery.py").write_text("base wrapper\n", encoding="utf-8")
            (scripts / "performance_audit.py").write_text("base auditor\n", encoding="utf-8")

            def git(*args: str) -> str:
                result = subprocess.run(
                    ["git", "-C", str(root), *args], capture_output=True,
                    text=True, check=True)
                return result.stdout.strip()

            git("init", "-q")
            git("add", "scripts/repoctl.py", "scripts/repository_delivery.py",
                "scripts/performance_audit.py")
            git("-c", "user.name=Native Test", "-c", "user.email=native@example.test",
                "-c", "commit.gpgsign=false", "commit", "-qm", "exact base")
            binding = replace(self.binding, base_sha=git("rev-parse", "HEAD"))
            controller = scripts / "repoctl.py"
            with mock.patch.object(
                repository_delivery, "_native_verify_controller",
                return_value=(binding.base_sha, scripts / "repository_delivery.py", controller)):
                self.assertEqual(
                    repoctl._native_uac_trusted_controller(binding, str(root)), controller)
                self.assertFalse(repoctl._native_uac_qualification_matches(
                    binding, "", expected_witness="f" * 64)[0])

                with mock.patch.object(repoctl, "_qualification_toolchain",
                                       return_value=({}, set())):
                    default_identity = repoctl.qualification_identity()
                    token = repoctl._NATIVE_UAC_CONTROLLER_PATH.set(str(controller))
                    try:
                        exact_base_identity = repoctl.qualification_identity()
                    finally:
                        repoctl._NATIVE_UAC_CONTROLLER_PATH.reset(token)
                    self.assertNotEqual(default_identity, exact_base_identity)

                    def exact_evidence(base: str, head: str) -> Path:
                        self.assertEqual((base, head), (binding.base_sha, SHA))
                        self.assertEqual(repoctl._controller_command()[1], str(controller))
                        self.assertEqual(repoctl.qualification_identity(), exact_base_identity)
                        return Path("proof.json")

                    with (mock.patch.object(repoctl, "_valid_exact_evidence",
                                            side_effect=exact_evidence) as evidence,
                          mock.patch.object(repoctl, "_valid_performance_audit",
                                            return_value=Path("audit.json")) as audit,
                          mock.patch.object(repoctl, "_native_uac_qualification_witness",
                                            return_value="f" * 64)):
                        self.assertTrue(repoctl._native_uac_qualification_matches(
                            binding, str(root), expected_witness="f" * 64)[0])
                evidence.assert_called_once_with(binding.base_sha, SHA)
                audit.assert_called_once_with(binding.base_sha, SHA)
                self.assertNotEqual(repoctl._controller_command()[1], str(controller))

                with mock.patch.object(repoctl, "_valid_exact_evidence", return_value=None):
                    self.assertFalse(repoctl._native_uac_qualification_matches(
                        binding, str(root), expected_witness="f" * 64)[0])
                self.assertFalse(repoctl._native_uac_qualification_matches(
                    replace(binding, base_sha=SHA_ALT), str(root),
                    expected_witness="f" * 64)[0])
                controller.write_text("tampered\n", encoding="utf-8")
                self.assertFalse(repoctl._native_uac_qualification_matches(
                    binding, str(root), expected_witness="f" * 64)[0])

    def test_prepare_reuses_one_binding_at_three_boundaries(self) -> None:
        self.configure_pr(170, SHA_ALT)
        stack, gate, prepare, bootstrap, run = self._boot_context()
        with stack:
            self.assertEqual(repoctl.lab_network_native_boot(
                "Prepare", CAMPAIGN, VM_ID, TRUSTED_ROOT), 0)
        self.assertEqual(gate.call_count, 3)
        self.assertTrue(all(call.args[1] is self.binding for call in gate.call_args_list))
        prepare.assert_called_once_with(CAMPAIGN)
        self.assertIs(bootstrap.call_args.args[-2], self.binding)
        self.assertEqual(bootstrap.call_args.args[-1], PINNED_GH)
        run.assert_called_once()

    def test_head_change_after_staging_or_before_uac_denies_elevation(self) -> None:
        for reads, expected_gates in (
            ([SHA, SHA_ALT], 1),
            ([SHA, SHA, SHA_ALT], 2),
        ):
            with self.subTest(reads=reads):
                stack, gate, prepare, _bootstrap, run = self._boot_context(head_reads=reads)
                with stack:
                    self.assertNotEqual(
                        repoctl.lab_network_native_boot(
                            "Prepare", CAMPAIGN, VM_ID, TRUSTED_ROOT), 0)
                self.assertEqual(gate.call_count, expected_gates)
                prepare.assert_called_once()
                run.assert_not_called()

    def test_pr_change_after_staging_or_before_uac_denies_elevation(self) -> None:
        for results, expected_gates in (
            ([(True, "clean"), (False, "BASE_CHANGED")], 2),
            ([(True, "clean"), (True, "clean"), (False, "HEAD_CHANGED")], 3),
        ):
            with self.subTest(results=results):
                stack, gate, _prepare, _bootstrap, run = self._boot_context(
                    gate_results=results)
                with stack:
                    self.assertNotEqual(
                        repoctl.lab_network_native_boot(
                            "Prepare", CAMPAIGN, VM_ID, TRUSTED_ROOT), 0)
                self.assertEqual(gate.call_count, expected_gates)
                run.assert_not_called()

    def test_direct_pr_head_cli_refuses_all_native_actions_before_uac(self) -> None:
        env = os.environ.copy()
        env.pop("REPOCTL_TRUSTED_NATIVE_UAC", None)
        env["ECOMMERCE_RUNTIME_ORCHESTRATED"] = "1"
        for action in ("prepare", "self-test", "reboot", "recover"):
            with self.subTest(action=action):
                command = [sys.executable, str(repoctl.ROOT / "scripts/repoctl.py"),
                           f"lab-network-native-boot-{action}", "--campaign-id", CAMPAIGN]
                if action in {"prepare", "self-test"}:
                    command += ["--expected-vm-id", VM_ID, "--trusted-root", TRUSTED_ROOT]
                result = subprocess.run(command, cwd=repoctl.ROOT, env=env,
                                        text=True, capture_output=True, timeout=20)
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue("exact-base trusted controller" in result.stderr or "canonical-workspace" in result.stderr, result.stderr)

    def test_direct_pr_head_fails_before_lock_staging_and_uac(self) -> None:
        with (mock.patch.dict(os.environ, {"REPOCTL_TRUSTED_NATIVE_UAC": ""}),
              mock.patch.object(repoctl, "_execute_with_runtime") as locked,
              mock.patch.object(repoctl, "lab_network_native_prepare") as staged,
              mock.patch.object(repoctl, "_native_bootstrap_script") as bootstrap,
              mock.patch.object(repoctl, "run") as elevated):
            for action in ("Prepare", "SelfTest", "Reboot", "Recover"):
                self.assertNotEqual(repoctl.lab_network_native_boot(
                    action, CAMPAIGN, VM_ID, TRUSTED_ROOT), 0)
            for action in ("prepare", "reboot", "recover"):
                self.assertNotEqual(repoctl.lab_network_native_boot_with_runtime(
                    f"lab-network-native-boot-{action}", CAMPAIGN, VM_ID, TRUSTED_ROOT), 0)
        locked.assert_not_called()
        staged.assert_not_called()
        bootstrap.assert_not_called()
        elevated.assert_not_called()

    def test_self_forged_trusted_environment_cannot_authorize_head(self) -> None:
        context = {
            "trusted_root": repoctl.ROOT, "target_root": repoctl.ROOT,
            "base_sha": SHA, "head_sha": SHA, "pr_number": 169,
        }
        with (mock.patch.dict(os.environ, {"REPOCTL_TRUSTED_NATIVE_UAC": "1"}),
              mock.patch.object(repoctl, "_require_trusted_pr_execution",
                                return_value=context)):
            with self.assertRaisesRegex(RuntimeError, "cannot authorize itself"):
                repoctl._native_uac_trusted_context("Prepare")

    def test_native_run_requires_runtime_lock_even_with_base_context(self) -> None:
        context = {"trusted_root": Path(TRUSTED_ROOT), "target_root": repoctl.ROOT,
                   "base_sha": BASE_SHA, "head_sha": SHA, "pr_number": 169}
        with (mock.patch.object(repoctl, "_native_uac_trusted_context",
                                return_value=context),
              mock.patch.object(repoctl, "lab_network_native_prepare") as stage,
              mock.patch.object(repoctl, "_native_bootstrap_script") as bootstrap,
              mock.patch.object(repoctl, "run") as elevated):
            for action in ("Prepare", "SelfTest", "Reboot", "Recover"):
                self.assertNotEqual(repoctl.lab_network_native_boot(
                    action, CAMPAIGN, VM_ID, TRUSTED_ROOT), 0)
        stage.assert_not_called()
        bootstrap.assert_not_called()
        elevated.assert_not_called()

    def test_native_runtime_rejects_inherited_bypass_before_lock(self) -> None:
        context = {"trusted_root": Path(TRUSTED_ROOT), "target_root": repoctl.ROOT,
                   "base_sha": BASE_SHA, "head_sha": SHA, "pr_number": 169}
        with (mock.patch.object(repoctl, "_native_uac_trusted_context",
                                return_value=context),
              mock.patch.object(repoctl, "_native_uac_runtime_directory"),
              mock.patch.dict(os.environ, {"ECOMMERCE_RUNTIME_ORCHESTRATED": "1"}),
              mock.patch.object(repoctl, "_execute_with_runtime") as locked):
            self.assertNotEqual(repoctl.lab_network_native_boot_with_runtime(
                "lab-network-native-boot-prepare", CAMPAIGN, VM_ID, TRUSTED_ROOT), 0)
        locked.assert_not_called()

    def test_native_runtime_rejects_redirected_lock_directory(self) -> None:
        context = {"trusted_root": Path(TRUSTED_ROOT), "target_root": repoctl.ROOT,
                   "base_sha": BASE_SHA, "head_sha": SHA, "pr_number": 169}
        with (mock.patch.object(repoctl, "_native_uac_trusted_context",
                                return_value=context),
              mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": "/tmp/redirected",
                                          "ECOMMERCE_RUNTIME_ORCHESTRATED": ""}),
              mock.patch.object(repoctl, "_execute_with_runtime") as locked):
            self.assertNotEqual(repoctl.lab_network_native_boot_with_runtime(
                "lab-network-native-boot-prepare", CAMPAIGN, VM_ID, TRUSTED_ROOT), 0)
        locked.assert_not_called()

    def test_native_runtime_executes_inside_base_policy_lock(self) -> None:
        context = {"trusted_root": Path(TRUSTED_ROOT), "target_root": repoctl.ROOT,
                   "base_sha": BASE_SHA, "head_sha": SHA, "pr_number": 169}
        policy = {"runtime_orchestration": {"capabilities": {
            "local-virtualization-serialization": {"global_lock": True}}}}

        def execute_under_lock(_plan, callback, **_kwargs):
            self.assertEqual(repoctl._NATIVE_UAC_CONTROLLER_PATH.get(),
                             str(Path(TRUSTED_ROOT) / "scripts/repoctl.py"))
            self.assertFalse(repoctl._NATIVE_UAC_RUNTIME_LOCK_HELD.get())
            return callback({"ECOMMERCE_RUNTIME_ORCHESTRATED": "1",
                             "ECOMMERCE_RUNTIME_RUN_ID": "lock-test"})

        def boot_under_lock(*_args):
            self.assertTrue(repoctl._NATIVE_UAC_RUNTIME_LOCK_HELD.get())
            self.assertEqual(repoctl._NATIVE_UAC_CONTROLLER_PATH.get(),
                             str(Path(TRUSTED_ROOT) / "scripts/repoctl.py"))
            return 0

        with (mock.patch.object(repoctl, "_native_uac_trusted_context",
                                return_value=context),
              mock.patch.object(repoctl, "_native_uac_runtime_directory"),
              mock.patch.object(repoctl, "qualification_execution_policy",
                                return_value=policy),
              mock.patch.object(repoctl, "_native_uac_fresh_qualification",
                                return_value="f" * 64),
              mock.patch.dict(os.environ, {"ECOMMERCE_RUNTIME_ORCHESTRATED": ""}),
              mock.patch.object(repoctl, "_execute_with_runtime",
                                side_effect=execute_under_lock),
              mock.patch.object(repoctl, "lab_network_native_boot",
                                side_effect=boot_under_lock) as boot):
            self.assertEqual(repoctl.lab_network_native_boot_with_runtime(
                "lab-network-native-boot-prepare", CAMPAIGN, VM_ID, TRUSTED_ROOT), 0)
        boot.assert_called_once_with("Prepare", CAMPAIGN, VM_ID, TRUSTED_ROOT)
        self.assertIsNone(repoctl._NATIVE_UAC_CONTROLLER_PATH.get())
        self.assertFalse(repoctl._NATIVE_UAC_RUNTIME_LOCK_HELD.get())

    def test_native_runtime_refuses_callback_without_lock_run_id(self) -> None:
        context = {"trusted_root": Path(TRUSTED_ROOT), "target_root": repoctl.ROOT,
                   "base_sha": BASE_SHA, "head_sha": SHA, "pr_number": 169}
        policy = {"runtime_orchestration": {"capabilities": {
            "local-virtualization-serialization": {"global_lock": True}}}}

        def unlocked_callback(_plan, callback, **_kwargs):
            return callback({"ECOMMERCE_RUNTIME_ORCHESTRATED": "1"})

        with (mock.patch.object(repoctl, "_native_uac_trusted_context",
                                return_value=context),
              mock.patch.object(repoctl, "_native_uac_runtime_directory"),
              mock.patch.object(repoctl, "qualification_execution_policy",
                                return_value=policy),
              mock.patch.object(repoctl, "_native_uac_fresh_qualification",
                                return_value="f" * 64),
              mock.patch.dict(os.environ, {"ECOMMERCE_RUNTIME_ORCHESTRATED": ""}),
              mock.patch.object(repoctl, "_execute_with_runtime",
                                side_effect=unlocked_callback),
              mock.patch.object(repoctl, "lab_network_native_boot") as boot):
            self.assertNotEqual(repoctl.lab_network_native_boot_with_runtime(
                "lab-network-native-boot-prepare", CAMPAIGN, VM_ID, TRUSTED_ROOT), 0)
        boot.assert_not_called()
        self.assertFalse(repoctl._NATIVE_UAC_RUNTIME_LOCK_HELD.get())

    def test_native_git_disables_local_hooks_and_fsmonitor(self) -> None:
        command = ["/usr/bin/git", "-c", "core.fsmonitor=false",
                   "-c", "core.hooksPath=/dev/null", "status", "--porcelain"]
        with (mock.patch.object(repoctl, "_NATIVE_UAC_MODE", True),
              mock.patch.object(repoctl, "run", return_value=
                                subprocess.CompletedProcess(command, 0, "", "")) as run):
            self.assertEqual(repoctl.git("status", "--porcelain"), "")
        run.assert_called_once_with(command, check=True, capture=True)

    def test_native_generic_run_hardens_git_commands(self) -> None:
        with (mock.patch.object(repoctl, "_NATIVE_UAC_MODE", True),
              mock.patch.object(repoctl.subprocess, "run", return_value=
                                subprocess.CompletedProcess([], 0, "head\n", "")) as child):
            self.assertEqual(repoctl.output(["git", "rev-parse", "HEAD"]), "head\n")
        self.assertEqual(child.call_args.args[0], [
            "/usr/bin/git", "-c", "core.fsmonitor=false", "-c",
            "core.hooksPath=/dev/null", "rev-parse", "HEAD"])

    def test_native_import_uses_base_toolchain_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary) / "base"
            target = Path(temporary) / "target"
            for root, origin in ((base, "base"), (target, "pr")):
                lock = root / "config/contracts/toolchain-lock.json"
                lock.parent.mkdir(parents=True)
                lock.write_text(json.dumps({"origin": origin}), encoding="utf-8")
            with (mock.patch.object(repoctl, "SCRIPT_DIR", base / "scripts"),
                  mock.patch.object(repoctl, "ROOT", target),
                  mock.patch.object(repoctl, "_NATIVE_UAC_MODE", True)):
                self.assertEqual(repoctl._raw_toolchain_lock()["origin"], "base")
            with (mock.patch.object(repoctl, "ROOT", target),
                  mock.patch.object(repoctl, "_NATIVE_UAC_MODE", False)):
                self.assertEqual(repoctl._raw_toolchain_lock()["origin"], "pr")

    def test_native_import_never_runs_git_from_pr_toolchain_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "target"
            target.mkdir()
            subprocess.run(["/usr/bin/git", "init", "-q", str(target)], check=True)
            tool_home = Path(temporary) / "pr-tools"
            binary = tool_home / "bin/git"
            binary.parent.mkdir(parents=True)
            marker_file = Path(temporary) / "fake-git-ran"
            binary.write_text(
                "#!/bin/sh\nprintf hit > " + str(marker_file) + "\nexit 99\n",
                encoding="utf-8")
            binary.chmod(0o755)
            lock = json.loads((repoctl.ROOT / "config/contracts/toolchain-lock.json")
                              .read_text(encoding="utf-8"))
            install = lock["capability_policy"]["managed_install_root"]
            install["fallback"] = str(tool_home)
            lock_path = target / "config/contracts/toolchain-lock.json"
            lock_path.parent.mkdir(parents=True)
            lock_path.write_text(json.dumps(lock), encoding="utf-8")
            script = (
                "import os,sys;sys.path.insert(0,sys.argv[1]);"
                "import repoctl;"
                "assert repoctl.git('rev-parse','--show-toplevel').strip()==sys.argv[2];"
                "print(os.environ['PATH']);"
                "print(repoctl.PROJECT_COLLECTIONS);"
                "print(os.environ['ANSIBLE_CONFIG'])"
            )
            environment = os.environ.copy()
            environment["PATH"] = "/usr/bin:/bin:/usr/local/bin"
            environment["REPOCTL_TRUSTED_NATIVE_UAC"] = "1"
            environment.pop(install["environment"], None)
            result = subprocess.run(
                [sys.executable, "-I", "-c", script, str(repoctl.SCRIPT_DIR), str(target)],
                cwd=target, env=environment, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            lines = result.stdout.splitlines()
            self.assertEqual(lines[0], "/usr/bin:/bin:/usr/local/bin")
            self.assertTrue(lines[1].startswith(str(repoctl.SCRIPT_DIR.parent)), lines[1])
            self.assertTrue(lines[2].startswith(str(repoctl.SCRIPT_DIR.parent)), lines[2])
            self.assertFalse(marker_file.exists())

    def test_native_qualification_toolchain_uses_exact_base_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary) / "base"
            target = Path(temporary) / "target"
            for root, command in ((base, "base-tool"), (target, "pr-tool")):
                contract = root / "config/toolchain/capabilities.json"
                contract.parent.mkdir(parents=True)
                contract.write_text(json.dumps({
                    "capabilities": [], "command_capabilities": {},
                    "gate_requirements": {"gate": [command]},
                }), encoding="utf-8")
            controller = base / "scripts/repoctl.py"
            controller.parent.mkdir(parents=True)
            controller.write_text("exact base controller\n", encoding="utf-8")
            with mock.patch.object(repoctl, "ROOT", target):
                target_tools, _ = repoctl._qualification_toolchain()
                token = repoctl._NATIVE_UAC_CONTROLLER_PATH.set(str(controller))
                try:
                    native_tools, _ = repoctl._qualification_toolchain()
                finally:
                    repoctl._NATIVE_UAC_CONTROLLER_PATH.reset(token)
            self.assertIn("pr-tool", target_tools)
            self.assertNotIn("base-tool", target_tools)
            self.assertIn("base-tool", native_tools)
            self.assertNotIn("pr-tool", native_tools)

    def test_runner_manifest_binds_crlf_checkout_bytes_and_rejects_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            subprocess.run(["/usr/bin/git", "init", "-q", str(target)], check=True)
            (target / ".gitattributes").write_bytes(b"*.ps1 text eol=crlf\n")
            directory = target / "scripts/windows"
            directory.mkdir(parents=True)
            for name in repoctl._NATIVE_UAC_RUNNER_NAMES:
                (directory / name).write_bytes(b"Write-Output 'OK'\n")
            subprocess.run(["/usr/bin/git", "-C", str(target), "add", "."], check=True)
            subprocess.run([
                "/usr/bin/git", "-C", str(target), "-c", "user.name=Native Test",
                "-c", "user.email=native@example.test", "-c", "commit.gpgsign=false",
                "commit", "-qm", "runners"],
                check=True)
            head = subprocess.check_output(
                ["/usr/bin/git", "-C", str(target), "rev-parse", "HEAD"],
                text=True).strip()
            for name in repoctl._NATIVE_UAC_RUNNER_NAMES:
                if name.endswith(".ps1"):
                    (directory / name).write_bytes(b"Write-Output 'OK'\r\n")
            binding = replace(self.binding, head_sha=head)
            entries = []
            for name in sorted(repoctl._NATIVE_UAC_RUNNER_NAMES):
                relative = f"scripts/windows/{name}"
                digest = hashlib.sha256((directory / name).read_bytes()).hexdigest()
                entries.append(relative.encode() + b"\0" + digest.encode() + b"\n")
            manifest = hashlib.sha256(b"".join(entries)).hexdigest()
            with (mock.patch.object(repoctl, "ROOT", target),
                  mock.patch.dict(os.environ, {
                      "REPOCTL_TRUSTED_NATIVE_RUNNER_MANIFEST_SHA256": manifest})):
                digests = repoctl._native_uac_runner_manifest(binding)
                self.assertEqual(
                    digests["LabNetworkSeed.ps1"],
                    hashlib.sha256(b"Write-Output 'OK'\r\n").hexdigest())
                (directory / "LabNetworkSeed.ps1").write_bytes(b"Write-Output 'evil'\r\n")
                with self.assertRaisesRegex(RuntimeError, "runner bytes differ"):
                    repoctl._native_uac_runner_manifest(binding)

    def test_forged_qualification_json_is_removed_before_fresh_full_run(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "target"
            evidence = target / ".context/evidence" / f"{SHA}.json"
            audit = target / ".context/performance" / f"{SHA}.json"
            evidence.parent.mkdir(parents=True)
            audit.parent.mkdir(parents=True)
            evidence.write_text('{"status":"PASS"}', encoding="utf-8")
            audit.write_text('{"status":"PASS"}', encoding="utf-8")
            context = {"trusted_root": Path(temporary) / "base", "target_root": target,
                       "base_sha": BASE_SHA, "head_sha": SHA, "pr_number": 169}

            def full_run(base, head, profile=""):
                self.assertEqual((base, head, profile), (BASE_SHA, SHA, "full"))
                self.assertEqual(os.environ.get("ECOMMERCE_FORCE_FULL_QUALIFICATION"), "1")
                self.assertFalse(evidence.exists())
                self.assertFalse(audit.exists())
                return 1

            with (mock.patch.object(repoctl, "ROOT", target),
                  mock.patch.object(repoctl, "CONTEXT", target / ".context"),
                  mock.patch.object(repoctl, "git", return_value=self.binding.head_branch),
                  mock.patch.object(repoctl, "_native_uac_pinned_gh", return_value=PINNED_GH),
                  mock.patch.object(exact_pr_binding, "resolve_exact_open_pr",
                                    return_value=self.binding),
                  mock.patch.object(repoctl, "_require_trusted_pr_execution"),
                  mock.patch.object(repoctl, "_native_uac_runner_manifest"),
                  mock.patch.object(repoctl, "_native_uac_worktree_matches",
                                    return_value=(True, "clean")),
                  mock.patch.object(repoctl, "_native_uac_review_gate",
                                    return_value=(True, "approved")),
                  mock.patch.object(repoctl, "_native_uac_trusted_controller",
                                    return_value=context["trusted_root"] / "scripts/repoctl.py"),
                  mock.patch.object(repoctl, "_qualification_audit_path", return_value=audit),
                  mock.patch.object(repoctl, "verify_change", side_effect=full_run) as verify):
                with self.assertRaisesRegex(RuntimeError, "fresh full qualification failed"):
                    repoctl._native_uac_fresh_qualification(
                        context, CAMPAIGN, VM_ID, "Prepare")
            verify.assert_called_once_with(BASE_SHA, SHA, profile="full")
            self.assertFalse(evidence.exists())
            self.assertFalse(audit.exists())

    def test_forged_json_without_fresh_witness_cannot_authorize_uac(self) -> None:
        token = repoctl._NATIVE_UAC_FRESH_QUALIFICATION.set(None)
        try:
            with mock.patch.object(repoctl, "_valid_exact_evidence",
                                   return_value=Path("forged.json")) as evidence:
                accepted, reason = repoctl._native_uac_qualification_matches(
                    self.binding, TRUSTED_ROOT)
        finally:
            repoctl._NATIVE_UAC_FRESH_QUALIFICATION.reset(token)
        self.assertFalse(accepted)
        self.assertIn("fresh exact-base qualification witness is absent", reason)
        evidence.assert_not_called()

    def test_post_uac_revocation_denies_before_runner(self) -> None:
        context = {"trusted_root": Path(TRUSTED_ROOT), "target_root": repoctl.ROOT,
                   "base_sha": BASE_SHA, "head_sha": SHA, "pr_number": 169}
        with (mock.patch.object(repoctl.sys, "flags", mock.Mock(isolated=1)),
              mock.patch.object(repoctl, "_native_uac_trusted_context",
                                return_value=context),
              mock.patch.object(repoctl, "_native_uac_pinned_gh", return_value=PINNED_GH),
              mock.patch.object(repoctl, "git", return_value=self.binding.head_branch),
              mock.patch.object(exact_pr_binding, "resolve_exact_open_pr",
                                return_value=self.binding),
              mock.patch.object(repoctl, "_require_trusted_pr_execution"),
              mock.patch.object(repoctl, "_native_uac_runner_manifest"),
              mock.patch.object(repoctl, "_native_uac_worktree_matches",
                                return_value=(True, "clean")),
              mock.patch.object(repoctl, "_native_uac_qualification_matches",
                                return_value=(True, "fresh")),
              mock.patch.object(repoctl, "_native_uac_review_gate",
                                side_effect=[(True, "approved"), (False, "owner revoked")]) as gate,
              mock.patch.object(repoctl, "run") as elevated):
            self.assertNotEqual(repoctl.lab_network_native_boot_authority_check(
                CAMPAIGN, VM_ID, "f" * 64), 0)
        self.assertEqual(gate.call_count, 2)
        elevated.assert_not_called()

    def test_post_uac_missing_review_or_owner_denies_immediately(self) -> None:
        context = {"trusted_root": Path(TRUSTED_ROOT), "target_root": repoctl.ROOT,
                   "base_sha": BASE_SHA, "head_sha": SHA, "pr_number": 169}
        for reason in ("CODE missing", "SECURITY revoked", "OWNER absent"):
            with (self.subTest(reason=reason),
                mock.patch.object(repoctl.sys, "flags", mock.Mock(isolated=1)),
                mock.patch.object(repoctl, "_native_uac_trusted_context",
                                  return_value=context),
                mock.patch.object(repoctl, "_native_uac_pinned_gh", return_value=PINNED_GH),
                mock.patch.object(repoctl, "git", return_value=self.binding.head_branch),
                mock.patch.object(exact_pr_binding, "resolve_exact_open_pr",
                                  return_value=self.binding),
                mock.patch.object(repoctl, "_require_trusted_pr_execution"),
                mock.patch.object(repoctl, "_native_uac_runner_manifest"),
                mock.patch.object(repoctl, "_native_uac_worktree_matches",
                                  return_value=(True, "clean")),
                mock.patch.object(repoctl, "_native_uac_qualification_matches",
                                  return_value=(True, "fresh")),
                mock.patch.object(repoctl, "_native_uac_review_gate",
                                  return_value=(False, reason)),
                mock.patch.object(repoctl, "run") as elevated):
                self.assertNotEqual(repoctl.lab_network_native_boot_authority_check(
                    CAMPAIGN, VM_ID, "f" * 64), 0)
                elevated.assert_not_called()

    def test_native_gh_lock_is_loaded_from_exact_base(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            trusted = Path(temporary).resolve()
            with mock.patch.object(managed_gh, "resolve_managed_gh",
                                   return_value=PINNED_GH) as resolve:
                self.assertEqual(repoctl._native_uac_pinned_gh(str(trusted)), PINNED_GH)
            resolve.assert_called_once_with(trusted)

    def test_selftest_cli_requires_vm_id_before_any_uac(self) -> None:
        result = subprocess.run(
            [sys.executable, str(repoctl.ROOT / "scripts/repoctl.py"),
             "lab-network-native-boot-self-test", "--campaign-id", CAMPAIGN],
            text=True, capture_output=True, timeout=20)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--expected-vm-id", result.stderr)


class ManagedGhPinTests(unittest.TestCase):
    def fixture(self, root: Path) -> tuple[Path, Path, Path]:
        repository = root / "repository"
        lock_path = repository / "config/contracts/toolchain-lock.json"
        lock_path.parent.mkdir(parents=True)
        tool_home = root / "tool-home"
        version = "2.101.0"
        binary = tool_home / f"share/ecommerce-1/tools/gh-{version}/bin/gh"
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"verified fixture GitHub CLI binary")
        binary.chmod(0o755)
        link = tool_home / "bin/gh"
        link.parent.mkdir(parents=True)
        link.symlink_to(binary)
        archive = tool_home / f"cache/gh-{version}-linux-amd64.tar.gz"
        archive.parent.mkdir(parents=True)
        with tarfile.open(archive, "w:gz") as package:
            member = tarfile.TarInfo(f"gh_{version}_linux_amd64/bin/gh")
            content = binary.read_bytes()
            member.size = len(content)
            member.mode = 0o755
            package.addfile(member, io.BytesIO(content))
        lock = {
            "versions": {
                "GH_VERSION": version,
                "GH_SHA256_LINUX_AMD64_TARGZ": hashlib.sha256(
                    archive.read_bytes()).hexdigest(),
            },
            "tool_lifecycle": {"active": {"gh": {
                "version_ref": "GH_VERSION",
                "checksum_ref": "GH_SHA256_LINUX_AMD64_TARGZ",
                "provision": {"type": "ansible", "tags": "gh"},
            }}},
            "capability_policy": {"managed_install_root": {
                "environment": "ECOMMERCE_TOOL_HOME",
                "fallback": "~/.local",
                "bin_subdirectory": "bin",
                "share_subdirectory": "share/ecommerce-1",
                "cache_subdirectory": "cache",
                "fallback_cache_root": "~/.cache/ecommerce-1",
            }},
        }
        lock_path.write_text(json.dumps(lock), encoding="utf-8")
        return repository, tool_home, binary

    @staticmethod
    def fake_run(argv, **_kwargs):
        if argv[1:] == ["--version"]:
            return subprocess.CompletedProcess(
                argv, 0, "gh version 2.101.0 (fixture)\\n", "")
        if argv[1:] == ["api", "--help"]:
            return subprocess.CompletedProcess(
                argv, 0, "Flags: --paginate --slurp\\n", "")
        raise AssertionError(argv)

    def test_pinned_binary_is_resolved_from_verified_archive(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository, tool_home, binary = self.fixture(Path(temporary))
            with (
                mock.patch.dict(managed_gh.os.environ,
                                {"ECOMMERCE_TOOL_HOME": str(tool_home)}),
                mock.patch.object(managed_gh.subprocess, "run",
                                  side_effect=self.fake_run),
            ):
                resolved = managed_gh.resolve_managed_gh(repository)
        self.assertEqual(str(binary), resolved[0])
        self.assertEqual("2.101.0", resolved[1])
        self.assertEqual(hashlib.sha256(
            b"verified fixture GitHub CLI binary").hexdigest(), resolved[2])

    def test_missing_or_wrong_version_or_modified_binary_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository, tool_home, binary = self.fixture(Path(temporary))
            with mock.patch.dict(managed_gh.os.environ,
                                 {"ECOMMERCE_TOOL_HOME": str(tool_home)}):
                with (mock.patch.object(
                          managed_gh.subprocess, "run",
                          side_effect=lambda argv, **_kw: subprocess.CompletedProcess(
                              argv, 0,
                              "gh version 2.45.0 (fixture)\\n"
                              if argv[1:] == ["--version"]
                              else "Flags: --paginate --slurp\\n", "")),
                      self.assertRaisesRegex(ValueError, "version")):
                    managed_gh.resolve_managed_gh(repository)
                binary.write_bytes(b"tampered gh")
                with self.assertRaisesRegex(ValueError, "differs"):
                    managed_gh.resolve_managed_gh(repository)
                binary.unlink()
                with self.assertRaises(ValueError):
                    managed_gh.resolve_managed_gh(repository)


if __name__ == "__main__":
    unittest.main()
