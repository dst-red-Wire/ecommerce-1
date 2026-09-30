"""One dynamically resolved PR and exact owner evidence must precede native UAC."""

from __future__ import annotations

import contextlib
from dataclasses import replace
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import exact_pr_binding
import repoctl


CAMPAIGN = "20260929T163821Z-9da62296f3d5"
SHA = "a" * 40
SHA_ALT = "c" * 40
BASE_SHA = "b" * 40
VM_ID = "e80d60f3-a12e-4734-a654-0cd24dce0fa1"
OWNER = "dst-red-Wire"
REPOSITORY = "dst-red-Wire/ecommerce-1"
TRUSTED_ROOT = "/tmp/exact-base-test"


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
            self.assertEqual(gh, "/usr/bin/gh")
            if binding != self.remote_binding:
                raise exact_pr_binding.ExactPRBindingChanged("PR_CHANGED")
            return binding

        with (mock.patch.object(exact_pr_binding, "revalidate_exact_open_pr",
                                side_effect=revalidate),
              mock.patch.object(repoctl, "_native_uac_paginated_comments",
                                side_effect=issue_comments_only)):
            return repoctl._native_uac_review_gate(
                "/usr/bin/gh", self.binding, CAMPAIGN, VM_ID)

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
                "/usr/bin/gh", self.binding, CAMPAIGN, VM_ID)[0])

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
            self.assertEqual(repoctl._native_uac_paginated_comments("/usr/bin/gh", endpoint),
                             [one, two])
        self.assertEqual(run.call_args.args[0], ["/usr/bin/gh", "api", "--paginate", endpoint])
        with mock.patch.object(repoctl, "run", return_value=subprocess.CompletedProcess([], 0, "{}", "")):
            with self.assertRaises(RuntimeError):
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
        stack.enter_context(mock.patch.object(repoctl.os.path, "isfile", return_value=True))
        stack.enter_context(mock.patch.object(repoctl.os, "access", return_value=True))
        stack.enter_context(mock.patch.object(Path, "is_file", return_value=True))
        stack.enter_context(mock.patch.dict(repoctl.os.environ,
                                           {"WSL_DISTRO_NAME": "Ubuntu-24.04"}))
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

            def git(*args: str) -> str:
                result = subprocess.run(
                    ["git", "-C", str(root), *args], capture_output=True,
                    text=True, check=True)
                return result.stdout.strip()

            git("init", "-q")
            git("add", "scripts/repoctl.py", "scripts/repository_delivery.py")
            git("-c", "user.name=Native Test", "-c", "user.email=native@example.test",
                "-c", "commit.gpgsign=false", "commit", "-qm", "exact base")
            binding = replace(self.binding, base_sha=git("rev-parse", "HEAD"))
            controller = scripts / "repoctl.py"
            self.assertEqual(
                repoctl._native_uac_trusted_controller(binding, str(root)), controller)
            self.assertFalse(repoctl._native_uac_qualification_matches(binding, "")[0])

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
                                        return_value=Path("audit.json")) as audit):
                    self.assertTrue(repoctl._native_uac_qualification_matches(
                        binding, str(root))[0])
            evidence.assert_called_once_with(binding.base_sha, SHA)
            audit.assert_called_once_with(binding.base_sha, SHA)
            self.assertNotEqual(repoctl._controller_command()[1], str(controller))

            with mock.patch.object(repoctl, "_valid_exact_evidence", return_value=None):
                self.assertFalse(repoctl._native_uac_qualification_matches(
                    binding, str(root))[0])
            self.assertFalse(repoctl._native_uac_qualification_matches(
                replace(binding, base_sha=SHA_ALT), str(root))[0])
            controller.write_text("tampered\n", encoding="utf-8")
            self.assertFalse(repoctl._native_uac_qualification_matches(
                binding, str(root))[0])

    def test_prepare_reuses_one_binding_at_three_boundaries(self) -> None:
        self.configure_pr(170, SHA_ALT)
        stack, gate, prepare, bootstrap, run = self._boot_context()
        with stack:
            self.assertEqual(repoctl.lab_network_native_boot(
                "Prepare", CAMPAIGN, VM_ID, TRUSTED_ROOT), 0)
        self.assertEqual(gate.call_count, 3)
        self.assertTrue(all(call.args[1] is self.binding for call in gate.call_args_list))
        prepare.assert_called_once_with(CAMPAIGN)
        self.assertIs(bootstrap.call_args.args[-1], self.binding)
        run.assert_called_once()

    def test_head_change_after_staging_or_before_uac_denies_elevation(self) -> None:
        for reads, expected_gates in (
            ([SHA, SHA, SHA_ALT], 1),
            ([SHA, SHA, SHA, SHA_ALT], 2),
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

    def test_selftest_cli_requires_vm_id_before_any_uac(self) -> None:
        result = subprocess.run(
            [sys.executable, str(repoctl.ROOT / "scripts/repoctl.py"),
             "lab-network-native-boot-self-test", "--campaign-id", CAMPAIGN],
            text=True, capture_output=True, timeout=20)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--expected-vm-id", result.stderr)


if __name__ == "__main__":
    unittest.main()
