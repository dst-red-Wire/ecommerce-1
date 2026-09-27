"""Fail-closed tests for the one public branch-publication workflow."""

import contextlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("repoctl_publication_test", ROOT / "scripts/repoctl.py")
assert SPEC and SPEC.loader
REPOCTL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPOCTL)


class PublicationAuthorityTests(unittest.TestCase):
    def test_make_deliver_is_the_only_public_publication_target(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn("deliver: signing-rotation-check", makefile)
        self.assertIn("scripts/repoctl.py deliver", makefile)
        self.assertNotIn("\npublish:", makefile)
        self.assertNotIn("\npublish-change:", makefile)
        publication = REPOCTL.repository_delivery_policy()["publication"]
        self.assertEqual("make deliver", publication["canonical_entrypoint"])
        self.assertEqual("deliver", publication["repoctl_entrypoint"])
        self.assertTrue(publication["pull_request_creation"]["required"])
        self.assertTrue(publication["exact_sha"]["required"])
        self.assertTrue(publication["signed_commit"]["required"])
        self.assertTrue(publication["qualification_before_push"]["required"])
        self.assertTrue(publication["default_branch_write"]["forbidden"])
        self.assertTrue(publication["force_push"]["forbidden"])

    def test_scope_allowlist_blocks_ci_and_keeps_trusted_bundle_delivery(self):
        from canonical_workspace import command_allowed

        allowlist = yaml.safe_load((ROOT / "architecture.lock.yaml").read_text(encoding="utf-8"))[
            "repository_governance"
        ]["canonical_workspace"]["command_allowlist"]
        commands = set(allowlist["local"])
        self.assertTrue(command_allowed("deliver", "local", commands))
        self.assertTrue(command_allowed("deliver", "isolated-delivery", commands))
        self.assertFalse(command_allowed("deliver", "ci", commands))
        self.assertFalse(command_allowed("publish", "local", commands))
        self.assertFalse(command_allowed("publish-change", "local", commands))
        source = (ROOT / "scripts/repository_delivery.py").read_text(encoding="utf-8")
        self.assertIn('trusted_env["ECOMMERCE_EXECUTION_SCOPE"] = "isolated-delivery"', source)

    def test_publish_and_publish_change_are_not_cli_commands(self):
        for command in ("publish", "publish-change"):
            with self.subTest(command=command), mock.patch.object(
                REPOCTL.sys, "argv", ["repoctl.py", command]
            ), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    REPOCTL.main()
                self.assertEqual(2, raised.exception.code)

    def test_repoctl_deliver_cli_fails_in_ci_scope(self):
        with mock.patch.object(
            REPOCTL.sys, "argv", ["repoctl.py", "deliver", "--title", "Blocked"]
        ), mock.patch(
            "canonical_workspace.check",
            return_value={"status": "PASS", "execution_scope": "ci"},
        ), mock.patch.object(REPOCTL, "deliver") as handler:
            with contextlib.redirect_stderr(io.StringIO()):
                rc = REPOCTL.main()
        self.assertEqual(1, rc)
        handler.assert_not_called()

    def test_publication_mutation_sites_are_ast_allowlisted(self):
        REPOCTL.publication_mutation_site_check()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            (root / "Makefile").write_text("deliver:\n\t@python3 scripts/repoctl.py deliver\n")
            (root / "scripts/repoctl.py").write_text(
                'def publish():\n    run(["git", "push", "origin", "HEAD"])\n'
                'def _delete_branch_ref():\n'
                '    run(["git", "push", f"--force-with-lease={ref}:{sha}", "origin", f":{ref}"])\n'
                'def deliver():\n'
                '    run([gh, "pr", "create"])\n'
                '    run([gh, "api", "--method", "PATCH", "--raw-field", body])\n'
                'def rogue():\n    command = ["git", "push", "origin", "HEAD"]\n    run(command)\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RuntimeError, "mutation sites"):
                REPOCTL.publication_mutation_site_check(source_root=root)

    def test_unsigned_commit_is_rejected_locally(self):
        sha = "a" * 40
        failed = subprocess.CompletedProcess(["git"], 1, "", "invalid signature")
        with mock.patch.object(REPOCTL, "git", return_value=sha + "\n"), mock.patch.object(
            REPOCTL, "run", return_value=failed
        ), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(2, REPOCTL._verify_local_delivery_signatures("origin/main", sha))

    def test_remote_branch_readback_rejects_wrong_ref(self):
        wrong = subprocess.CompletedProcess(["git"], 0, "a" * 40 + "\trefs/heads/other\n", "")
        with mock.patch.object(REPOCTL, "run", return_value=wrong):
            with self.assertRaisesRegex(RuntimeError, "invalid head"):
                REPOCTL._remote_branch_head("feature")


class PublishPrimitiveTests(unittest.TestCase):
    HEAD = "a" * 40
    NEW_HEAD = "c" * 40
    BRANCH = "feature/canonical-delivery"

    def invoke(self, *, branch=None, dirty=False, remote_heads=None, signature_rc=0):
        head = [self.HEAD]
        completed = subprocess.CompletedProcess([], 0, "", "")

        def git(*args):
            if args == ("branch", "--show-current"):
                return (branch or self.BRANCH) + "\n"
            if args[:2] == ("status", "--porcelain"):
                return " M scripts/repoctl.py\n" if dirty else ""
            if args == ("rev-parse", "HEAD"):
                return head[0] + "\n"
            raise AssertionError(args)

        def run(command, **_kwargs):
            if command[:2] == ["git", "commit"]:
                head[0] = self.NEW_HEAD
            return completed

        verify = mock.Mock(return_value=0)
        run_mock = mock.Mock(side_effect=run)
        stdout = io.StringIO()
        with mock.patch.object(REPOCTL, "toolchain_closure", return_value=0), mock.patch.object(
            REPOCTL, "repository_delivery_policy", return_value={"default_branch": "main"}
        ), mock.patch.object(REPOCTL, "git", side_effect=git), mock.patch.object(
            REPOCTL, "run", run_mock
        ), mock.patch.object(
            REPOCTL, "commit_provenance_check", return_value=0
        ), mock.patch.object(
            REPOCTL, "_load_promotable_worktree_evidence", return_value=None
        ), mock.patch.object(
            REPOCTL, "_valid_exact_evidence", return_value=None if dirty else ROOT / "proof.json"
        ), mock.patch.object(
            REPOCTL, "verify_change", verify
        ), mock.patch.object(
            REPOCTL, "_verify_local_delivery_signatures", return_value=signature_rc
        ), mock.patch.object(
            REPOCTL, "_remote_branch_head", side_effect=remote_heads or [self.HEAD, self.HEAD]
        ), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            rc = REPOCTL.publish("main", "Signed canonical delivery")
        return rc, stdout.getvalue(), run_mock, verify

    def test_rerun_does_not_commit_or_push_unchanged_head(self):
        rc, text, run_mock, verify = self.invoke()
        self.assertEqual(0, rc)
        self.assertIn("no push needed", text)
        verify.assert_not_called()
        self.assertFalse(any(call.args[0][:2] in (["git", "commit"], ["git", "push"])
                             for call in run_mock.call_args_list))

    def test_new_commit_is_requalified_at_new_exact_sha_before_push(self):
        rc, text, run_mock, verify = self.invoke(
            dirty=True, remote_heads=["", self.NEW_HEAD]
        )
        self.assertEqual(0, rc)
        verify.assert_called_once_with("origin/main", self.NEW_HEAD)
        pushes = [call.args[0] for call in run_mock.call_args_list if call.args[0][:2] == ["git", "push"]]
        self.assertEqual([["git", "push", "-u", "origin", f"HEAD:refs/heads/{self.BRANCH}"]], pushes)
        self.assertIn(f"sha={self.NEW_HEAD}", text)

    def test_remote_head_mismatch_after_push_fails(self):
        rc, _, _, _ = self.invoke(remote_heads=["", "d" * 40])
        self.assertNotEqual(0, rc)

    def test_invalid_signature_blocks_push(self):
        rc, _, run_mock, _ = self.invoke(signature_rc=1)
        self.assertNotEqual(0, rc)
        self.assertFalse(any(call.args[0][:2] == ["git", "push"] for call in run_mock.call_args_list))

    def test_main_branch_is_never_pushed(self):
        rc, _, run_mock, _ = self.invoke(branch="main")
        self.assertNotEqual(0, rc)
        self.assertFalse(any(call.args[0][:2] == ["git", "push"] for call in run_mock.call_args_list))


class DeliveryFlowTests(unittest.TestCase):
    HEAD = "a" * 40
    BASE = "b" * 40
    BRANCH = "feature/canonical-delivery"
    URL = "https://github.com/dst-red-Wire/ecommerce-1/pull/42"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        (root / "evidence").mkdir()
        (root / "evidence" / f"{self.HEAD}.json").write_text(
            json.dumps({"base_sha": self.BASE, "gates": []}), encoding="utf-8"
        )
        self.body = root / "pr-body.md"
        self.body.write_text("Proof body", encoding="utf-8")
        self.context = root

    def pr(self, **changes):
        value = {
            "number": 42,
            "url": self.URL,
            "state": "OPEN",
            "baseRefName": "main",
            "headRefName": self.BRANCH,
            "headRefOid": self.HEAD,
        }
        value.update(changes)
        return value

    def deliver(self, *, candidates=None, pr=None, run_error=None, remote_head=None):
        candidates = candidates if candidates is not None else [[], [{"number": 42, "url": self.URL}]]
        pr = pr if pr is not None else self.pr()
        completed = subprocess.CompletedProcess([], 0, "", "")

        def git(*args):
            if args == ("branch", "--show-current"):
                return self.BRANCH + "\n"
            if args == ("rev-parse", "HEAD"):
                return self.HEAD + "\n"
            raise AssertionError(args)

        run_mock = mock.Mock(side_effect=run_error) if run_error else mock.Mock(return_value=completed)
        stdout = io.StringIO()
        with mock.patch.object(REPOCTL, "CONTEXT", self.context), mock.patch.object(
            REPOCTL, "repository_delivery_policy",
            return_value={"default_branch": "main", "publication": {"canonical_entrypoint": "make deliver"}},
        ), mock.patch.object(
            REPOCTL, "publish", return_value=0
        ) as publish, mock.patch.object(
            REPOCTL.shutil, "which", return_value="gh"
        ), mock.patch.object(
            REPOCTL, "git", side_effect=git
        ), mock.patch.object(
            REPOCTL, "remote_commit_provenance_check", return_value=0
        ), mock.patch.object(
            REPOCTL, "_delivery_pr_body", return_value=self.body
        ), mock.patch.object(
            REPOCTL, "_delivery_open_prs", side_effect=candidates
        ), mock.patch.object(
            REPOCTL, "output", return_value=json.dumps(pr)
        ), mock.patch.object(
            REPOCTL, "run", run_mock
        ), mock.patch.object(
            REPOCTL, "_remote_branch_head", return_value=remote_head or self.HEAD
        ), mock.patch.object(
            REPOCTL, "_record_delivery_wall"
        ), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            rc = REPOCTL.deliver("main", "Canonical publication", "")
        publish.assert_called_once_with("main", "Canonical publication")
        return rc, stdout.getvalue(), run_mock

    def test_first_delivery_creates_one_pr_and_verifies_exact_heads(self):
        rc, text, run_mock = self.deliver()
        self.assertEqual(0, rc)
        self.assertIn("PUSH_RESULT=PASS", text)
        self.assertIn("PR_HEAD_MATCH=PASS", text)
        self.assertIn("FINAL_STATUS=PASS", text)
        self.assertIn("created PR", text)
        self.assertEqual(1, run_mock.call_count)
        self.assertIn("create", run_mock.call_args.args[0])

    def test_rerun_reuses_existing_pr_without_creating_another(self):
        existing = {"number": 42, "url": self.URL}
        rc, text, run_mock = self.deliver(candidates=[[existing], [existing]])
        self.assertEqual(0, rc)
        self.assertIn("refreshed PR", text)
        self.assertEqual(1, run_mock.call_count)
        self.assertIn("PATCH", run_mock.call_args.args[0])
        self.assertNotIn("create", run_mock.call_args.args[0])

    def test_multiple_open_prs_fail_closed(self):
        with mock.patch.object(
            REPOCTL, "output", return_value=json.dumps([{"number": 1}, {"number": 2}])
        ):
            with self.assertRaisesRegex(RuntimeError, "multiple open PRs"):
                REPOCTL._delivery_open_prs("gh", self.BRANCH, "main", self.HEAD)

    def test_stale_existing_pr_is_rejected_before_update(self):
        stale = self.pr(headRefOid="c" * 40)
        with mock.patch.object(REPOCTL, "output", return_value=json.dumps([stale])):
            with self.assertRaisesRegex(RuntimeError, "before update"):
                REPOCTL._delivery_open_prs("gh", self.BRANCH, "main", self.HEAD)

    def test_pr_creation_failure_after_push_is_partial(self):
        rc, text, _ = self.deliver(run_error=RuntimeError("GitHub unavailable"))
        self.assertEqual(1, rc)
        self.assertIn("PUSH_RESULT=PASS", text)
        self.assertIn("PR_RESULT=FAIL", text)
        self.assertIn("FINAL_STATUS=PARTIAL_DELIVERY", text)

    def test_pr_head_mismatch_is_partial(self):
        rc, text, _ = self.deliver(pr=self.pr(headRefOid="c" * 40))
        self.assertEqual(1, rc)
        self.assertIn("FINAL_STATUS=PARTIAL_DELIVERY", text)

    def test_remote_head_mismatch_is_partial(self):
        rc, text, _ = self.deliver(remote_head="c" * 40)
        self.assertEqual(1, rc)
        self.assertIn("FINAL_STATUS=PARTIAL_DELIVERY", text)

    def test_non_open_or_wrong_base_pr_is_partial(self):
        for changes in ({"state": "MERGED"}, {"baseRefName": "other"}):
            with self.subTest(changes=changes):
                rc, text, _ = self.deliver(pr=self.pr(**changes))
                self.assertEqual(1, rc)
                self.assertIn("FINAL_STATUS=PARTIAL_DELIVERY", text)


if __name__ == "__main__":
    unittest.main()
