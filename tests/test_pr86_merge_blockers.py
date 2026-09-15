"""Scoped frontend requirements, including offline execution without templ."""

import json
import os
import subprocess
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from test_docker_product_preflight import REPOCTL as ctl


class FrontendTemplScopeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="pr86-frontend-offline-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "frontend").mkdir()
        self.log = self.root / "invocations.jsonl"
        self.pins = ctl.pinned_versions()
        pins = self.root / "config/toolchain/versions.env"
        pins.parent.mkdir(parents=True)
        pins.write_bytes((ctl.ROOT / "config/toolchain/versions.env").read_bytes())
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        for name in ("go", "gofmt"):
            self.binary(self.root / ".local/bin" / name)
        for patch in [
            mock.patch.object(ctl, "ROOT", self.root),
            mock.patch.object(Path, "home", return_value=self.root),
            mock.patch.dict(os.environ, {"GOPROXY": "off", "GOSUMDB": "off"}),
        ]:
            patch.start()
            self.addCleanup(patch.stop)

    def binary(self, path):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            f"#!{sys.executable}\nimport json,os,sys\n"
            f"with open({str(self.log)!r}, 'a') as log: "
            "log.write(json.dumps({'args':sys.argv,'cgo':os.getenv('CGO_ENABLED'),"
            "'proxy':os.getenv('GOPROXY')})+'\\n')\n"
        )
        path.chmod(0o755)

    def test_offline_lint_test_build_do_not_resolve_or_reconcile_templ(self):
        for action, command in [("lint", "vet"), ("test", "test"), ("build", "build")]:
            with self.subTest(action=action):
                self.log.unlink(missing_ok=True)

                def reconcile(tags):
                    self.assertEqual("go,cgo", tags)
                    if "templ" in tags:
                        raise RuntimeError("offline: templ unavailable")

                with (
                    mock.patch.object(ctl, "ensure_developer", side_effect=reconcile) as ensure,
                    mock.patch.object(ctl, "pinned_versions", side_effect=AssertionError("templ resolution forbidden")),
                ):
                    self.assertEqual(0, ctl.frontend(action, "all"))
                ensure.assert_called_once_with("go,cgo")
                calls = [json.loads(line) for line in self.log.read_text().splitlines()]
                self.assertTrue(any(x["args"][1] == command for x in calls))
                self.assertTrue(all(x["proxy"] == "off" for x in calls))
                self.assertFalse(any("templ" in Path(x["args"][0]).name for x in calls))
                if action == "test":
                    self.assertEqual("1", calls[0]["cgo"])

    def test_check_requires_templ_even_offline(self):
        with mock.patch.object(
            ctl, "ensure_developer", side_effect=RuntimeError("offline: templ unavailable")
        ) as ensure:
            with self.assertRaisesRegex(RuntimeError, "offline: templ unavailable"):
                ctl.frontend("check", "all")
        ensure.assert_called_once_with("go,cgo,templ")
        self.assertFalse(self.log.exists())
        with mock.patch.object(ctl, "ensure_developer"):
            with self.assertRaisesRegex(RuntimeError, "templ provider is unavailable"):
                ctl.frontend("check", "all")

    def test_check_uses_the_canonical_managed_templ_provider(self):
        templ = self.root / ".local/share/ecommerce-1/tools/templ" / self.pins["TEMPL_VERSION"] / "linux-amd64/templ"
        self.binary(templ)
        with mock.patch.object(ctl, "ensure_developer") as ensure:
            self.assertEqual(0, ctl.frontend("check", "all"))
        ensure.assert_called_once_with("go,cgo,templ")
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        generation = [x for x in calls if x["args"][1] == "generate"]
        self.assertEqual([[str(templ), "generate"]], [x["args"] for x in generation])


class FrontendAnsibleTagTests(unittest.TestCase):
    def test_actual_playbook_excludes_templ_from_go_cgo_and_keeps_it_for_check(self):
        # Use Ansible's actual tag selection on the production playbook. Listing
        # tasks performs no host reconciliation and needs no network/provider.
        for tags, needs_templ in [("go,cgo", False), ("go,cgo,templ", True)]:
            with self.subTest(tags=tags):
                result = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "ansible.cli.playbook",
                        "-i",
                        "localhost,",
                        "-c",
                        "local",
                        "platform/ansible/developer.yml",
                        "--list-tasks",
                        "--tags",
                        tags,
                    ],
                    cwd=ctl.ROOT,
                    env=dict(os.environ, GOPROXY="off", GOSUMDB="off", ANSIBLE_NOCOLOR="1"),
                    capture_output=True,
                    text=True,
                    check=True,
                )
                selected = [
                    line.split("TAGS:")[0].strip()
                    for line in result.stdout.splitlines()
                    if "developer_toolchain :" in line
                ]
                self.assertTrue(any("Download pinned Go archive" in task for task in selected))
                self.assertTrue(any("CGO" in task for task in selected))
                templ_tasks = [task for task in selected if "templ" in task.lower()]
                if needs_templ:
                    self.assertTrue(any("Compile missing or invalid pinned templ" in task for task in templ_tasks))
                    self.assertTrue(any("Probe pinned templ" in task for task in templ_tasks))
                else:
                    self.assertEqual([], templ_tasks)
