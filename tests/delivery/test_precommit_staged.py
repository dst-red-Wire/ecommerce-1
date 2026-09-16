import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
from unittest import mock
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("staged_behavior", ROOT / "scripts/repoctl.py")
REPOCTL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPOCTL)


class PrecommitStagedContractTest(unittest.TestCase):
    def test_hooks_declare_explicit_stages(self):
        config = (ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
        self.assertIn("stages: [pre-commit]", config)
        self.assertIn("stages: [pre-push]", config)

    def test_fast_hook_materializes_only_the_index(self):
        controller = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        function = controller.split("def precommit()", 1)[1].split("\ndef prepush()", 1)[0]
        self.assertIn('"--cached"', function)
        self.assertIn("_materialize_staged_tree(snapshot)", function)
        self.assertNotIn("verify_change", function)
        self.assertIn('"gitleaks"', function)

    @contextlib.contextmanager
    def fixture(self):
        env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, env, clear=True):
            root = Path(directory)

            def git(*args):
                return subprocess.check_output(
                    ["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", *args],
                    cwd=root,
                    stderr=subprocess.DEVNULL,
                    text=True,
                ).strip()

            git("init")
            (root / ".gitleaks.toml").write_bytes((ROOT / ".gitleaks.toml").read_bytes())
            versions_path = root / "config/toolchain/versions.env"
            versions_path.parent.mkdir(parents=True)
            versions_path.write_bytes((ROOT / "config/toolchain/versions.env").read_bytes())
            git("add", ".gitleaks.toml", "config/toolchain/versions.env")
            git("commit", "-m", "Initialize fixture")
            versions = REPOCTL.pinned_versions()
            with (
                mock.patch.object(REPOCTL, "ROOT", root),
                mock.patch.object(REPOCTL, "pinned_versions", return_value=versions),
            ):
                yield root, git

    def test_partial_commit_preserves_index_and_unstaged_content(self):
        with self.fixture() as (root, git):
            path = root / "example.py"
            path.write_text("value = 1\n")
            git("add", "--", path.name)
            index = git("write-tree")
            path.write_text("def invalid(\n")
            self.assertEqual(0, REPOCTL.precommit())
            self.assertEqual(index, git("write-tree"))
            self.assertEqual("def invalid(\n", path.read_text())

    def test_replacement_head_cannot_hide_invalid_staged_change(self):
        with self.fixture() as (root, git):
            (root / "invalid.py").write_text("undefined_name()\n")
            git("add", "invalid.py")
            original = git("rev-parse", "HEAD")
            replacement = git("commit-tree", git("write-tree"), "-m", "Replacement fixture")
            git("replace", original, replacement)
            self.assertEqual("", git("diff", "--cached", "--name-only"))
            with self.assertRaises(RuntimeError):
                REPOCTL.precommit()

    def test_replacement_blob_cannot_change_indexed_bytes(self):
        with self.fixture() as (root, git):
            path = root / "invalid.py"
            path.write_text("undefined_name()\n")
            git("add", path.name)
            indexed = git("rev-parse", ":invalid.py")
            path.write_text("value = 1\n")
            replacement = git("hash-object", "-w", path.name)
            git("replace", indexed, replacement)
            with tempfile.TemporaryDirectory() as directory:
                REPOCTL._materialize_staged_tree(Path(directory))
                self.assertEqual("undefined_name()\n", (Path(directory) / path.name).read_text())
            with self.assertRaises(RuntimeError):
                REPOCTL.precommit()

    def test_filesystem_equivalent_index_paths_cannot_overwrite_a_blob(self):
        with self.fixture() as (root, git), tempfile.TemporaryDirectory() as directory:
            (root / "first").write_text("first indexed content")
            (root / "second").write_text("second indexed content")
            first = git("hash-object", "-w", "first")
            second = git("hash-object", "-w", "second")
            git("update-index", "--add", "--cacheinfo", f"100644,{first},CASE.txt")
            git("update-index", "--add", "--cacheinfo", f"100644,{second},case.txt")
            snapshot = Path(directory)
            original_open = Path.open
            original_chmod = Path.chmod

            def case_insensitive_chmod(path, *args, **kwargs):
                if path.parent == snapshot:
                    path = path.with_name(path.name.lower())
                return original_chmod(path, *args, **kwargs)

            def case_insensitive_open(path, mode="r", *args, **kwargs):
                if path.parent == snapshot:
                    path = path.with_name(path.name.lower())
                return original_open(path, mode, *args, **kwargs)

            with (
                mock.patch.object(Path, "open", case_insensitive_open),
                mock.patch.object(Path, "chmod", case_insensitive_chmod),
            ):
                with self.assertRaisesRegex(RuntimeError, "indexed paths collide"):
                    REPOCTL._materialize_staged_tree(snapshot)
            self.assertEqual("first indexed content", (snapshot / "case.txt").read_text())
            self.assertEqual(first, git("rev-parse", ":CASE.txt"))
            self.assertEqual(second, git("rev-parse", ":case.txt"))

    def test_directory_aliases_cannot_redirect_staged_linter_configuration(self):
        with self.fixture() as (root, git), tempfile.TemporaryDirectory() as directory:
            (root / "fixture-config").write_text('[tool.ruff.lint]\nignore = ["F821"]\n')
            (root / "bad").write_text("undefined_name()\n")
            config = git("hash-object", "-w", "fixture-config")
            bad = git("hash-object", "-w", "bad")
            git("update-index", "--add", "--cacheinfo", f"100644,{config},CASE/pyproject.toml")
            git("update-index", "--add", "--cacheinfo", f"100644,{bad},case/bad.py")
            snapshot = Path(directory)
            original_mkdir, original_stat = Path.mkdir, Path.stat

            def folded(path):
                if path.is_relative_to(snapshot):
                    return snapshot.joinpath(*(part.lower() for part in path.relative_to(snapshot).parts))
                return path

            def mkdir(path, *args, **kwargs):
                return original_mkdir(folded(path), *args, **kwargs)

            def stat(path, *args, **kwargs):
                return original_stat(folded(path), *args, **kwargs)

            with mock.patch.object(Path, "mkdir", mkdir), mock.patch.object(Path, "stat", stat):
                with self.assertRaisesRegex(RuntimeError, "directory aliases collide"):
                    REPOCTL._materialize_staged_tree(snapshot)
            self.assertEqual([], list(snapshot.rglob("*.py")))
            self.assertEqual([], list(snapshot.rglob("*.toml")))

    def test_non_utf8_staged_path_is_scanned_without_decoding_failure(self):
        with self.fixture() as (root, git):
            name = os.fsdecode(b"bad\xff.txt")
            (root / name).write_text("value = 1\n")
            git("add", "--", name)
            index = git("write-tree")
            self.assertEqual(0, REPOCTL.precommit())
            self.assertEqual(index, git("write-tree"))

    def test_staged_terraform_format_drift_is_rejected(self):
        with self.fixture() as (root, git):
            path = root / "main.tf"
            path.write_text('locals {\nvalue= "example"\n}\n')
            git("add", "main.tf")
            path.write_text('locals {\n  value = "example"\n}\n')
            with self.assertRaises(RuntimeError):
                REPOCTL.precommit()

    def test_staged_ansible_configuration_cannot_execute_inventory_or_custom_rules(self):
        with self.fixture() as (root, git):
            marker = root / "inventory-executed"
            rule_marker = root / "rule-executed"
            inventory = root / "inventories/mgmt/inventory.rb"
            inventory.parent.mkdir(parents=True)
            inventory.write_text(f"#!/usr/bin/ruby\nFile.write('{marker}', 'executed')\nputs '{{}}'\n")
            inventory.chmod(0o755)
            config = root / "platform/ansible/ansible.cfg"
            config.parent.mkdir(parents=True)
            config.write_text(f"[defaults]\ninventory = {inventory}\n")
            rules = root / "candidate_rules"
            rules.mkdir()
            (rules / "execute.py").write_text(f'from pathlib import Path\n\nPath("{rule_marker}").touch()\n')
            (root / ".ansible-lint").write_text(f"---\nrulesdir: [{rules}]\n")
            (root / "playbook.yml").write_text("---\n- name: Valid indexed playbook\n  hosts: localhost\n  tasks: []\n")
            git("add", ".")
            index = git("write-tree")
            self.assertEqual(0, REPOCTL.precommit())
            self.assertFalse(marker.exists())
            self.assertFalse(rule_marker.exists())
            self.assertEqual(index, git("write-tree"))

    def test_staged_ansible_sandbox_executes_untrusted_code_without_host_access(self):
        with self.fixture() as (root, _), tempfile.TemporaryDirectory() as directory:
            private = Path(directory)
            sentinel = private / "host-private-sentinel"
            marker = private / "host-write-marker"
            sentinel.write_text("private-fixture-content")
            snapshot, control = root / "snapshot", root / "control"
            snapshot.mkdir()
            control.mkdir()
            (control / "collections").mkdir()
            versions = snapshot / "config/toolchain/versions.env"
            versions.parent.mkdir(parents=True)
            versions.write_bytes((ROOT / "config/toolchain/versions.env").read_bytes())
            (control / "passwd").write_text(f"sandbox:x:{os.getuid()}:{os.getgid()}::/home/sandbox:/nonexistent\n")
            (control / "group").write_text(f"sandbox:x:{os.getgid()}:\n")
            probe = snapshot / "probe.py"
            probe.write_text(
                "import os, pathlib, socket, sys\n"
                f"sentinel = pathlib.Path({str(sentinel)!r})\n"
                f"marker = pathlib.Path({str(marker)!r})\n"
                "result = {'read_blocked': not sentinel.exists(), 'environment_clean': 'HOST_PRIVATE_TOKEN' not in os.environ}\n"
                "try:\n    marker.write_text('escaped')\n    result['write_blocked'] = False\n"
                "except OSError:\n    result['write_blocked'] = True\n"
                "result['private_pid'] = os.getpid() <= 2\n"
                "result['private_network'] = socket.if_nameindex() == [(1, 'lo')]\n"
                "result['stdin_closed'] = sys.stdin.buffer.read() == b''\n"
                "result['bounded_workers'] = pathlib.Path('/sys/fs/cgroup/cpu.max').read_text().split() == ['100000','100000']\n"
                "assert all(result.values()), result\n"
            )
            with mock.patch.dict(os.environ, {"HOST_PRIVATE_TOKEN": "private-environment-fixture"}):
                command, interpreter = REPOCTL._staged_ansible_sandbox(snapshot, control)
                REPOCTL._run_staged_ansible_sandbox(command + [str(interpreter), "-I", "/staged/probe.py"])
            self.assertFalse(marker.exists())

    def test_adjacent_and_candidate_collection_plugins_cannot_escape_staged_lint(self):
        plugin_paths = (
            "filter_plugins/probe.py",
            "lookup_plugins/probe.py",
            ".ansible/collections/ansible_collections/host/probe/plugins/filter/probe.py",
        )
        for plugin_path in plugin_paths:
            with (
                self.subTest(plugin=plugin_path),
                self.fixture() as (root, git),
                tempfile.TemporaryDirectory() as directory,
            ):
                private = Path(directory)
                sentinel, marker = private / "host-sentinel", private / "host-marker"
                sentinel.write_text("private-fixture-content")
                plugin = root / plugin_path
                plugin.parent.mkdir(parents=True)
                plugin.write_text(
                    "import os\nfrom pathlib import Path\n\n"
                    f"assert not Path({str(sentinel)!r}).exists()\n"
                    "assert 'HOST_PRIVATE_TOKEN' not in os.environ\n"
                    f"try:\n    Path({str(marker)!r}).write_text('escaped')\n"
                    "except OSError:\n    pass\n"
                    "else:\n    raise RuntimeError('host write escaped')\n\n"
                    "class FilterModule:\n    def filters(self):\n        return {'probe': lambda value: value}\n\n"
                    "class LookupModule:\n    def run(self, terms, variables=None, **kwargs):\n        return ['localhost']\n"
                )
                subprocess.run([REPOCTL.require("ruff"), "format", str(plugin)], check=True, stdout=subprocess.DEVNULL)
                hosts = "{{ lookup('probe') }}" if "lookup_plugins" in plugin_path else "{{ 'localhost' | probe }}"
                if ".ansible/" in plugin_path:
                    hosts = "{{ 'localhost' | host.probe.probe }}"
                (root / "playbook.yml").write_text(
                    f'---\n- name: Candidate plugin playbook\n  hosts: "{hosts}"\n  tasks: []\n'
                )
                git("add", "--force", plugin_path, "playbook.yml")
                index = git("write-tree")
                # Either lint result is legitimate: unavailable filters may be
                # rejected. The real executable sandbox test above prevents a
                # vacuous pass if this Ansible version defers plugin loading.
                with mock.patch.dict(os.environ, {"HOST_PRIVATE_TOKEN": "private-environment-fixture"}):
                    try:
                        REPOCTL.precommit()
                    except RuntimeError as error:
                        self.assertNotIn("private-fixture-content", str(error))
                        self.assertNotIn("private-environment-fixture", str(error))
                self.assertFalse(marker.exists())
                self.assertEqual(index, git("write-tree"))

    def test_staged_ansible_missing_or_unsupported_sandbox_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(REPOCTL.sys, "platform", "darwin"), mock.patch.object(REPOCTL, "run") as run:
                with self.assertRaisesRegex(RuntimeError, "supported Linux"):
                    REPOCTL._staged_ansible_sandbox(root, root)
                run.assert_not_called()
            with (
                mock.patch.object(REPOCTL, "require", side_effect=RuntimeError("missing bwrap")),
                mock.patch.object(REPOCTL, "run") as run,
            ):
                with self.assertRaisesRegex(RuntimeError, "missing bwrap"):
                    REPOCTL._staged_ansible_sandbox(root, root)
                run.assert_not_called()
            versions = root / "config/toolchain/versions.env"
            versions.parent.mkdir(parents=True)
            versions.write_text("BWRAP_VERSION=0.0.0\n")
            with mock.patch.object(REPOCTL, "pinned_versions", return_value={"BWRAP_VERSION": "0.0.0"}):
                with self.assertRaisesRegex(RuntimeError, "declared pin"):
                    REPOCTL._staged_ansible_sandbox(root, root)

    def test_sandbox_refuses_unverified_collection_generation(self):
        import ansible_collections

        with self.fixture() as (root, _), mock.patch.object(ansible_collections, "installed_ok", return_value=False):
            with self.assertRaisesRegex(RuntimeError, "checksum-locked collection closure"):
                REPOCTL._staged_ansible_sandbox(root, root)

    def test_installed_external_python_runtime_paths_are_mounted(self):
        with self.fixture() as (root, _), tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / "installed-python"
            stdlib = base / "lib/python3.12"
            shared = stdlib / "lib-dynload"
            shared.mkdir(parents=True)
            original_run = REPOCTL.run

            def probe(command, **kwargs):
                result = original_run(command, **kwargs)
                if "sysconfig" in " ".join(command):
                    identity = json.loads(result.stdout)
                    identity.update(
                        base_prefix=str(base), stdlib=str(stdlib), libdir=str(base / "lib"), shared=str(shared)
                    )
                    result.stdout = json.dumps(identity)
                return result

            with mock.patch.object(REPOCTL, "run", side_effect=probe):
                command, _ = REPOCTL._staged_ansible_sandbox(root, root)
            for path in (stdlib, shared, base / "lib"):
                self.assertIn(["--ro-bind", str(path), str(path)], [command[i : i + 3] for i in range(len(command))])

    def test_missing_resource_manager_fails_closed_before_candidate_execution(self):
        with (
            mock.patch.object(REPOCTL, "require", side_effect=RuntimeError("missing user scope")),
            mock.patch.object(REPOCTL.subprocess, "Popen") as popen,
        ):
            with self.assertRaisesRegex(RuntimeError, "missing user scope"):
                REPOCTL._run_staged_ansible_sandbox(["untrusted-candidate"])
            popen.assert_not_called()

    def test_partial_staged_sandbox_pin_cannot_be_hidden_by_worktree(self):
        with self.fixture() as (root, git):
            pin = root / "config/toolchain/versions.env"
            original = pin.read_text()
            pin.write_text(original.replace("BWRAP_VERSION=0.9.0", "BWRAP_VERSION=0.0.0"))
            (root / "playbook.yml").write_text("---\n- name: Pinned runtime\n  hosts: localhost\n  tasks: []\n")
            git("add", "config/toolchain/versions.env", "playbook.yml")
            pin.write_text(original)
            with self.assertRaisesRegex(RuntimeError, "indexed sandbox pin"):
                REPOCTL.precommit()

    def test_staged_playbook_resolves_trusted_kubernetes_collection(self):
        with self.fixture() as (root, git):
            (root / "playbook.yml").write_text(
                "---\n- name: Trusted Kubernetes collection\n  hosts: localhost\n  tasks:\n"
                "    - name: Inspect resources without contacting cluster during lint\n"
                "      kubernetes.core.k8s_info:\n        kind: Pod\n"
            )
            git("add", "playbook.yml")
            self.assertEqual(0, REPOCTL.precommit())

    def test_resource_limits_are_effective_and_input_is_not_inherited(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "completed"
            read_fd, write_fd = os.pipe()
            os.write(write_fd, b"private caller input")
            os.close(write_fd)
            saved = os.dup(0)
            try:
                os.dup2(read_fd, 0)
                source = (
                    "import pathlib,resource,sys\n"
                    "assert sys.stdin.buffer.read() == b''\n"
                    "assert resource.getrlimit(resource.RLIMIT_CPU) == (90,90)\n"
                    "assert resource.getrlimit(resource.RLIMIT_FSIZE) == (16777216,16777216)\n"
                    "try:\n bytearray(600*1024*1024)\n"
                    "except MemoryError:\n pass\n"
                    "else:\n raise AssertionError('memory limit ineffective')\n"
                    f"pathlib.Path({str(marker)!r}).write_text('contained')\n"
                )
                REPOCTL._run_staged_ansible_sandbox([REPOCTL.sys.executable, "-I", "-c", source])
            finally:
                os.dup2(saved, 0)
                os.close(saved)
                os.close(read_fd)
            self.assertEqual("contained", marker.read_text())

    def test_sandbox_resource_envelope_closes_stdin_and_suppresses_diagnostics(self):
        # Exercise the same outer envelope used for every candidate sandbox.
        command = [
            REPOCTL.sys.executable,
            "-I",
            "-c",
            "import sys; assert sys.stdin.buffer.read() == b''; "
            "sys.stderr.write('candidate-secret\\x1b[2J' * 10000); raise SystemExit(1)",
        ]
        with self.assertRaisesRegex(RuntimeError, "^staged Ansible lint failed inside its bounded sandbox$"):
            REPOCTL._run_staged_ansible_sandbox(command)

    def test_sandbox_resource_envelope_terminates_detached_descendants(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "escaped-after-timeout"
            source = (
                "import os,time,pathlib\n"
                "if os.fork() == 0:\n"
                " os.setsid()\n time.sleep(5)\n"
                f" pathlib.Path({str(marker)!r}).write_text('escaped')\n"
                "else:\n time.sleep(10)\n"
            )
            with self.assertRaises(RuntimeError):
                REPOCTL._run_staged_ansible_sandbox([REPOCTL.sys.executable, "-I", "-c", source], timeout=1)
            import time

            time.sleep(5)
            self.assertFalse(marker.exists())

    def test_staged_tekton_task_is_yaml_not_an_ansible_task_list(self):
        with self.fixture() as (root, git):
            task = root / "platform/tekton/tasks/component.yaml"
            task.parent.mkdir(parents=True)
            task.write_text(
                "---\napiVersion: tekton.dev/v1\nkind: Task\nmetadata:\n  name: fixture\n"
                "spec:\n  steps:\n    - name: inspect\n      image: example.invalid/runner:1.0.0\n"
                "      command: [python3]\n      args: ['--version']\n"
            )
            git("add", "platform/tekton/tasks/component.yaml")
            task.write_text("malformed: [\n")
            self.assertEqual(0, REPOCTL.precommit())

    def test_staged_malformed_tekton_yaml_is_rejected(self):
        with self.fixture() as (root, git):
            task = root / "platform/tekton/tasks/component.yaml"
            task.parent.mkdir(parents=True)
            task.write_text("---\napiVersion: [\n")
            git("add", "platform/tekton/tasks/component.yaml")
            task.write_text("---\napiVersion: tekton.dev/v1\n")
            with self.assertRaises(RuntimeError):
                REPOCTL.precommit()

    def test_staged_ansible_task_schema_is_still_enforced(self):
        with self.fixture() as (root, git):
            task = root / "platform/ansible/roles/fixture/tasks/main.yml"
            task.parent.mkdir(parents=True)
            task.write_text("---\nincorrect_mapping: true\n")
            git("add", "platform/ansible/roles/fixture/tasks/main.yml")
            task.write_text("---\n- name: Valid unstaged task\n  ansible.builtin.debug:\n    msg: fixture\n")
            with self.assertRaises(RuntimeError):
                REPOCTL.precommit()

    def test_staged_ansible_syntax_is_rejected_despite_valid_worktree(self):
        with self.fixture() as (root, git):
            path = root / "playbook.yml"
            path.write_text("---\n- hosts: localhost\n  tasks: [\n")
            git("add", "playbook.yml")
            path.write_text("---\n- name: Valid unstaged playbook\n  hosts: localhost\n  tasks: []\n")
            with self.assertRaises(RuntimeError):
                REPOCTL.precommit()

    def test_valid_staged_terraform_and_ansible_ignore_unstaged_invalid_content(self):
        with self.fixture() as (root, git):
            terraform = root / "main.tf"
            playbook = root / "playbook.yml"
            terraform.write_text('locals {\n  value = "example"\n}\n')
            playbook.write_text("---\n- name: Valid staged playbook\n  hosts: localhost\n  tasks: []\n")
            git("add", "main.tf", "playbook.yml")
            index = git("write-tree")
            terraform.write_text("invalid Terraform\n")
            playbook.write_text("[invalid YAML\n")
            self.assertEqual(0, REPOCTL.precommit())
            self.assertEqual(index, git("write-tree"))
            self.assertEqual("[invalid YAML\n", playbook.read_text())

    def test_staged_go_vet_failure_is_not_hidden_by_valid_worktree(self):
        with self.fixture() as (root, git):
            (root / "go.mod").write_text("module fixture\n\ngo 1.23.0\n")
            source = root / "example.go"
            invalid = 'package fixture\n\nimport "fmt"\n\nfunc message() {\n\tfmt.Printf("%d", "text")\n}\n'
            source.write_text(invalid)
            git("add", "go.mod", "example.go")
            source.write_text(invalid.replace('"%d"', '"%s"'))
            with self.assertRaisesRegex(RuntimeError, "vet"):
                REPOCTL.precommit()

    def test_option_like_and_quoted_paths_are_checked(self):
        for name in ("--stdin-filename=x.py", "line\nbreak.py"):
            with self.subTest(name=name), self.fixture() as (root, git):
                (root / name).write_text("undefined_name()\n")
                git("add", "--", name)
                with self.assertRaises(RuntimeError):
                    REPOCTL.precommit()

    def test_external_symlink_is_rejected_before_any_scanner(self):
        with self.fixture() as (root, git), tempfile.TemporaryDirectory() as external:
            target = Path(external) / "private.py"
            target.write_text("untracked_private_fixture\n")
            (root / "link.py").symlink_to(target)
            git("add", "--", "link.py")
            diagnostics = io.StringIO()
            with mock.patch.object(REPOCTL, "require") as require, contextlib.redirect_stderr(diagnostics):
                self.assertNotEqual(0, REPOCTL.precommit())
            require.assert_not_called()
            self.assertNotIn("untracked_private_fixture", diagnostics.getvalue())
            self.assertNotIn(str(target), diagnostics.getvalue())

    def test_publish_rejects_dirty_symlink_before_commit_even_without_hooks(self):
        with self.fixture() as (root, git), tempfile.TemporaryDirectory() as external:
            git("checkout", "-b", "fixture-publish")
            head = git("rev-parse", "HEAD")
            git("update-ref", "refs/remotes/origin/main", head)
            target = Path(external) / "private.py"
            target.write_text("untracked_private_fixture\n")
            (root / "link.py").symlink_to(target)
            original_run = REPOCTL.run
            commands = []

            def run(command, **kwargs):
                commands.append(command)
                if command[:2] == ["git", "fetch"]:
                    return subprocess.CompletedProcess(command, 0)
                return original_run(command, **kwargs)

            with (
                mock.patch.object(REPOCTL, "run", side_effect=run),
                mock.patch.object(REPOCTL, "_load_promotable_worktree_evidence", return_value=None),
                mock.patch.object(REPOCTL, "verify_change") as verify,
            ):
                self.assertEqual(1, REPOCTL.publish("main", "Must reject symlink"))
            self.assertEqual(head, git("rev-parse", "HEAD"))
            self.assertFalse(any(command[:2] in (["git", "commit"], ["git", "push"]) for command in commands))
            verify.assert_not_called()

    def test_publish_rejects_clean_committed_gitlink_before_verification(self):
        with self.fixture() as (root, git):
            git("checkout", "-b", "fixture-publish")
            head = git("rev-parse", "HEAD")
            git("update-ref", "refs/remotes/origin/main", head)
            git("update-index", "--add", "--cacheinfo", f"160000,{head},external")
            (root / "external").mkdir()
            git("commit", "-m", "Add gitlink fixture")
            original_run = REPOCTL.run
            commands = []

            def run(command, **kwargs):
                commands.append(command)
                if command[:2] == ["git", "fetch"]:
                    return subprocess.CompletedProcess(command, 0)
                return original_run(command, **kwargs)

            with (
                mock.patch.object(REPOCTL, "run", side_effect=run),
                mock.patch.object(REPOCTL, "verify_change") as verify,
            ):
                self.assertEqual(1, REPOCTL.publish("main", "Refuse committed gitlink"))
            verify.assert_not_called()
            self.assertFalse(any(command[:2] == ["git", "push"] for command in commands))

    def test_guard_rejects_unresolved_regular_index_entries(self):
        with mock.patch.object(REPOCTL, "git", return_value=f"100644 {'a' * 40} 2\tconflicted.py\0"):
            self.assertNotEqual(0, REPOCTL._reject_staged_symlinks())

    def test_unstaged_attributes_cannot_convert_indexed_blobs(self):
        for tracked in (False, True):
            with self.subTest(tracked=tracked), self.fixture() as (root, git):
                folder = root / "nested"
                folder.mkdir()
                path = folder / "fixture.go"
                content = b"package fixture\n\nvar value = 1\n"
                path.write_bytes(content)
                attributes = folder / ".gitattributes"
                if tracked:
                    attributes.write_text("*.go text\n")
                    git("add", "--", "nested/.gitattributes")
                git("add", "--", "nested/fixture.go")
                index = git("write-tree")
                attributes.write_text("*.go working-tree-encoding=UTF-16\n")
                with tempfile.TemporaryDirectory() as destination:
                    snapshot = Path(destination)
                    REPOCTL._materialize_staged_tree(snapshot)
                    self.assertEqual(content, (snapshot / "nested/fixture.go").read_bytes())
                self.assertEqual(0, REPOCTL.precommit())
                self.assertEqual(index, git("write-tree"))
                self.assertEqual("*.go working-tree-encoding=UTF-16\n", attributes.read_text())


if __name__ == "__main__":
    unittest.main()
