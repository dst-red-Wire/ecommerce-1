from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("repoctl_protobuf_compat_test", ROOT / "scripts/repoctl.py")
assert SPEC and SPEC.loader
REPOCTL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPOCTL)


class ProtobufCompatibilityTests(unittest.TestCase):
    def test_changed_existing_module_runs_buf_breaking_against_base(self) -> None:
        commands: list[list[str]] = []

        def materialize(_ref: str, destination: Path) -> None:
            proto = destination / "contracts" / "proto"
            proto.mkdir(parents=True)
            (proto / "buf.yaml").write_text("version: v2\n", encoding="utf-8")

        def run(command, **_kwargs):
            commands.append(command)
            return mock.Mock(returncode=0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as managed:
            managed_go = Path(managed) / "go"
            managed_go.touch()
            with (
                mock.patch.object(REPOCTL, "git", return_value="contracts/proto/service.proto\n"),
                mock.patch.object(REPOCTL, "_git_tree_has_path", return_value=True),
                mock.patch.object(REPOCTL, "_materialize_proto_tree", side_effect=materialize),
                mock.patch.object(REPOCTL, "managed_bin_dirs", return_value=(Path(managed),)),
                mock.patch.object(REPOCTL, "run", side_effect=run),
            ):
                self.assertEqual(0, REPOCTL.protobuf_compat("base-sha", "WORKTREE"))

        breaking = next(command for command in commands if "breaking" in command)
        self.assertEqual(str(managed_go), breaking[0])
        self.assertIn("--against", breaking)

    def test_new_module_has_no_false_breaking_failure(self) -> None:
        with (
            mock.patch.object(REPOCTL, "git", return_value="contracts/proto/service.proto\n"),
            mock.patch.object(REPOCTL, "_git_tree_has_path", return_value=False),
            mock.patch.object(REPOCTL, "run") as run,
        ):
            self.assertEqual(0, REPOCTL.protobuf_compat("base-sha", "WORKTREE"))
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
