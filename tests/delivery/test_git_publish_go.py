import ast
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class GoToolchainDeliveryTests(unittest.TestCase):
    def test_go_toolchain_is_pinned(self):
        versions = (ROOT / "config/toolchain/versions.env").read_text(encoding="utf-8")
        self.assertIn("GO_VERSION=1.26.6", versions)
        self.assertIn("GO_SHA256_LINUX_AMD64=708effb774be8237570d0add163225abbdfaf4fca28b2611df167beba4feef89", versions)

    def test_go_toolchain_is_reconciled_by_ansible(self):
        tasks = (ROOT / "platform/ansible/roles/developer_toolchain/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("Download pinned Go archive", tasks)
        self.assertIn("checksum: \"sha256:{{ go_sha256 }}\"", tasks)
        self.assertIn("Link Go commands", tasks)

    def test_publish_uses_affected_exact_sha_controller(self):
        controller = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        module = ast.parse(controller)
        publish = next(
            node for node in module.body
            if isinstance(node, ast.FunctionDef) and node.name == "publish"
        )
        calls = [node for node in ast.walk(publish) if isinstance(node, ast.Call)]

        verify_calls = [
            call for call in calls
            if isinstance(call.func, ast.Name) and call.func.id == "verify_change"
        ]
        self.assertTrue(any(
            len(call.args) >= 2
            and isinstance(call.args[0], ast.Name) and call.args[0].id == "base_ref"
            and isinstance(call.args[1], ast.Name) and call.args[1].id == "head"
            for call in verify_calls
        ))

        push_calls = [
            call for call in calls
            if isinstance(call.func, ast.Name) and call.func.id == "run"
            and call.args and isinstance(call.args[0], ast.List)
        ]
        self.assertTrue(any(
            all(isinstance(item, ast.Constant) and isinstance(item.value, str) for item in call.args[0].elts)
            and [item.value for item in call.args[0].elts] == ["git", "push", "-u", "origin", "HEAD"]
            for call in push_calls
        ))


if __name__ == "__main__":
    unittest.main()
