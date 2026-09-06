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
        self.assertIn("verify_change(base_ref, head)", controller)
        self.assertIn('run(["git","push","-u","origin","HEAD"])', controller)


if __name__ == "__main__":
    unittest.main()
