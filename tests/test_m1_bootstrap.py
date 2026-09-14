import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("servicegen", ROOT / "scripts/servicegen.py")
SERVICEGEN = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(SERVICEGEN)


class M1BootstrapTest(unittest.TestCase):
    def test_every_canonical_service_has_an_autonomous_go_module(self):
        services = SERVICEGEN.canonical_services(ROOT)
        self.assertEqual(19, len(services))
        self.assertEqual(set(services), {path.name for path in (ROOT / "services").iterdir() if path.is_dir()})
        workspace = (ROOT / "go.work").read_text(encoding="utf-8")
        for service in services:
            module = ROOT / "services" / service / "go.mod"
            self.assertTrue(module.is_file(), module)
            self.assertIn(f"./services/{service}", workspace)

    def test_canonical_frontends_are_independent_go_entrypoints(self):
        workspace = (ROOT / "go.work").read_text(encoding="utf-8")
        self.assertIn("./frontend", workspace)
        for frontend in ("storefront", "admin"):
            self.assertTrue((ROOT / "frontend" / "apps" / frontend / "main.go").is_file())
        self.assertTrue((ROOT / "frontend" / "internal" / "web" / "layout.templ").is_file())
