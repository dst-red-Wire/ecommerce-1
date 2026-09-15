from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class QualificationReuseContractTests(unittest.TestCase):
    def test_canonical_entrypoint_prepares_before_qualification(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertNotIn("env-check: bootstrap", makefile)
        self.assertIn("qualify: bootstrap", makefile)
        self.assertIn("@$(MAKE) env-check", makefile)
        self.assertIn("ECOMMERCE_TOOL_HOME ?=", makefile)
        self.assertIn("TF_PLUGIN_CACHE_DIR ?=", makefile)

    def test_seed_identity_is_external_versioned_and_locked(self):
        source = (ROOT / "scripts/capability_bootstrap.py").read_text(encoding="utf-8")
        self.assertIn('os.environ.get("ECOMMERCE_TOOL_HOME"', source)
        self.assertIn('"lock_sha256"', source)
        self.assertIn("identity_lock(lock_path)", source)
        self.assertIn("publish_checkout_reference(seed_root)", source)
        self.assertLess(source.index("with identity_lock(lock_path)"), source.index("if valid():"))

    def test_frontend_qualification_cannot_compile_templ_implicitly(self):
        source = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        frontend = source[source.index("def frontend(") : source.index("def site(")]
        self.assertNotIn("go run", frontend)
        self.assertIn('tools/templ" / templ_version / "linux-amd64/templ"', frontend)
        contract = (ROOT / "config/toolchain/capabilities.json").read_text(encoding="utf-8")
        self.assertIn('"identity_path": ".local/share/ecommerce-1/tools/templ/{version}/linux-amd64/templ"', contract)

    def test_documentation_distinguishes_cold_and_warm_operation(self):
        documentation = (ROOT / "docs/engineering/QUALIFICATION_TOOL_REUSE.md").read_text(encoding="utf-8")
        for phrase in ("cold machine", "warm caches", "pin change", "without network access"):
            self.assertIn(phrase, documentation)


if __name__ == "__main__":
    unittest.main()
