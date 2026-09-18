from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "qualification_cache",
    ROOT / "scripts" / "qualification_cache.py",
)
qualification_cache = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(qualification_cache)


class QualificationCacheTest(unittest.TestCase):
    def isolated_tool_home(self):
        directory = tempfile.TemporaryDirectory(prefix="qualification-cache-test-")
        previous = os.environ.get("ECOMMERCE_TOOL_HOME")
        os.environ["ECOMMERCE_TOOL_HOME"] = directory.name

        def cleanup():
            qualification_cache.clear_memory_cache()
            if previous is None:
                os.environ.pop("ECOMMERCE_TOOL_HOME", None)
            else:
                os.environ["ECOMMERCE_TOOL_HOME"] = previous
            directory.cleanup()

        self.addCleanup(cleanup)
        qualification_cache.clear_memory_cache()
        return Path(directory.name)

    def test_contract_is_central_and_dynamic_state_is_not_cacheable(self):
        contract = qualification_cache.contract()
        self.assertEqual("architecture.lock.yaml", contract["architecture_authority"])
        self.assertEqual("sha256", contract["identity"]["algorithm"])
        self.assertEqual(
            "forbidden",
            contract["consumers"]["security_scan"]["persistence"],
        )
        self.assertIn("owner-authorization", contract["scope"]["forbidden"])
        self.assertIn("remote-ci-state", contract["scope"]["forbidden"])
        self.assertIn("kubernetes-runtime-state", contract["scope"]["forbidden"])

    def test_key_changes_for_every_required_identity_dimension(self):
        base = dict(
            namespace="gate",
            input_content_digest="input-a",
            validator_content_digest="validator-a",
            tool_identity={"ruby": "tool-a"},
            options={"mode": "one"},
        )
        key = qualification_cache.build_key(**base)
        for field, value in (
            ("input_content_digest", "input-b"),
            ("validator_content_digest", "validator-b"),
            ("tool_identity", {"ruby": "tool-b"}),
            ("options", {"mode": "two"}),
        ):
            changed = dict(base)
            changed[field] = value
            self.assertNotEqual(key, qualification_cache.build_key(**changed), field)

    def test_l2_cache_is_persistent_and_caller_mutation_safe(self):
        tool_home = self.isolated_tool_home()
        key = qualification_cache.build_key(
            "unit",
            input_content_digest="input",
            validator_content_digest="validator",
            tool_identity={"python": sys.version},
            options={},
        )
        qualification_cache.store_success("unit", key, {"nested": {"value": "one"}})

        first = qualification_cache.load_success("unit", key)
        first["nested"]["value"] = "caller-mutated"

        qualification_cache.clear_memory_cache("unit")
        second = qualification_cache.load_success("unit", key)
        self.assertEqual("one", second["nested"]["value"])

        entry = tool_home / "qualification-cache" / "v1" / "unit" / f"{key}.json"
        self.assertTrue(entry.is_file())

    def test_corrupt_disk_entry_is_a_cache_miss(self):
        tool_home = self.isolated_tool_home()
        key = qualification_cache.build_key(
            "unit-corrupt",
            input_content_digest="input",
            validator_content_digest="validator",
            tool_identity={},
            options={},
        )
        qualification_cache.store_success("unit-corrupt", key, {"ok": True})
        qualification_cache.clear_memory_cache("unit-corrupt")
        entry = tool_home / "qualification-cache" / "v1" / "unit-corrupt" / f"{key}.json"
        entry.write_text("{not-json", encoding="utf-8")
        self.assertIsNone(qualification_cache.load_success("unit-corrupt", key))

    def test_psych_cache_reuses_equal_content_and_invalidates_changes(self):
        self.isolated_tool_home()
        with tempfile.TemporaryDirectory(prefix="psych-cache-") as directory:
            root = Path(directory)
            first = root / "first.yaml"
            second = root / "second.yaml"
            first.write_text("root:\n  value: one\n", encoding="utf-8")
            second.write_text("root:\n  value: one\n", encoding="utf-8")

            qualification_cache.psych_load(first)
            self.assertEqual(1, qualification_cache.memory_entry_count("psych-yaml"))
            qualification_cache.psych_load(second)
            self.assertEqual(1, qualification_cache.memory_entry_count("psych-yaml"))

            second.write_text("root:\n  value: two\n", encoding="utf-8")
            parsed = qualification_cache.psych_load(second)
            self.assertEqual("two", parsed["root"]["value"])
            self.assertEqual(2, qualification_cache.memory_entry_count("psych-yaml"))


if __name__ == "__main__":
    unittest.main()
