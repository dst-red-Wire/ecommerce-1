import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/qualification-tools"
SPEC = importlib.util.spec_from_file_location(
    "qualification_tools", ROOT / "scripts/qualification_tools.py"
)
QUALIFICATION = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(QUALIFICATION)


class QualificationToolContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = yaml.safe_load(
            (ROOT / "config/contracts/qualification-tools.yaml").read_text(
                encoding="utf-8"
            )
        )
        cls.toolchain = json.loads(
            (ROOT / "config/contracts/toolchain-lock.json").read_text(encoding="utf-8")
        )

    def test_contract_is_complete_and_centrally_versioned(self):
        self.assertEqual(self.contract, QUALIFICATION.validate_contract())
        expected = {
            "openscap",
            "scap-security-guide",
            "kube-bench",
            "conftest",
            "opa",
            "k6",
            "nuclei",
            "hubble",
            "pint",
        }
        self.assertEqual(expected, set(self.contract["tools"]))
        for declaration in self.contract["tools"].values():
            registry_name = declaration["tool"]["registry_ref"].rsplit(".", 1)[-1]
            registry = self.toolchain["tools"][registry_name]
            self.assertIn(registry["version_ref"], self.toolchain["versions"])

    def test_downloaded_tools_are_pinned_to_official_sources_and_checksums(self):
        downloaded = {"kube-bench", "conftest", "opa", "k6", "nuclei", "hubble", "pint"}
        for name in downloaded:
            tool = self.toolchain["tools"][name]
            self.assertTrue(tool["source"].startswith("https://github.com/"))
            self.assertRegex(
                self.toolchain["versions"][tool["sha256_ref"]], r"^[0-9a-f]{64}$"
            )
            self.assertNotRegex(
                tool["artifact"]["url"].lower(), r"/(latest|main|master|nightly)/"
            )
        nuclei = self.toolchain["tools"]["nuclei"]
        self.assertRegex(
            self.toolchain["versions"][nuclei["templates"]["commit_ref"]],
            r"^[0-9a-f]{40}$",
        )
        self.assertRegex(
            self.toolchain["versions"][nuclei["templates"]["sha256_ref"]],
            r"^[0-9a-f]{64}$",
        )

    def test_installer_is_cached_offline_and_idempotent(self):
        defaults = (
            ROOT / "platform/ansible/roles/developer_toolchain/defaults/main.yml"
        ).read_text(encoding="utf-8")
        tasks = (
            ROOT / "platform/ansible/roles/developer_toolchain/tasks/main.yml"
        ).read_text(encoding="utf-8")
        self.assertEqual(
            "ECOMMERCE_TOOL_HOME",
            self.toolchain["capability_policy"]["managed_install_root"]["environment"],
        )
        self.assertIn("managed_install_root.environment", defaults)
        self.assertIn("toolchain_offline", defaults)
        self.assertIn("Validate cached registry-managed archive tools", tasks)
        self.assertIn("Validate the cached Nuclei template snapshot", tasks)
        self.assertIn("creates:", tasks)
        for tag in ("conftest", "opa", "k6", "nuclei", "hubble", "pint"):
            self.assertIn(tag, tasks)

    def test_runtime_compatibility_never_fakes_pass(self):
        kube = self.contract["tools"]["kube-bench"]["policy"]
        self.assertEqual("unsupported", kube["compatibility"])
        self.assertEqual("BLOCK", kube["unsupported_behavior"])
        hubble = self.contract["tools"]["hubble"]["policy"]
        self.assertEqual("unverified", hubble["compatibility"])
        self.assertEqual("BLOCK", hubble["unsupported_behavior"])
        self.assertTrue(
            self.contract["principles"]["static_result_must_not_claim_runtime_proof"]
        )

    def test_k6_smoke_is_bounded_by_the_central_contract(self):
        policy = self.contract["tools"]["k6"]["policy"]["smoke"]
        script = (FIXTURES / "k6/smoke.js").read_text(encoding="utf-8")
        self.assertIn(f"vus: {policy['virtual_users']}", script)
        self.assertIn(f"iterations: {policy['iterations']}", script)
        self.assertIn(f'maxDuration: "{policy["duration_limit_seconds"]}s"', script)

    def test_missing_required_scanner_fails_closed(self):
        with mock.patch.object(QUALIFICATION.shutil, "which", return_value=None):
            with self.assertRaisesRegex(
                QUALIFICATION.QualificationError, "required scanner is absent"
            ):
                QUALIFICATION._require_version("opa", ["opa", "version"], "1.21.0")


class QualificationEvidenceParserTests(unittest.TestCase):
    def test_openscap_pass_fail_notchecked_and_invalid(self):
        self.assertEqual(
            "PASS",
            QUALIFICATION.parse_openscap(FIXTURES / "openscap/pass.xml")[
                "final_result"
            ],
        )
        self.assertEqual(
            "FAIL",
            QUALIFICATION.parse_openscap(FIXTURES / "openscap/fail.xml")[
                "final_result"
            ],
        )
        self.assertEqual(
            "BLOCK",
            QUALIFICATION.parse_openscap(FIXTURES / "openscap/notchecked.xml")[
                "final_result"
            ],
        )
        with tempfile.TemporaryDirectory() as directory:
            invalid = Path(directory) / "invalid.xml"
            invalid.write_text("<not-closed>", encoding="utf-8")
            with self.assertRaises(QUALIFICATION.QualificationError):
                QUALIFICATION.parse_openscap(invalid)

    def test_kube_bench_pass_finding_unsupported_and_invalid(self):
        passing = FIXTURES / "kube-bench/pass.json"
        self.assertEqual(
            "PASS", QUALIFICATION.parse_kube_bench(passing)["final_result"]
        )
        self.assertEqual(
            "FAIL",
            QUALIFICATION.parse_kube_bench(FIXTURES / "kube-bench/fail.json")[
                "final_result"
            ],
        )
        self.assertEqual(
            "BLOCK",
            QUALIFICATION.parse_kube_bench(passing, compatible=False)["final_result"],
        )
        with tempfile.TemporaryDirectory() as directory:
            invalid = Path(directory) / "invalid.json"
            invalid.write_text("{}", encoding="utf-8")
            with self.assertRaises(QUALIFICATION.QualificationError):
                QUALIFICATION.parse_kube_bench(invalid)

    def test_k6_thresholds_are_fail_closed(self):
        self.assertEqual(
            "PASS",
            QUALIFICATION.parse_k6(FIXTURES / "k6/pass-summary.json")["final_result"],
        )
        self.assertEqual(
            "FAIL",
            QUALIFICATION.parse_k6(FIXTURES / "k6/fail-summary.json")["final_result"],
        )

    def test_nuclei_findings_and_invalid_output_fail_closed(self):
        smoke = QUALIFICATION.parse_nuclei(
            FIXTURES / "nuclei/smoke.jsonl",
            scanner_exit_code=0,
            allowed_template_ids={"ecommerce-local-health-smoke"},
        )
        self.assertEqual("PASS", smoke["final_result"])
        self.assertEqual(
            "FAIL",
            QUALIFICATION.parse_nuclei(
                FIXTURES / "nuclei/finding.jsonl", scanner_exit_code=0
            )["final_result"],
        )
        with tempfile.TemporaryDirectory() as directory:
            empty = Path(directory) / "empty.jsonl"
            empty.write_text("", encoding="utf-8")
            no_findings = QUALIFICATION.parse_nuclei(empty, scanner_exit_code=0)
            self.assertEqual(
                {"findings": 0, "blocking_templates": [], "final_result": "PASS"},
                no_findings,
            )
            invalid = Path(directory) / "invalid.jsonl"
            invalid.write_text("not-json\n", encoding="utf-8")
            with self.assertRaises(QUALIFICATION.QualificationError):
                QUALIFICATION.parse_nuclei(invalid, scanner_exit_code=0)
            with self.assertRaises(QUALIFICATION.QualificationError):
                QUALIFICATION.parse_nuclei(empty, scanner_exit_code=1)

    def test_hubble_requires_explicit_satisfied_assertions_and_compatibility(self):
        assertions = {
            "expected-allow",
            "expected-drop",
            "expected-dns",
            "policy-enforcement",
        }
        passing = QUALIFICATION.parse_hubble(
            FIXTURES / "hubble/pass.jsonl", assertions=assertions
        )
        self.assertEqual("PASS", passing["final_result"])
        failing = QUALIFICATION.parse_hubble(
            FIXTURES / "hubble/fail.jsonl", assertions=assertions
        )
        self.assertEqual("FAIL", failing["final_result"])
        blocked = QUALIFICATION.parse_hubble(
            FIXTURES / "hubble/pass.jsonl", assertions=assertions, compatible=False
        )
        self.assertEqual("BLOCK", blocked["final_result"])
        with self.assertRaises(QUALIFICATION.QualificationError):
            QUALIFICATION.parse_hubble(FIXTURES / "hubble/pass.jsonl", assertions=set())

    def test_pint_exit_status_is_not_reinterpreted_as_pass(self):
        self.assertEqual("PASS", QUALIFICATION.normalize_pint(0, "")["final_result"])
        self.assertEqual(
            "FAIL", QUALIFICATION.normalize_pint(1, "invalid rule")["final_result"]
        )


if __name__ == "__main__":
    unittest.main()
