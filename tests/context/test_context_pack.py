import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("context_pack", ROOT / "scripts/context-pack.py")
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class RoutingTests(unittest.TestCase):
    def _managed_yq(self, home: pathlib.Path, log: pathlib.Path) -> pathlib.Path:
        binary = home / ".local" / "bin" / "yq"
        binary.parent.mkdir(parents=True)
        binary.write_text(
            f"#!{sys.executable}\n"
            "import json, pathlib, sys\n"
            f"pathlib.Path({str(log)!r}).write_text(sys.argv[0], encoding='utf-8')\n"
            "print(json.dumps({'levels': {}}))\n",
            encoding="utf-8",
        )
        binary.chmod(0o755)
        return binary

    def test_context_yaml_uses_managed_yq_even_when_path_omits_local_bin(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = pathlib.Path(tmp) / "home"
            log = pathlib.Path(tmp) / "called"
            binary = self._managed_yq(home, log)
            with mock.patch.object(pathlib.Path, "home", return_value=home), mock.patch.dict(
                os.environ, {"PATH": "/usr/bin"}
            ):
                result = MOD.yq_json(".", ROOT / "config/context/router.yaml")
            self.assertEqual({"levels": {}}, result)
            self.assertEqual(str(binary), log.read_text(encoding="utf-8"))

    def test_missing_managed_yq_is_reported_before_subprocess(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            pathlib.Path, "home", return_value=pathlib.Path(tmp)
        ), mock.patch.object(subprocess, "run") as run:
            with self.assertRaisesRegex(RuntimeError, "managed yq missing: run `make context-tools`"):
                MOD.yq_json(".", ROOT / "config/context/router.yaml")
            run.assert_not_called()

    def test_path_only_system_yq_cannot_bypass_managed_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            system = root / "system"
            system.mkdir()
            (system / "yq").write_text("#!/bin/true\n", encoding="utf-8")
            (system / "yq").chmod(0o755)
            with mock.patch.object(pathlib.Path, "home", return_value=root / "home"), mock.patch.dict(
                os.environ, {"PATH": str(system)}
            ):
                with self.assertRaisesRegex(RuntimeError, "managed yq missing"):
                    MOD.yq_json(".", ROOT / "config/context/router.yaml")

    def test_architecture_task_routes_l2_even_without_diff(self):
        cfg = {"levels": {"L2": {"task_keywords": ["Tekton"]}, "L1": {"task_keywords": ["OpenAPI"]}}}
        with mock.patch.object(MOD, "yq_json", return_value=cfg):
            self.assertEqual(MOD.route("change Tekton control-plane", []), "L2")

    def test_domain_task_routes_l1_even_without_diff(self):
        cfg = {"levels": {"L2": {"task_keywords": ["Tekton"]}, "L1": {"task_keywords": ["OpenAPI"]}}}
        with mock.patch.object(MOD, "yq_json", return_value=cfg):
            self.assertEqual(MOD.route("add product OpenAPI operation", []), "L1")

    def test_local_helper_routes_l0(self):
        cfg = {"levels": {"L2": {}, "L1": {}}}
        with mock.patch.object(MOD, "yq_json", return_value=cfg):
            self.assertEqual(MOD.route("fix local helper", ["scripts/harmless-local-helper.py"]), "L0")

    def test_detects_service_from_task(self):
        with mock.patch.object(MOD, "yq_json", return_value=["inventory", "product"]):
            self.assertIn("inventory", MOD.detect_services("fix inventory reservation", []))

    def test_service_contract_contains_reverse_consumers_and_public_api(self):
        values = iter([{"owner": "catalog"}, {"sync": []}, {}, {"path": "product.yaml"}])
        with mock.patch.object(MOD, "yq_json", side_effect=lambda *_args: next(values)):
            contract = json.loads(MOD.service_contract("product"))
        self.assertIn("direct_sync_consumers", contract)
        self.assertIn("public_api", contract)

    def test_byte_budget(self):
        out = MOD.bounded("x" * 1000, 200)
        self.assertLessEqual(len(out.encode()), 200)
        self.assertIn("TRUNCATED", out)


if __name__ == "__main__":
    unittest.main()
