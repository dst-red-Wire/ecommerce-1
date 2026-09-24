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
            with (
                mock.patch.object(pathlib.Path, "home", return_value=home),
                mock.patch.dict(os.environ, {"PATH": "/usr/bin"}),
            ):
                result = MOD.yq_json(".", ROOT / "config/context/router.yaml")
            self.assertEqual({"levels": {}}, result)
            self.assertEqual(str(binary), log.read_text(encoding="utf-8"))

    def test_missing_managed_yq_is_reported_before_subprocess(self):
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.object(pathlib.Path, "home", return_value=pathlib.Path(tmp)),
            mock.patch.object(subprocess, "run") as run,
        ):
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
            with (
                mock.patch.object(pathlib.Path, "home", return_value=root / "home"),
                mock.patch.dict(os.environ, {"PATH": str(system)}),
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

    def test_governed_mlops_and_aiops_tasks_route_l2_without_overrouting(self):
        cfg = {
            "levels": {
                "L2": {"task_keywords": ["mlops", "aiops", "architecture"]},
                "L1": {"task_keywords": ["service"]},
            }
        }
        with mock.patch.object(MOD, "yq_json", return_value=cfg):
            self.assertEqual("L2", MOD.route("Implement the locked MLOps platform", []))
            self.assertEqual("L2", MOD.route("Implement the governed AIOps topology", []))
            self.assertEqual("L0", MOD.route("fix lightweight local helper", []))

    def test_router_declares_mlops_aiops_and_their_l2_contracts(self):
        text = (ROOT / "config/context/router.yaml").read_text(encoding="utf-8")
        for required in (
            "      - mlops",
            "      - aiops",
            "    - architecture.lock.yaml",
            "    - docs/architecture/EXACT_TOPOLOGY_V5.md",
            "    - config/infrastructure/deployment-waves.yaml",
            "    - docs/architecture/MLOPS_TOPOLOGY_V1.md",
        ):
            self.assertIn(required, text)

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

    def test_agent_context_is_read_only_bounded_and_secret_free(self):
        cfg = {
            "levels": {"L0": {"max_bytes": 100}},
            "agent_data_access": {
                "authority": "architecture.lock.yaml#machine_contracts.context_router",
                "default_mode": "read-only",
                "least_privilege": "required",
                "secret_values": "forbidden",
                "production_credentials": "forbidden",
                "private_keys": "forbidden",
                "unbounded_environment_dump": "forbidden",
                "output_root": ".context",
                "maximum_override_policy": "may-reduce-never-increase-level-budget",
                "contract_references": ["architecture.lock.yaml#machine_contracts.context_router"],
                "forbidden_path_patterns": [r"(^|/)\.env($|\.)", r"(^|/).*\.key$"],
                "redaction_patterns": [r"(?i)token\s*[:=]\s*[^\s]+"],
            },
        }
        lock = {"machine_contracts": {"context_router": "config/context/router.yaml"}}
        MOD.validate_router_contract(cfg, lock)
        with self.assertRaisesRegex(RuntimeError, "forbidden"):
            MOD.guard_context_paths(["secrets/prod.key"], cfg)
        self.assertNotIn("super-secret", MOD.redact_sensitive("token=super-secret", cfg))

    def test_context_inputs_cannot_escape_repository(self):
        cfg = {"agent_data_access": {"forbidden_path_patterns": []}}
        for unsafe in ("/etc/passwd", "../../secret"):
            with self.subTest(path=unsafe), self.assertRaisesRegex(
                RuntimeError, "repository-relative|escapes repository"
            ):
                MOD.guard_context_paths([unsafe], cfg)

        with tempfile.TemporaryDirectory() as directory:
            outside = pathlib.Path(directory) / "outside.yaml"
            outside.write_text("secret: outside\n", encoding="utf-8")
            link = ROOT / ".context" / "outside-link.yaml"
            link.parent.mkdir(parents=True, exist_ok=True)
            try:
                link.symlink_to(outside)
                with self.assertRaisesRegex(RuntimeError, "escapes repository"):
                    MOD.guard_context_paths([str(link.relative_to(ROOT))], cfg)
            finally:
                link.unlink(missing_ok=True)

    def test_complete_private_key_blocks_are_redacted(self):
        cfg = {"agent_data_access": {"redaction_patterns": []}}
        for key_type in ("RSA ", "EC ", "OPENSSH ", "", "ENCRYPTED "):
            body = f"-----BEGIN {key_type}PRIVATE KEY-----\nSENSITIVEBASE64BODY\n-----END {key_type}PRIVATE KEY-----"
            with self.subTest(key_type=key_type or "PKCS8"):
                redacted = MOD.redact_sensitive(f"before\n{body}\nafter", cfg)
                self.assertNotIn("SENSITIVEBASE64BODY", redacted)
                self.assertNotIn("BEGIN", redacted)
                self.assertIn("before", redacted)
                self.assertIn("after", redacted)

    def test_incomplete_private_key_fails_closed(self):
        cfg = {"agent_data_access": {"redaction_patterns": []}}
        redacted = MOD.redact_sensitive(
            "safe\n-----BEGIN PRIVATE KEY-----\nSENSITIVEBASE64BODY\nmore content",
            cfg,
        )
        self.assertEqual(
            "safe\n[REDACTED INCOMPLETE PRIVATE KEY BY CONTEXT POLICY]", redacted
        )

    def test_unknown_context_authority_reference_is_rejected(self):
        cfg = {
            "levels": {"L0": {"max_bytes": 100}},
            "agent_data_access": {
                "authority": "architecture.lock.yaml#machine_contracts.context_router",
                "default_mode": "read-only",
                "least_privilege": "required",
                "secret_values": "forbidden",
                "production_credentials": "forbidden",
                "private_keys": "forbidden",
                "unbounded_environment_dump": "forbidden",
                "output_root": ".context",
                "maximum_override_policy": "may-reduce-never-increase-level-budget",
                "contract_references": ["architecture.lock.yaml#machine_contracts.unknown"],
            },
        }
        with self.assertRaisesRegex(RuntimeError, "unknown context contract"):
            MOD.validate_router_contract(cfg, {"machine_contracts": {"context_router": "x"}})

    def test_context_output_cannot_escape_governed_root(self):
        cfg = {"agent_data_access": {"output_root": ".context"}}
        with self.assertRaisesRegex(RuntimeError, "remain under"):
            MOD.output_path("report.md", cfg)
        self.assertEqual((ROOT / ".context/test.md").resolve(), MOD.output_path(".context/test.md", cfg))

    def test_oversized_or_unbounded_context_override_is_rejected(self):
        self.assertEqual(512, MOD.resolve_byte_budget(1024, "512"))
        for override in ("0", "1025", "unbounded"):
            with self.subTest(override=override), self.assertRaisesRegex(RuntimeError, "byte budget override"):
                MOD.resolve_byte_budget(1024, override)


if __name__ == "__main__":
    unittest.main()
