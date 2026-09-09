import importlib.util
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("repoctl_api_codegen", ROOT / "scripts/repoctl.py")
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


COMMON = """\
openapi: 3.1.0
info: {title: Common, version: 1.0.0}
paths: {}
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
  parameters:
    Limit:
      name: limit
      in: query
      schema: {type: integer}
  headers:
    RequestId:
      description: request id
      schema: {type: string}
  schemas:
    Problem:
      type: object
      properties:
        requestId: {type: string}
  responses:
    BadRequest:
      description: bad request
      headers:
        X-Request-ID:
          $ref: '#/components/headers/RequestId'
      content:
        application/problem+json:
          schema:
            $ref: '#/components/schemas/Problem'
"""

PRODUCT = """\
openapi: 3.1.0
info: {title: Product, version: 1.0.0}
paths:
  /v1/products:
    get:
      parameters:
        - $ref: './common.v1.yaml#/components/parameters/Limit'
      responses:
        '400':
          $ref: './common.v1.yaml#/components/responses/BadRequest'
components:
  securitySchemes:
    bearerAuth:
      $ref: './common.v1.yaml#/components/securitySchemes/bearerAuth'
  schemas:
    Product:
      type: object
      properties:
        name: {type: string}
    ProductEnvelope:
      type: object
      properties:
        product:
          $ref: '#/components/schemas/Product'
"""


class ApiCodegenBundleTest(unittest.TestCase):
    def write_specs(self, product=PRODUCT):
        temp = tempfile.TemporaryDirectory()
        root = pathlib.Path(temp.name)
        common = root / "common.v1.yaml"
        service = root / "product.v1.yaml"
        common.write_text(COMMON, encoding="utf-8")
        service.write_text(product, encoding="utf-8")
        return temp, service, common

    def write_public_api_lock(self, root):
        (root / "architecture.lock.yaml").write_text(
            "machine_contracts:\n"
            "  public_api_contracts: config/contracts/public-api-contracts.yaml\n",
            encoding="utf-8",
        )

    def test_canonical_common_refs_become_internal_without_losing_named_service_refs(self):
        temp, service, common = self.write_specs()
        self.addCleanup(temp.cleanup)
        bundled = MOD.bundle_openapi_with_common(service, common)

        get = bundled["paths"]["/v1/products"]["get"]
        self.assertEqual("#/components/parameters/Limit", get["parameters"][0]["$ref"])
        self.assertEqual("#/components/responses/BadRequest", get["responses"]["400"]["$ref"])
        self.assertEqual("http", bundled["components"]["securitySchemes"]["bearerAuth"]["type"])
        self.assertEqual(
            "#/components/headers/RequestId",
            bundled["components"]["responses"]["BadRequest"]["headers"]["X-Request-ID"]["$ref"],
        )
        self.assertEqual(
            "#/components/schemas/Product",
            bundled["components"]["schemas"]["ProductEnvelope"]["properties"]["product"]["$ref"],
        )

        refs = []

        def collect(node):
            if isinstance(node, dict):
                if isinstance(node.get("$ref"), str):
                    refs.append(node["$ref"])
                for value in node.values():
                    collect(value)
            elif isinstance(node, list):
                for value in node:
                    collect(value)

        collect(bundled)
        self.assertTrue(refs)
        self.assertTrue(all(ref.startswith("#") for ref in refs), refs)

    def test_noncanonical_external_ref_fails_closed(self):
        product = PRODUCT.replace(
            "./common.v1.yaml#/components/parameters/Limit",
            "./other.yaml#/components/parameters/Limit",
        )
        temp, service, common = self.write_specs(product)
        self.addCleanup(temp.cleanup)
        with self.assertRaisesRegex(RuntimeError, "does not target canonical common components"):
            MOD.bundle_openapi_with_common(service, common)

    def test_remote_ref_fails_closed(self):
        product = PRODUCT.replace(
            "./common.v1.yaml#/components/parameters/Limit",
            "https://example.invalid/common.yaml#/components/parameters/Limit",
        )
        temp, service, common = self.write_specs(product)
        self.addCleanup(temp.cleanup)
        with self.assertRaisesRegex(RuntimeError, "remote OpenAPI reference forbidden"):
            MOD.bundle_openapi_with_common(service, common)

    def test_real_component_collision_fails_closed(self):
        product = PRODUCT.replace(
            "securitySchemes:\n    bearerAuth:\n      $ref: './common.v1.yaml#/components/securitySchemes/bearerAuth'",
            "securitySchemes:\n    bearerAuth:\n      type: apiKey\n      in: header\n      name: X-Test",
        )
        temp, service, common = self.write_specs(product)
        self.addCleanup(temp.cleanup)
        with self.assertRaisesRegex(RuntimeError, "component collision"):
            MOD.bundle_openapi_with_common(service, common)

    def test_codegen_runs_from_service_module_against_bundled_document(self):
        source = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        self.assertIn("bundled_doc = bundle_openapi_with_common(spec, common_spec)", source)
        self.assertIn('run(["oapi-codegen", "--config", str(config_path), str(bundled_spec)], cwd=module)', source)
        self.assertNotIn("import-mapping:", source[source.index("def api_generate") : source.index("def api_compat")])

    def test_api_generate_go_integration_uses_self_contained_bundle_and_service_cwd(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            (root / "scripts").mkdir(parents=True)
            shutil.copy2(ROOT / "scripts/repoctl.py", root / "scripts/repoctl.py")
            shutil.copy2(ROOT / "scripts/contract_paths.py", root / "scripts/contract_paths.py")
            self.write_public_api_lock(root)
            (root / "config/contracts").mkdir(parents=True)
            (root / "contracts/openapi").mkdir(parents=True)
            (root / "services/product").mkdir(parents=True)
            (root / "config/contracts/public-api-contracts.yaml").write_text(
                "common_components: contracts/openapi/common.v1.yaml\n"
                "contracts:\n"
                "  product:\n"
                "    path: contracts/openapi/product.v1.yaml\n",
                encoding="utf-8",
            )
            (root / "contracts/openapi/common.v1.yaml").write_text(COMMON, encoding="utf-8")
            (root / "contracts/openapi/product.v1.yaml").write_text(PRODUCT, encoding="utf-8")
            (root / "services/product/go.mod").write_text(
                "module example.invalid/ecommerce/product\n\ngo 1.25.0\n", encoding="utf-8"
            )

            bindir = root / "test-bin"
            bindir.mkdir()
            fake_oapi = bindir / "oapi-codegen"
            fake_oapi.write_text(
                "#!/usr/bin/env python3\n"
                "import json, pathlib, sys\n"
                "assert pathlib.Path.cwd().parts[-2:] == ('services', 'product'), pathlib.Path.cwd()\n"
                "cfg = pathlib.Path(sys.argv[sys.argv.index('--config') + 1]).read_text()\n"
                "spec = json.loads(pathlib.Path(sys.argv[-1]).read_text())\n"
                "refs=[]\n"
                "def walk(n):\n"
                "    if isinstance(n, dict):\n"
                "        r=n.get('$ref')\n"
                "        if isinstance(r,str): refs.append(r)\n"
                "        [walk(v) for v in n.values()]\n"
                "    elif isinstance(n,list): [walk(v) for v in n]\n"
                "walk(spec)\n"
                "assert refs and all(r.startswith('#') for r in refs), refs\n"
                "assert 'common.v1.yaml' not in json.dumps(spec)\n"
                "out = next(line.split(':',1)[1].strip() for line in cfg.splitlines() if line.startswith('output:'))\n"
                "pathlib.Path(out).parent.mkdir(parents=True, exist_ok=True)\n"
                "pathlib.Path(out).write_text('package generated\\n')\n",
                encoding="utf-8",
            )
            fake_gofmt = bindir / "gofmt"
            fake_gofmt.write_text(
                "#!/usr/bin/env python3\nimport pathlib, sys\nassert pathlib.Path(sys.argv[-1]).is_file()\n",
                encoding="utf-8",
            )
            fake_oapi.chmod(0o755)
            fake_gofmt.chmod(0o755)

            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            env = os.environ.copy()
            env["PATH"] = f"{bindir}:{env['PATH']}"
            result = subprocess.run(
                ["python3", "scripts/repoctl.py", "api-generate", "--target", "go"],
                cwd=root,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("PASS generated API bindings target=go", result.stdout)
            self.assertTrue((root / "services/product/api/generated/openapi.gen.go").is_file())

    def test_typescript_codegen_check_is_read_only_and_fails_on_drift(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            self.write_public_api_lock(root)
            (root / "config/contracts").mkdir(parents=True)
            (root / "contracts/openapi").mkdir(parents=True)
            (root / "frontend/packages/api-client/src/generated").mkdir(parents=True)
            common = root / "contracts/openapi/common.v1.yaml"
            product = root / "contracts/openapi/product.v1.yaml"
            common.write_text("openapi: 3.1.0\n", encoding="utf-8")
            product.write_text("openapi: 3.1.0\n", encoding="utf-8")
            generated = root / "frontend/packages/api-client/src/generated/product.ts"
            raw = "export   type Product=string;\n"
            canonical = "export type Product = string;\n"
            generated.write_text(canonical, encoding="utf-8")
            registry = {
                "common_components": "contracts/openapi/common.v1.yaml",
                "contracts": {"product": {"path": "contracts/openapi/product.v1.yaml"}},
            }
            (root / "config/contracts/public-api-contracts.yaml").write_text(
                "common_components: contracts/openapi/common.v1.yaml\n"
                "contracts:\n"
                "  product:\n"
                "    path: contracts/openapi/product.v1.yaml\n",
                encoding="utf-8",
            )

            def fake_run(command, *_args, **_kwargs):
                if command and command[0] == "oxfmt":
                    candidate = pathlib.Path(command[-1])
                    self.assertEqual(raw, candidate.read_text(encoding="utf-8"))
                    candidate.write_text(canonical, encoding="utf-8")
                    return subprocess.CompletedProcess(command, 0, "", "")
                return subprocess.CompletedProcess(command, 0, raw, "")

            with (
                mock.patch.object(MOD, "ROOT", root),
                mock.patch.object(MOD, "ruby_yaml", return_value=registry),
                mock.patch.object(MOD, "bundle_openapi_with_common", return_value={"openapi": "3.1.0"}),
                mock.patch.object(MOD, "require"),
                mock.patch.object(MOD, "run", side_effect=fake_run),
            ):
                self.assertEqual(0, MOD.api_generate("ts", check=True))
                self.assertEqual(canonical, generated.read_text(encoding="utf-8"))
                generated.write_text(raw, encoding="utf-8")
                self.assertEqual(1, MOD.api_generate("ts", check=True))
                self.assertEqual(raw, generated.read_text(encoding="utf-8"))
                generated.write_text("stale\n", encoding="utf-8")
                self.assertEqual(0, MOD.api_generate("ts"))
                self.assertEqual(canonical, generated.read_text(encoding="utf-8"))

        source = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        self.assertIn('api_generate("ts", check=True)', source)
        self.assertIn('require("oxfmt")', source)
        self.assertIn('gen.add_argument("--check", action="store_true")', source)
        self.assertIn('"mutated_paths"', source)


if __name__ == "__main__":
    unittest.main()
