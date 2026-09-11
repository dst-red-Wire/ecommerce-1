"""Mutation tests for root authority and active-document regression prevention."""

import importlib.util
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("authority", ROOT / "scripts/architecture_authority.py")
authority = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(authority)


class ArchitectureAuthorityTest(unittest.TestCase):
    def test_repository(self):
        self.assertEqual([], authority.validate(ROOT))

    def test_active_superseded_statements(self):
        for statement in (
            "Exactly 17 services.", "17 Go services + Storefront/Admin workloads.",
            "exactly 17 backend service directories", "No checkout service.",
            "PROD frontend target: Next.js.", "ATS -> Storefront Next.js",
            "Dataset versioning: DVC + Git + SeaweedFS S3.",
            "BASELINE_V2.md is the canonical architecture authority.",
            "Active exact index: EXACT_TOPOLOGY_V2.md.",
            "Next.js is the target PROD frontend runtime after migration.",
            "DVC is the active dataset versioner; lakeFS was rejected.",
            "Exactly 17 services; the historical diagram is attached.",
            "BASELINE_V2.md is canonical; the prior plan is superseded.",
            "Use the canonical V2 baseline.", "Synchronize with baseline V2.",
            "M0 locks the V2 canonical baseline.",
        ):
            with self.subTest(statement=statement):
                self.assertTrue(authority.documentation_errors(statement))

    def test_historical_context_does_not_exempt_later_active_claim(self):
        self.assertEqual([], authority.documentation_errors(
            "DVC is superseded by lakeFS.\nNext.js is the migration source.\n"
            "Historical: exactly 17 services."
        ))
        self.assertTrue(authority.documentation_errors(
            "Historical: DVC was used.\nDataset versioning: DVC."
        ))
        self.assertEqual([], authority.documentation_errors("DVC has been superseded by lakeFS."))
        self.assertEqual([], authority.documentation_errors("Historical: the V2 baseline preceded the V5 lock."))

    def test_dvc_removal_and_lakefs_migration_directives(self):
        for statement in (
            "Remove DVC from the bootstrap.", "Migrate DVC datasets to lakeFS.",
            "Replace DVC with lakeFS.", "Remove remaining DVC configuration.",
            "DVC is superseded by lakeFS.", "DVC remains historical only.",
        ):
            with self.subTest(statement=statement):
                self.assertEqual([], authority.documentation_errors(statement))
        for statement in (
            "Use DVC for dataset versioning.", "Dataset versioner: DVC.",
            "Deploy DVC for MLOps datasets.", "DVC is the default dataset versioner.",
            "Migrate DVC datasets.", "Replace DVC with another versioner.",
        ):
            with self.subTest(statement=statement):
                self.assertTrue(authority.documentation_errors(statement))

    def test_active_superseded_platform_defaults_are_rejected(self):
        for statement in ("GitOps CD: FluxCD.", "Progressive delivery: Flagger.", "MinIO is the object store.",
                          "Use MinIO Community Edition as the object store.",
                          "Object storage default: MinIO Community Edition.",
                          "Logging baseline: Loki.", "SIEM: Splunk.",
                          "General logging pipeline: Fluent Bit."):
            with self.subTest(statement=statement):
                self.assertTrue(authority.documentation_errors(statement))

    def test_direct_superseded_role_assignments_are_rejected(self):
        for statement in (
            "FluxCD is the CD controller.", "Flagger is the rollout controller.",
            "Loki is the infrastructure log store.", "MinIO is the S3 backend.",
            "Splunk is the SIEM.", "Fluent Bit is the general log shipper.",
        ):
            with self.subTest(statement=statement):
                self.assertTrue(authority.documentation_errors(statement))

        for statement in (
            "FluxCD is superseded by Rancher Fleet.", "Flagger is replaced by Argo Rollouts.",
            "Loki is historical only.", "MinIO is not the S3 backend; SeaweedFS is.",
            "Remove MinIO and use SeaweedFS.", "Migrate DVC datasets to lakeFS.",
        ):
            with self.subTest(statement=statement):
                self.assertEqual([], authority.documentation_errors(statement))

    def test_superseded_diagrams_require_a_scoped_explicit_label(self):
        diagram = """## Deployment topology
```mermaid
graph LR
  Git --> FluxCD --> MinIO
  Flagger --> Loki
```
"""
        self.assertTrue(authority.documentation_errors(diagram))
        self.assertEqual([], authority.documentation_errors(diagram.replace(
            "## Deployment topology", "## Historical deployment topology", 1
        )))
        self.assertEqual([], authority.documentation_errors("Superseded:\n" + diagram.split("\n", 1)[1]))
        self.assertTrue(authority.documentation_errors("Historical: prior notes.\n\n" + diagram))

    def test_restricted_observability_roles_are_semantic(self):
        for statement in (
            "General logging pipeline: Data Prepper + OpenSearch.",
            "Prometheus is the primary TSDB.",
            "Use Fluent Bit for general logging.",
            "Application logs -> VictoriaLogs.",
        ):
            with self.subTest(statement=statement):
                self.assertTrue(authority.documentation_errors(statement))
        for statement in (
            "Historical: General logging used Data Prepper + OpenSearch.",
            "Prometheus is not the primary TSDB.",
            "Fluent Bit is superseded for general logging.",
        ):
            with self.subTest(statement=statement):
                self.assertEqual([], authority.documentation_errors(statement))

    def test_retirement_is_scoped_to_the_superseded_component(self):
        for statement in ("FluxCD, not Fleet, is the GitOps CD default.",
                          "MinIO, not SeaweedFS, is the object store.",
                          "Fluent Bit, not VictoriaLogs, is the general logging baseline.",
                          "FluxCD is superseded, and Flagger is the active progressive delivery controller.",
                          "FluxCD is superseded, but use MinIO Community Edition as object storage.",
                          "MinIO is superseded, but Fluent Bit is the general logging pipeline.",
                          "Flagger is retired; FluxCD is the GitOps CD default.",
                          "Loki is superseded, but Splunk is the SIEM baseline."):
            with self.subTest(statement=statement):
                self.assertTrue(authority.documentation_errors(statement))
        for statement in ("FluxCD is superseded by Fleet.", "FluxCD is not the active GitOps controller.",
                          "Do not use FluxCD; use Fleet.", "Fluent Bit is not used for general logging.",
                          "MinIO CE has been superseded by SeaweedFS.",
                          "FluxCD is superseded and Flagger is superseded.",
                          "FluxCD and Flagger are both superseded.",
                          "Do not use FluxCD or Flagger.",
                          "MinIO Community Edition is superseded by SeaweedFS.",
                          "Loki and Splunk remain historical references only."):
            with self.subTest(statement=statement):
                self.assertEqual([], authority.documentation_errors(statement))

    def test_nextjs_active_directives_and_migration_context(self):
        for statement in ("Use Next.js for the Storefront.", "Deploy Next.js for the admin frontend.",
                          "Frontend framework: Next.js.", "Admin frontend uses Next.js.",
                          "Storefront is built with Next.js.", "Next.js is the production frontend framework."):
            with self.subTest(statement=statement):
                self.assertTrue(authority.documentation_errors(statement))
        for statement in ("Next.js is the migration source only.", "Migrate from Next.js to Go/templ/HTMX.",
                          "Legacy Next.js frontend remains only for migration reference.",
                          "Next.js is superseded as the PROD frontend target."):
            with self.subTest(statement=statement):
                self.assertEqual([], authority.documentation_errors(statement))

    def test_topology_assertions_and_operational_subsets(self):
        for statement in ("The topology consists of 17 backend services.", "The architecture includes 17 services.",
                          "The platform has 17 Go services.", "There are 17 Go services in the architecture.",
                          "Our backend consists of 17 services."):
            with self.subTest(statement=statement):
                self.assertTrue(authority.documentation_errors(statement))
        for statement in ("17 services were affected by the incident.",
                          "17 services have completed migration so far.", "tests passed for 17 services.",
                          "17 services currently have generated clients.", "17 of 19 services are healthy."):
            with self.subTest(statement=statement):
                self.assertEqual([], authority.documentation_errors(statement))

    def test_operational_service_counts_are_not_topology_claims(self):
        self.assertEqual([], authority.documentation_errors("Incident impact: 17 services were unavailable."))
        self.assertEqual([], authority.documentation_errors("17 backend services are complete; two remain."))

    def copy_repository(self, directory):
        root = Path(directory)
        for relative in ("architecture.lock.yaml", "AGENTS.md", "README.md"):
            shutil.copy2(ROOT / relative, root / relative)
        shutil.copytree(ROOT / "config", root / "config")
        shutil.copytree(ROOT / "docs", root / "docs")
        shutil.copytree(ROOT / "instruction", root / "instruction")
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        return root

    def test_mutated_lock_is_rejected(self):
        mutations = {
            "version": ("version: 5", "version: 2"),
            "index": ("docs/architecture/EXACT_TOPOLOGY_V5.md", "docs/architecture/EXACT_TOPOLOGY_V2.md"),
            "dataset": ("dataset_versioner: lakefs", "dataset_versioner: dvc"),
            "dag": ("M3-preprod-infrastructure: [M2-5-persistent-mgmt-bootstrap]",
                    "M3-preprod-infrastructure: [M2-golden-service-product]"),
            "contract": ("resilience_governance: config/contracts/resilience-governance.yaml",
                         "removed_resilience: config/contracts/resilience-governance.yaml"),
            "dns_ttl": ("critical_ttl_seconds: 60", "critical_ttl_seconds: 120"),
            "status": ("status: locked-for-build", "status: draft"),
        }
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            original = (root / "architecture.lock.yaml").read_text()
            for name, (before, after) in mutations.items():
                with self.subTest(name=name):
                    self.assertIn(before, original)
                    (root / "architecture.lock.yaml").write_text(original.replace(before, after, 1))
                    self.assertTrue(authority.validate(root))

    def test_closed_world_v5_mutation_matrix(self):
        """Unknown, duplicate, missing, and contradictory exact declarations all fail closed."""
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            lock_path = root / "architecture.lock.yaml"
            index_path = root / "docs/architecture/EXACT_TOPOLOGY_V5.md"
            waves_path = root / "config/infrastructure/deployment-waves.yaml"
            dag_path = root / "docs/architecture/DEPLOYMENT_DAG.md"
            originals = {path: path.read_text() for path in (lock_path, index_path, waves_path, dag_path)}
            mutations = (
                (lock_path, originals[lock_path] + "\nci: github-actions\n", "root keys"),
                (lock_path, originals[lock_path].replace("project: ecommerce\n", "", 1), "root keys"),
                (lock_path, originals[lock_path].replace("  fluxcd: rancher-fleet", "  fluxcd: fluxcd", 1),
                 "complete approved V5 registry"),
                (lock_path, originals[lock_path].replace(
                    "  fluxcd: rancher-fleet", "  fluxcd: rancher-fleet\n  legacy-gitops: fluxcd", 1),
                 "complete approved V5 registry"),
                (lock_path, originals[lock_path].replace(
                    "  dataset_versioner: lakefs",
                    "  dataset_versioner: lakefs\n  dataset_versioner: lakefs", 1),
                 "duplicate YAML mapping key"),
                (index_path, originals[index_path].replace(
                    "- `dataset_versioner`: `lakefs`",
                    "- `dataset_versioner`: `lakefs`\n- `feature_store`: `feast`", 1), "mlops role assignments"),
                (index_path, originals[index_path].replace(
                    "- `dataset_versioner`: `lakefs`",
                    "- `dataset_versioner`: `lakefs`\n- `dataset_versioner`: `lakefs`", 1),
                 "duplicate derived index assignment"),
                (index_path, originals[index_path].replace(
                    "- `metrics`: `victoriametrics`",
                    "- `metrics`: `victoriametrics`\n- `retention_store`: `thanos`", 1),
                 "observability role assignments"),
                (index_path, originals[index_path].replace(
                    "- `metrics`: `victoriametrics`",
                    "- `metrics`: `victoriametrics`\n- `metrics`: `victoriametrics`", 1),
                 "duplicate derived index assignment"),
                (waves_path, originals[waves_path].replace(
                    "rules:\n", "  - id: 97-legacy-gitops\n    requires: [95-mlops]\n    components: [fluxcd]\nrules:\n", 1),
                 "complete approved V5 schedule"),
                (waves_path, originals[waves_path].replace(
                    "  - id: 10-rke2", "  - id: 00-underlay\n    requires: []\n    components: [network]\n  - id: 10-rke2", 1),
                 "complete approved V5 schedule"),
                (waves_path, originals[waves_path].replace(
                    "components: [rke2-control-plane, rke2-workers]",
                    "components: [rke2-control-plane, rke2-workers, legacy-node]", 1),
                 "complete approved V5 schedule"),
                (index_path, originals[index_path].replace(
                    "- PROD-A `10.241.0.0/16`",
                    "- PROD-A `10.241.0.0/16`\n- PROD-A `10.241.0.0/16`", 1),
                 "duplicate derived index assignment"),
                (dag_path, originals[dag_path] + "\n" + next(
                    line for line in originals[dag_path].splitlines()
                    if line.startswith("Machine wave `50-observability`")
                ) + "\n", "exactly mirror machine wave 50-observability"),
            )
            for path, mutation, expected in mutations:
                with self.subTest(path=path.relative_to(root), expected=expected):
                    path.write_text(mutation)
                    self.assertTrue(any(expected in error for error in authority.validate(root)))
                    path.write_text(originals[path])
                    self.assertEqual([], authority.validate(root))

    def test_governed_lock_sections_reject_unknown_missing_and_wrong_types(self):
        mutations = (
            ("  forbidden_services: []", "  forbidden_services: []\n  shadow_services: []", "business keys"),
            ("  runtime_security: tetragon", "  runtime_security: tetragon\n  legacy_ci: github-actions", "platform keys"),
            ("  object_storage: seaweedfs-s3", "  object_storage: seaweedfs-s3\n  archive: minio", "stateful keys"),
            ("  gitops: rancher-fleet\n  bootstrap:", "  bootstrap:", "management_plane keys"),
            ("    migration_source: nextjs-react-node", "    migration_source: nextjs-react-node\n    package_manager: npm",
             "business.frontend_runtime keys"),
            ("stateful:\n  database: cloudnativepg-postgresql\n  events: strimzi-kafka-kraft\n"
             "  jobs: rabbitmq-quorum-queues\n  cache: redis-cluster\n  search: opensearch\n"
             "  object_storage: seaweedfs-s3", "stateful: []", "stateful must be a mapping"),
            ("  M9-prod-ab: [M8-preprod-certification]", "", "milestone_dependencies keys"),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            path = root / "architecture.lock.yaml"
            original = path.read_text()
            for before, after, expected in mutations:
                with self.subTest(expected=expected):
                    self.assertIn(before, original)
                    path.write_text(original.replace(before, after, 1))
                    self.assertTrue(any(expected in error for error in authority.validate(root)))
                    path.write_text(original)
                    self.assertEqual([], authority.validate(root))

    def test_lock_status_is_exact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            path = root / "architecture.lock.yaml"
            original = path.read_text()
            for mutation in ("status: draft", "status: unlocked", ""):
                path.write_text(original.replace("status: locked-for-build\n", f"{mutation}\n", 1))
                self.assertTrue(any("status must be locked-for-build" in error for error in authority.validate(root)))
            path.write_text(original)
            self.assertEqual([], authority.validate(root))

    def test_forbidden_services_must_remain_empty(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            path = root / "architecture.lock.yaml"
            original = path.read_text()
            for mutation in ("[pricing]", "[checkout]", "[fulfillment]", "[legacy, legacy]", "legacy"):
                with self.subTest(mutation=mutation):
                    path.write_text(original.replace("forbidden_services: []", f"forbidden_services: {mutation}", 1))
                    self.assertTrue(any("business.forbidden_services" in error for error in authority.validate(root)))
                    path.write_text(original)
                    self.assertEqual([], authority.validate(root))

    def test_prod_certified_topology_has_an_exact_nested_schema(self):
        mutations = (
            ("  physical_hosts_total: 6", "  physical_hosts_total: 6\n  physical_hosts_per_site_override: 5",
             "prod_certified_topology keys"),
            ("  sites:\n", "  sites:\n    unknown_site_policy: active\n", "prod_certified_topology.sites keys"),
            ("    prod-a:\n", "    prod-a:\n      unknown_directive: true\n",
             "prod_certified_topology.sites.prod-a keys"),
            ("    prod-b:\n", "    prod-b:\n      unknown_directive: true\n",
             "prod_certified_topology.sites.prod-b keys"),
            ("    prod-b:\n      private_block: 10.242.0.0/16\n      physical_hosts:\n"
             "        - b-host-01\n        - b-host-02\n        - b-host-03\n",
             "", "prod_certified_topology.sites keys"),
            ("  physical_hosts_total: 6\n", "", "prod_certified_topology keys"),
            ("  physical_hosts_total: 6", "  physical_hosts_total: six",
             "prod_certified_topology.physical_hosts_total must be an integer"),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            path = root / "architecture.lock.yaml"
            original = path.read_text()
            for before, after, expected in mutations:
                with self.subTest(expected=expected):
                    self.assertIn(before, original)
                    path.write_text(original.replace(before, after, 1))
                    self.assertTrue(any(expected in error for error in authority.validate(root)))
                    path.write_text(original)
                    self.assertEqual([], authority.validate(root))

    def test_complete_mlops_mapping_mutations_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            lock_path = root / "architecture.lock.yaml"
            index_path = root / "docs/architecture/EXACT_TOPOLOGY_V5.md"
            original_lock = lock_path.read_text()
            original_index = index_path.read_text()
            for before, after in (("dataset_versioner: lakefs", "dataset_versioner: pachyderm"),
                                  ("runtime: kserve-vllm", "runtime: mlflow")):
                lock_path.write_text(original_lock.replace(before, after, 1))
                index_path.write_text(original_index.replace(
                    f"- `{before.replace(': ', '`: `')}`", f"- `{after.replace(': ', '`: `')}`", 1))
                self.assertTrue(any("complete approved V5 mapping" in error for error in authority.validate(root)))
                lock_path.write_text(original_lock)
                index_path.write_text(original_index)
            self.assertEqual([], authority.validate(root))

    def test_canonical_frontend_set_and_deployment_are_exact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            lock_path = root / "architecture.lock.yaml"
            original_lock = lock_path.read_text()
            for mutation in ("    - admin\n", "    - storefront\n", "    - admin\n    - portal\n"):
                lock_path.write_text(original_lock.replace("    - admin\n", mutation, 1) if "portal" in mutation
                                     else original_lock.replace(mutation, "", 1))
                self.assertTrue(any("frontends" in error for error in authority.validate(root)))
                lock_path.write_text(original_lock)
            waves = root / "config/infrastructure/deployment-waves.yaml"
            original_waves = waves.read_text()
            waves.write_text(original_waves.replace("components: [storefront, admin]", "components: [storefront]"))
            self.assertTrue(any("frontend" in error for error in authority.validate(root)))
            waves.write_text(original_waves.replace("components: [storefront, admin]",
                                                    "components: [storefront, admin, portal]"))
            self.assertTrue(any("frontend" in error for error in authority.validate(root)))
            for frontend in ("storefront", "admin"):
                waves.write_text(original_waves.replace(
                    "components: [network, dns-prerequisites, time-sync, image-mirrors]",
                    f"components: [network, dns-prerequisites, time-sync, image-mirrors, {frontend}]"))
                self.assertTrue(any("frontend" in error for error in authority.validate(root)))
            waves.write_text(original_waves)
            self.assertEqual([], authority.validate(root))

    def test_deployment_waves_status_is_exact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            waves = root / "config/infrastructure/deployment-waves.yaml"
            original = waves.read_text()
            for mutation in ("status: draft", "status: inexact", ""):
                waves.write_text(original.replace("status: exact\n", f"{mutation}\n", 1))
                self.assertIn("deployment-waves.yaml status must be exact", authority.validate(root))
            waves.write_text(original)
            self.assertEqual([], authority.validate(root))

    def test_duplicate_subordinate_mlops_assignments_are_rejected(self):
        mutations = (
            ("dataset_versioner", "mlflow"),
            ("dataset_versioner", "lakefs"),
            ("runtime", "mlflow"),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            path = root / "docs/architecture/MLOPS_TOPOLOGY_V1.md"
            original = path.read_text()
            for role, value in mutations:
                with self.subTest(role=role, value=value):
                    assignment = f"- `{role}`: `"
                    line = next(line for line in original.splitlines() if line.startswith(assignment))
                    path.write_text(original.replace(line, f"{line}\n- `{role}`: `{value}`", 1))
                    self.assertIn(f"duplicate subordinate MLOps assignment: {role}", authority.validate(root))
                    path.write_text(original)
                    self.assertEqual([], authority.validate(root))

    def test_delivery_guidance_mutations_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            self.assertEqual([], authority.validate(root))
            agents = root / "AGENTS.md"
            original = agents.read_text()
            agents.write_text(original.replace("M2.5 -> M3 PREPROD infra", "M1 -> M3 PREPROD infra"))
            self.assertTrue(any("build sequence" in error for error in authority.validate(root)))
            agents.write_text(original)
            plan = root / "docs/project/MASTER_EXECUTION_PLAN.md"
            original_plan = plan.read_text()
            plan.write_text(original_plan.replace("M2.5 PROVEN; exact infrastructure", "M1 PROVEN; exact infrastructure"))
            self.assertTrue(any("gate M3" in error for error in authority.validate(root)))

    def test_readiness_and_m25_handoff_mutations_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            readiness = root / "docs/project/TECHNICAL_READINESS.md"
            original = readiness.read_text()
            for replacement in ("M1 PROVEN", "M2 PROVEN", "a completed prerequisite"):
                readiness.write_text(original.replace("M2.5 PROVEN", replacement))
                self.assertTrue(any("TECHNICAL_READINESS" in error for error in authority.validate(root)))
                readiness.write_text(original)
            handoff = root / "docs/project/CODEX_HANDOFFS.md"
            original_handoff = handoff.read_text()
            for required in ("## M2.5 prompt", "Tracker: `#15`", "Entry gate: M1 PROVEN", "Evidence required for M2.5 PROVEN", "That PROVEN state enables M3"):
                handoff.write_text(original_handoff.replace(required, "removed", 1))
                self.assertTrue(any("executable M2.5" in error for error in authority.validate(root)))
                handoff.write_text(original_handoff)
            self.assertEqual([], authority.validate(root))

    def test_declared_topology_contract_deletions_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            for relative in ("docs/architecture/PROD_TOPOLOGY_V2.md", "docs/architecture/DEPLOYMENT_DAG.md",
                             "docs/architecture/SECURITY_TRUST_ZONES.md", "docs/architecture/OBSERVABILITY_TOPOLOGY_V1.md"):
                path = root / relative
                original = path.read_text()
                path.unlink()
                self.assertTrue(any(relative in error for error in authority.validate(root)))
                path.write_text(original)
            self.assertEqual([], authority.validate(root))

    def test_required_topology_contract_registrations_are_rejected_when_file_is_also_deleted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            lock_path = root / "architecture.lock.yaml"
            original_lock = lock_path.read_text()
            for key, relative in (("prod", "docs/architecture/PROD_TOPOLOGY_V2.md"),
                                  ("mlops", "docs/architecture/MLOPS_TOPOLOGY_V1.md")):
                with self.subTest(key=key):
                    mutated = re.sub(rf"^  {key}: .*\n", "", original_lock, count=1, flags=re.M)
                    lock_path.write_text(mutated)
                    path = root / relative
                    contents = path.read_text()
                    path.unlink()
                    self.assertTrue(any("complete approved V5 role/path registry" in error
                                        for error in authority.validate(root)))
                    path.write_text(contents)
                    lock_path.write_text(original_lock)
            self.assertEqual([], authority.validate(root))

    def test_missing_topology_contract_registrations_return_registry_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            lock_path = root / "architecture.lock.yaml"
            original = lock_path.read_text()
            for key in ("mlops", "prod"):
                with self.subTest(key=key):
                    lock_path.write_text(re.sub(rf"^  {key}: .*\n", "", original, count=1, flags=re.M))
                    self.assertEqual(
                        ["topology_contracts must match the complete approved V5 role/path registry"],
                        authority.validate(root),
                    )
            lock_path.write_text(original)
            self.assertEqual([], authority.validate(root))

    def test_v5_registry_role_path_mutations_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            lock_path = root / "architecture.lock.yaml"
            original = lock_path.read_text()
            for first, second in (("preprod", "prod"), ("mlops", "observability")):
                mutated = re.sub(rf"(^  {first}: )([^\n]+)", rf"\g<1>{authority.V5_TOPOLOGY_CONTRACTS[second]}", original, flags=re.M)
                mutated = re.sub(rf"(^  {second}: )([^\n]+)", rf"\g<1>{authority.V5_TOPOLOGY_CONTRACTS[first]}", mutated, flags=re.M)
                lock_path.write_text(mutated)
                self.assertTrue(any("topology_contracts must match" in error for error in authority.validate(root)))
                lock_path.write_text(original)
            mutated = original.replace("  preprod_inventory: config/infrastructure/preprod-inventory.yaml\n", "")
            lock_path.write_text(mutated)
            (root / "config/infrastructure/preprod-inventory.yaml").unlink()
            self.assertTrue(any("machine_contracts must match" in error for error in authority.validate(root)))

    def test_m5_autonomous_domain_handoff_mutations_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            handoff = root / "docs/project/CODEX_HANDOFFS.md"
            original = handoff.read_text()
            flow = "Cart -> Checkout -> Pricing/final totals -> Tax -> Fraud/Risk -> delivery-context validation -> Order"
            for before, after in ((flow, flow.replace(" -> Tax", " -> Order -> Tax")),
                                  (flow, flow.replace(" -> Fraud/Risk", " -> Order -> Fraud/Risk")),
                                  ("Fulfillment -> Shipping", "Shipping")):
                handoff.write_text(original.replace(before, after, 1))
                self.assertTrue(any("M5 must preserve" in error for error in authority.validate(root)))
                handoff.write_text(original)
            self.assertEqual([], authority.validate(root))

    def test_deployment_wave_service_coverage_mutations_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            path = root / "config/infrastructure/deployment-waves.yaml"
            original = path.read_text()
            for before, after in (("notification, order, payment", "notification, payment"),
                                  ("tracking, fulfillment, review", "tracking, unknown-service, review")):
                path.write_text(original.replace(before, after, 1))
                self.assertTrue(any("deployment waves" in error for error in authority.validate(root)))
                path.write_text(original)
            self.assertEqual([], authority.validate(root))

    def test_deployment_dependency_ordering_mutations_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            path = root / "config/infrastructure/deployment-waves.yaml"
            original = path.read_text()
            for before, after in (("      - [catalog, cart]\n    serial_after_parallel: [checkout]",
                                   "      - [catalog, cart, checkout]\n    serial_after_parallel: []"),
                                  ("shipping, fraud-risk", "fraud-risk")):
                path.write_text(original.replace(before, after, 1))
                self.assertTrue(any("deployment" in error for error in authority.validate(root)))
                path.write_text(original)
            path.write_text(original.replace("shipping, fraud-risk", "fraud-risk", 1).replace(
                "tracking, fulfillment", "tracking, fulfillment, shipping", 1))
            self.assertTrue(any("fulfillment after synchronous dependency shipping" in error
                                for error in authority.validate(root)))
            path.write_text(original)
            for component in authority.DEPLOYABLE_MLOPS:
                path.write_text(original.replace(f", {component}", "", 1).replace(f"[{component}, ", "[", 1))
                self.assertTrue(any("MLOps" in error for error in authority.validate(root)))
                path.write_text(original)
            path.write_text(original.replace("components: [network, dns-prerequisites, time-sync, image-mirrors]",
                                             "components: [network, dns-prerequisites, time-sync, image-mirrors, lakefs]")
                                 .replace("serial_after_parallel: [lakefs, mlflow, kserve-vllm, evidently-tekton-batch]",
                                          "serial_after_parallel: [mlflow, kserve-vllm, evidently-tekton-batch]"))
            self.assertTrue(any("lakefs after MLOps dependency seaweedfs" in error
                                for error in authority.validate(root)))
            path.write_text(original)
            self.assertEqual([], authority.validate(root))

    def test_exact_contract_mutations_are_rejected(self):
        mutations = (
            ("config/contracts/security-trust-zones.yaml", "  Z6: backup-evidence-dfir\n", ""),
            ("config/contracts/security-trust-zones.yaml", "  default: deny", "  default: allow"),
            ("config/contracts/security-trust-zones.yaml", "image-layers, ci-logs", "image-layers, ci-output"),
            ("config/contracts/resilience-governance.yaml", "  destroy_required_forensic_evidence: forbidden",
             "  destroy_required_forensic_evidence: allowed"),
            ("config/contracts/resilience-governance.yaml", "    - dns-gslb-change", ""),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            for relative, before, after in mutations:
                with self.subTest(relative=relative, invariant=before.strip()):
                    path = root / relative
                    original = path.read_text()
                    self.assertIn(before, original)
                    path.write_text(original.replace(before, after, 1))
                    self.assertTrue(any(relative in error for error in authority.validate(root)))
                    path.write_text(original)
            self.assertEqual([], authority.validate(root))

    def test_observability_guidance_mutation_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            agents = root / "AGENTS.md"
            original = agents.read_text()
            agents.write_text(original.replace("- Infrastructure logs: OpenTelemetry Collector -> VictoriaLogs.",
                                               "- General logging pipeline: Fluent Bit + Data Prepper + OpenSearch."))
            self.assertTrue(any("general logging" in error for error in authority.validate(root)))
            agents.write_text(original)
            self.assertEqual([], authority.validate(root))

    def test_exact_observability_source_mutations_are_rejected(self):
        mutations = (
            ("docs/architecture/PREPROD_TOPOLOGY_V2.md", "OpenTelemetry Collector where the role requires host or infrastructure telemetry",
             "Fluent Bit where the role requires host or general logging"),
            ("docs/architecture/AIOPS_TOPOLOGY_V1.md", "VictoriaLogs infrastructure logs and Rotel/ClickHouse/HyperDX application observability",
             "OpenSearch Logs as the general observability source"),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            for relative, before, after in mutations:
                with self.subTest(relative=relative):
                    path = root / relative
                    original = path.read_text()
                    self.assertIn(before, original)
                    path.write_text(original.replace(before, after, 1))
                    self.assertTrue(authority.validate(root))
                    path.write_text(original)
                    self.assertEqual([], authority.validate(root))

    def test_derived_index_mutations_are_rejected(self):
        mutations = (
            ("3 physical failure domains", "5 physical failure domains"),
            ("3 CP + 5 workers", "2 CP + 4 workers"),
            ("Exactly 19 backend services", "Exactly 18 backend services"),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            index = root / "docs/architecture/EXACT_TOPOLOGY_V5.md"
            original = index.read_text()
            for before, after in mutations:
                with self.subTest(mutation=f"{before} -> {after}"):
                    self.assertIn(before, original)
                    index.write_text(original.replace(before, after, 1))
                    self.assertTrue(any("derived index drift" in error for error in authority.validate(root)))
                    index.write_text(original)
                    self.assertEqual([], authority.validate(root))

    def test_derived_role_assignment_mutations_are_rejected(self):
        mutations = (
            (("- `ci`: `tekton`", "- `ci`: `harbor`"),
             ("- `registry`: `harbor`", "- `registry`: `tekton`")),
            (("- `desired_state`: `rancher-fleet`", "- `desired_state`: `argo-rollouts`"),
             ("- `progressive_delivery`: `argo-rollouts`", "- `progressive_delivery`: `rancher-fleet`")),
            (("- `dataset_versioner`: `lakefs`", "- `dataset_versioner`: `mlflow`"),
             ("- `experiments_lineage`: `mlflow`", "- `experiments_lineage`: `lakefs`")),
            (("- `artifact_registry`: `harbor`", "- `artifact_registry`: `tekton`"),
             ("- `orchestration`: `tekton`", "- `orchestration`: `harbor`")),
            (("- `runtime_nodejs`: `false`", "- `runtime_nodejs`: `true`"),),
            (("- `module_file`: `frontend/go.mod`", "- `module_file`: `frontend/node.mod`"),),
            (("- `migration_source`: `nextjs-react-node`", "- `migration_source`: `go-templ-htmx`"),),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            index = root / "docs/architecture/EXACT_TOPOLOGY_V5.md"
            original = index.read_text()
            for replacements in mutations:
                with self.subTest(mutation=replacements):
                    mutated = original
                    for before, after in replacements:
                        mutated = mutated.replace(before, after, 1)
                    index.write_text(mutated)
                    self.assertTrue(any("derived index drift" in error for error in authority.validate(root)))
                    index.write_text(original)
                    self.assertEqual([], authority.validate(root))

    def test_l2_context_contract_mutation_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            router = root / "config/context/router.yaml"
            original = router.read_text()
            router.write_text(original.replace("      - config/contracts/resilience-governance.yaml\n", "", 1))
            self.assertTrue(any("L2 context" in error for error in authority.validate(root)))
            router.write_text(original)
            self.assertEqual([], authority.validate(root))

    def test_derived_index_private_blocks_are_bound_to_site_labels(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            path = root / "docs/architecture/EXACT_TOPOLOGY_V5.md"
            original = path.read_text()
            mutations = (
                original.replace("PROD-A `10.241.0.0/16`", "PROD-A `10.242.0.0/16`").replace(
                    "PROD-B `10.242.0.0/16`", "PROD-B `10.241.0.0/16`"),
                original.replace("permanent MGMT `10.243.0.0/16`", "permanent MGMT `10.241.0.0/16`"),
                original.replace("PROD-B `10.242.0.0/16`", "PROD-B `10.243.0.0/16`"),
                original.replace("PROD-B `10.242.0.0/16`", "PROD-B `10.241.0.0/16`"),
            )
            for mutation in mutations:
                path.write_text(mutation)
                self.assertIn(
                    "derived index drift from architecture.lock.yaml: labeled private block mapping",
                    authority.validate(root),
                )
            path.write_text(original)
            self.assertEqual([], authority.validate(root))

    def test_duplicate_derived_index_private_block_labels_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            path = root / "docs/architecture/EXACT_TOPOLOGY_V5.md"
            original = path.read_text()
            marker = "- PROD-A `10.241.0.0/16`"
            for duplicate in ("- PROD-A `192.0.2.0/24`", marker):
                with self.subTest(duplicate=duplicate):
                    path.write_text(original.replace(marker, f"{duplicate}\n{marker}", 1))
                    self.assertIn("duplicate derived index assignment: network.private_blocks.PROD-A",
                                  authority.validate(root))
                    path.write_text(original)
                    self.assertEqual([], authority.validate(root))

    def test_derived_index_service_list_is_exact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            path = root / "docs/architecture/EXACT_TOPOLOGY_V5.md"
            original = path.read_text()
            service_list = "`catalog`, `product`"
            for replacement in (
                "`warehouse`, `catalog`, `product`",
                "`catalog`, `product`, `product`",
                "`catalog`, `warehouse`",
                "`product`",
            ):
                path.write_text(original.replace(service_list, replacement, 1))
                self.assertIn(
                    "derived index drift from architecture.lock.yaml: business.services membership/order",
                    authority.validate(root),
                )
            path.write_text(original)
            self.assertEqual([], authority.validate(root))

    def test_exact_prose_dag_mirrors_delivery_and_observability_waves(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            path = root / "docs/architecture/DEPLOYMENT_DAG.md"
            original = path.read_text()
            for component, wave_id in (("rotel", "50-observability"), ("clickhouse", "50-observability"),
                                       ("hyperdx", "50-observability"),
                                       ("mongodb-oss-self-hosted", "50-observability"),
                                       ("vmalert", "50-observability"),
                                       ("argo-rollouts", "30-gitops-identity")):
                marker = f"`{component}`"
                line = next(line for line in original.splitlines()
                            if line.startswith(f"Machine wave `{wave_id}` scheduled components:"))
                path.write_text(original.replace(line, line.replace(marker, "", 1), 1))
                self.assertIn(f"DEPLOYMENT_DAG.md must exactly mirror machine wave {wave_id}",
                              authority.validate(root))
            line = next(line for line in original.splitlines()
                        if line.startswith("Machine wave `50-observability` scheduled components:"))
            path.write_text(original.replace(line, f"{line}, `prometheus-server`", 1))
            self.assertIn("DEPLOYMENT_DAG.md must exactly mirror machine wave 50-observability",
                          authority.validate(root))
            path.write_text(original)
            self.assertEqual([], authority.validate(root))

    def test_duplicate_prose_machine_wave_declarations_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            path = root / "docs/architecture/DEPLOYMENT_DAG.md"
            original = path.read_text()
            canonical = next(line for line in original.splitlines()
                             if line.startswith("Machine wave `50-observability` scheduled components:"))
            for duplicate in (canonical,
                              "Machine wave `50-observability` scheduled components: `prometheus-server`"):
                with self.subTest(duplicate=duplicate):
                    path.write_text(f"{original}\n{duplicate}\n")
                    self.assertIn("DEPLOYMENT_DAG.md must exactly mirror machine wave 50-observability",
                                  authority.validate(root))
                    path.write_text(original)
                    self.assertEqual([], authority.validate(root))

    def test_spire_is_scheduled_once_before_spiffe_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            path = root / "docs/architecture/DEPLOYMENT_DAG.md"
            original = path.read_text()
            wave20 = next(line for line in original.splitlines()
                          if line.startswith("Machine wave `20-network-security`"))
            wave30 = next(line for line in original.splitlines()
                          if line.startswith("Machine wave `30-gitops-identity`"))
            mutations = (
                original.replace(wave30, f"{wave30}, `spire`", 1),
                original.replace(f"{wave20}\n\nGate W3:",
                                 f"Gate W3:", 1).replace(
                                     "## Wave 4 — GitOps/secrets/mesh control",
                                     f"## Wave 4 — GitOps/secrets/mesh control\n\n{wave20}", 1),
            )
            for mutation in mutations:
                path.write_text(mutation)
                self.assertIn("SPIRE must be scheduled exactly once before Gate W3 verifies SPIFFE issuance",
                              authority.validate(root))
                path.write_text(original)
                self.assertEqual([], authority.validate(root))

    def test_l2_context_includes_v5_exact_index(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            router = root / "config/context/router.yaml"
            original = router.read_text()
            router.write_text(original.replace("    - docs/architecture/EXACT_TOPOLOGY_V5.md\n", "", 1))
            self.assertTrue(any("L2 context" in error for error in authority.validate(root)))
            router.write_text(original)
            self.assertEqual([], authority.validate(root))

    def test_duplicate_derived_role_assignments_are_rejected(self):
        mutations = (
            ("- `runtime_nodejs`: `false`", "- `runtime_nodejs`: `false`\n- `runtime_nodejs`: `true`"),
            ("- `runtime_nodejs`: `false`", "- `runtime_nodejs`: `false`\n- `runtime_nodejs`: `false`"),
            ("- `dataset_versioner`: `lakefs`", "- `dataset_versioner`: `lakefs`\n- `dataset_versioner`: `mlflow`"),
            ("- `telemetry`: `opentelemetry`", "- `telemetry`: `opentelemetry`\n- `telemetry`: `rotel`"),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            index = root / "docs/architecture/EXACT_TOPOLOGY_V5.md"
            original = index.read_text()
            for before, after in mutations:
                with self.subTest(mutation=after):
                    index.write_text(original.replace(before, after, 1))
                    self.assertTrue(any("duplicate derived index assignment" in error
                                        for error in authority.validate(root)))
                    index.write_text(original)
                    self.assertEqual([], authority.validate(root))

    def test_observability_role_mutations_are_rejected(self):
        mutations = (
            ("- `application_gateway`: `rotel`", "- `application_gateway`: `opentelemetry-collector`"),
            ("- `application_observability_storage`: `clickhouse`",
             "- `application_observability_storage`: `victorialogs`"),
            ("- `hyperdx_metadata_store`: `mongodb-oss-self-hosted`",
             "- `hyperdx_metadata_store`: `postgresql`"),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            index = root / "docs/architecture/EXACT_TOPOLOGY_V5.md"
            original = index.read_text()
            for before, after in mutations:
                with self.subTest(mutation=before):
                    index.write_text(original.replace(before, after, 1))
                    self.assertTrue(any("observability." in error for error in authority.validate(root)))
                    index.write_text(original)
                    self.assertEqual([], authority.validate(root))

    def test_observability_role_mapping_is_complete_and_exact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            index = root / "docs/architecture/EXACT_TOPOLOGY_V5.md"
            original = index.read_text()
            marker = "- `telemetry`: `opentelemetry`"
            mutations = (
                original.replace(marker, f"{marker}\n- `retention_store`: `thanos`", 1),
                original.replace(f"{marker}\n", "", 1),
                original.replace(marker, f"{marker}\n{marker}", 1),
                original.replace(marker, "- `telemetry`: `rotel`", 1),
            )
            for mutation in mutations:
                index.write_text(mutation)
                self.assertTrue(any("observability" in error for error in authority.validate(root)))
                index.write_text(original)
                self.assertEqual([], authority.validate(root))

    def test_exact_topology_status_mutations_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            topology = root / "docs/architecture/PROD_TOPOLOGY_V2.md"
            original = topology.read_text()
            for status in ("INEXACT", "EXACT DRAFT", "NOT-EXACT", "EXACTLY", "DRAFT"):
                topology.write_text(original.replace("Status: `EXACT`", f"Status: `{status}`", 1))
                self.assertTrue(any("readable and EXACT" in error for error in authority.validate(root)))
            topology.write_text(original.replace("Status: `EXACT`", "status: `exact`", 1))
            self.assertEqual([], authority.validate(root))

    def test_m7_coverage_threshold_mutations_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            handoff = root / "docs/project/CODEX_HANDOFFS.md"
            original = handoff.read_text()
            for before, after in ((">=80% global coverage", ""),
                                  (">=80% global coverage", "79% global coverage"),
                                  (">=90% critical-code coverage", ""),
                                  (">=90% critical-code coverage", "89% critical-code coverage")):
                with self.subTest(mutation=f"{before} -> {after}"):
                    handoff.write_text(original.replace(before, after, 1))
                    self.assertTrue(any("coverage" in error for error in authority.validate(root)))
                    handoff.write_text(original)
                    self.assertEqual([], authority.validate(root))

    def test_management_plane_mutations_are_rejected(self):
        mutations = (
            ("architecture.lock.yaml", "provider: hetzner-cloud", "provider: aws"),
            ("architecture.lock.yaml", "requires_human_apply_gate: true", "requires_human_apply_gate: false"),
            ("config/infrastructure/mgmt-inventory.yaml", "provider: hetzner-cloud", "provider: aws"),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            for relative, before, after in mutations:
                path = root / relative
                original = path.read_text()
                path.write_text(original.replace(before, after, 1))
                self.assertTrue(any("management_plane" in error for error in authority.validate(root)))
                path.write_text(original)
                self.assertEqual([], authority.validate(root))

    def test_new_documents_and_missing_authority_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            self.assertEqual([], authority.validate(root))
            new = root / "new-guide.md"
            new.write_text("Exactly 17 services.")
            self.assertTrue(any("new-guide.md" in e for e in authority.validate(root)))
            new.unlink()
            (root / "architecture.lock.yaml").unlink()
            self.assertTrue(authority.validate(root))


if __name__ == "__main__":
    unittest.main()
