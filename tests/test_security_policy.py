import gzip
import hashlib
import importlib.util
import io
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "security_policy", ROOT / "scripts/security_policy.py"
)
SECURITY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SECURITY)
POLICY = SECURITY.load_policy(ROOT)
NOW = datetime(2026, 9, 24, 12, 0, tzinfo=timezone.utc)


class SecurityPolicyTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.dataset_dir = self.root / ".context/security-datasets"
        self.dataset_dir.mkdir(parents=True)

    def tearDown(self):
        self.temporary.cleanup()

    def datasets(self, *, kev=(), scores=None, kev_age=0, epss_age=0, bad_checksum=""):
        scores = scores or {}
        kev_raw = json.dumps(
            {
                "catalogVersion": "test",
                "dateReleased": NOW.isoformat(),
                "vulnerabilities": [{"cveID": item} for item in kev],
            }
        ).encode()
        csv_text = "#model_version:test,score_date:2026-09-24T00:00:00+00:00\n"
        csv_text += "cve,epss,percentile\n"
        csv_text += "".join(f"{cve},{score},0.9\n" for cve, score in scores.items())
        epss_raw = gzip.compress(csv_text.encode())
        (self.dataset_dir / "cisa-kev.json").write_bytes(kev_raw)
        (self.dataset_dir / "epss.csv.gz").write_bytes(epss_raw)
        manifest = {
            "schema_version": 1,
            "generated_at": NOW.isoformat(),
            "datasets": {
                "kev": {
                    "source": POLICY["risk_datasets"]["kev"]["source"],
                    "file": "cisa-kev.json",
                    "snapshot_at": (NOW - timedelta(hours=kev_age)).isoformat(),
                    "sha256": hashlib.sha256(kev_raw).hexdigest(),
                    "provenance": "test-fixture",
                },
                "epss": {
                    "source": POLICY["risk_datasets"]["epss"]["source"],
                    "file": "epss.csv.gz",
                    "snapshot_at": (NOW - timedelta(hours=epss_age)).isoformat(),
                    "sha256": hashlib.sha256(epss_raw).hexdigest(),
                    "provenance": "test-fixture",
                },
            },
        }
        if bad_checksum:
            manifest["datasets"][bad_checksum]["sha256"] = "0" * 64
        (self.dataset_dir / "manifest.json").write_text(
            json.dumps(manifest), encoding="utf-8"
        )

    def finding(self, severity, **values):
        return {
            "finding_id": values.pop("finding_id", "CVE-2026-1000"),
            "identifier_namespace": values.pop("identifier_namespace", None),
            "aliases": values.pop("aliases", []),
            "severity": severity,
            "cvss": values.pop("cvss", None),
            "fixed_version": values.pop("fixed_version", ""),
            "fix_available": values.pop("fix_available", False),
            "reachable": values.pop("reachable", None),
            "presence": values.pop("presence", "package"),
            "reachability_evidence": values.pop("reachability_evidence", None),
            "artifact": "product@sha256:" + "d" * 64,
            "scope": "oci_images",
            "scanner": "trivy",
            "ecosystem": values.pop("ecosystem", "alpine"),
            "package": values.pop("package", "test-package"),
            "installed_version": values.pop("installed_version", "1.0.0"),
            **values,
        }

    def payload(self, findings, **values):
        payload = {
            "base_sha": "a" * 40,
            "head_sha": "b" * 40,
            "source_head_sha": "b" * 40,
            "head_tree_sha": "c" * 40,
            "artifact": "product@sha256:" + "d" * 64,
            "artifact_digest": "sha256:" + "d" * 64,
            "scope": "oci_images",
            "environment": "release",
            "release": True,
            "scanner_runs": [
                {
                    "name": "trivy",
                    "status": "PASS",
                    "version": "test",
                    "checksum": "f" * 64,
                }
            ],
            "required_scanners": ["trivy"],
            "findings": findings,
            "exceptions": [],
        }
        payload.update(values)
        return payload

    def evaluate(self, findings, **values):
        trusted_owner_authorizations = values.pop("_trusted_owner_authorizations", None)
        return SECURITY.evaluate(
            self.payload(findings, **values),
            POLICY,
            self.root,
            now=NOW,
            trusted_owner_authorizations=trusted_owner_authorizations,
        )

    def exception(self, finding, **values):
        item = {
            "finding_id": finding["finding_id"],
            "owner": "security-engineering",
            "reason": "temporary compensating control while upstream fix is unavailable",
            "scope": finding["scope"],
            "affected_artifact": finding["artifact"],
            "created_at": (NOW - timedelta(hours=1)).isoformat(),
            "expires_at": (NOW + timedelta(days=2)).isoformat(),
            "approval": f"/owner-authorization approve scope=vulnerability-exception:{finding['finding_id']} sha={'b' * 40}",
            "exact_sha": "b" * 40,
            "environment": "release",
            "mitigation": "network isolation",
            "remediation_issue": "#999",
        }
        item.update(values)
        return item

    def test_severity_decisions_fix_and_unfixed(self):
        cases = (
            (
                self.finding("CRITICAL", fix_available=True, fixed_version="1.0.1"),
                "BLOCK",
            ),
            (
                self.finding("HIGH", fix_available=True, fixed_version="1.0.1"),
                "BLOCK",
            ),
            (self.finding("HIGH", fix_available=False), "BLOCK"),
            (self.finding("MEDIUM"), "REPORT"),
            (self.finding("LOW"), "REPORT"),
        )
        for finding, expected in cases:
            with self.subTest(
                severity=finding["severity"], fixed=finding["fix_available"]
            ):
                self.datasets(scores={finding["finding_id"]: 0.1})
                evidence = self.evaluate([finding])
                self.assertEqual(expected, evidence["policy_decisions"][0]["decision"])
                self.assertEqual(
                    finding["fix_available"],
                    evidence["policy_decisions"][0]["fix_available"],
                )

    def test_medium_kev_and_epss_threshold_block(self):
        kev = self.finding("MEDIUM", finding_id="CVE-2026-2000")
        epss = self.finding("MEDIUM", finding_id="CVE-2026-2001")
        self.datasets(
            kev=[kev["finding_id"]],
            scores={kev["finding_id"]: 0.1, epss["finding_id"]: 0.70},
        )
        evidence = self.evaluate([kev, epss])
        self.assertEqual(
            ["BLOCK", "BLOCK"],
            [item["decision"] for item in evidence["policy_decisions"]],
        )

    def test_unknown_release_fails_closed(self):
        finding = self.finding("UNKNOWN")
        self.datasets(scores={finding["finding_id"]: 0.1})
        evidence = self.evaluate([finding])
        self.assertEqual("BLOCK", evidence["final_result"])
        self.assertEqual("BLOCK", evidence["policy_decisions"][0]["decision"])

    def test_valid_temporary_exception_is_exact_and_expiring(self):
        finding = self.finding("HIGH")
        self.datasets(scores={finding["finding_id"]: 0.1})
        exception = self.exception(finding)
        evidence = self.evaluate(
            [finding],
            exceptions=[exception],
            _trusted_owner_authorizations={
                exception["approval"]: {
                    "decision_authority": "repository-owner",
                    "recording_agent": "ChatGPT",
                    "explicit_owner_instruction": True,
                }
            },
        )
        self.assertEqual("PASS", evidence["final_result"])
        self.assertEqual(
            "ACCEPTED_TEMPORARILY", evidence["policy_decisions"][0]["decision"]
        )
        self.assertEqual(1, len(evidence["exceptions_used"]))

    def test_local_exception_cannot_forge_owner_authorization(self):
        finding = self.finding("HIGH")
        self.datasets(scores={finding["finding_id"]: 0.1})
        evidence = self.evaluate([finding], exceptions=[self.exception(finding)])
        self.assertEqual("BLOCK", evidence["final_result"])
        self.assertTrue(
            any(
                "owner authorization is not authenticated" in reason
                for reason in evidence["reasons"]
            )
        )
        self.assertEqual([], evidence["exceptions_used"])

    def test_exception_validation_is_fail_closed(self):
        finding = self.finding("HIGH")
        self.datasets(scores={finding["finding_id"]: 0.1})
        invalid = (
            ({"owner": ""}, "missing owner"),
            ({"expires_at": ""}, "missing expires_at"),
            ({"expires_at": (NOW - timedelta(minutes=1)).isoformat()}, "expired"),
            ({"scope": "repository_filesystem"}, "wrong advisory scope"),
            ({"affected_artifact": "other@sha256:" + "e" * 64}, "wrong artifact"),
        )
        for changes, expected in invalid:
            with self.subTest(expected=expected):
                evidence = self.evaluate(
                    [finding], exceptions=[self.exception(finding, **changes)]
                )
                self.assertEqual("BLOCK", evidence["final_result"])
                self.assertTrue(
                    any(expected in reason for reason in evidence["reasons"])
                )

    def test_dataset_staleness_and_checksum_are_blocking(self):
        finding = self.finding("LOW")
        cases = (
            ({"kev_age": 337}, "KEV dataset is stale"),
            ({"epss_age": 73}, "EPSS dataset is stale"),
            ({"bad_checksum": "kev"}, "KEV dataset checksum mismatch"),
        )
        for arguments, expected in cases:
            with self.subTest(expected=expected):
                self.datasets(scores={finding["finding_id"]: 0.1}, **arguments)
                evidence = self.evaluate([finding])
                self.assertEqual("BLOCK", evidence["final_result"])
                self.assertIn(expected, evidence["reasons"])

    def test_missing_and_failed_scanners_block(self):
        for runs, expected in (
            ([], "required scanner missing"),
            ([{"name": "trivy", "status": "FAIL"}], "scanner failure"),
        ):
            with self.subTest(expected=expected):
                evidence = self.evaluate(
                    [], scanner_runs=runs, required_scanners=["trivy"]
                )
                self.assertEqual("BLOCK", evidence["final_result"])
                self.assertTrue(
                    any(expected in reason for reason in evidence["reasons"])
                )

    def test_duplicate_and_malformed_scanner_runs_fail_closed(self):
        duplicate = self.payload([])["scanner_runs"] * 2
        for runs, expected in (
            (duplicate, "duplicate scanner run: trivy"),
            ([{"name": " trivy", "status": "PASS"}], "scanner run is malformed"),
            (["trivy"], "scanner run is malformed"),
        ):
            with self.subTest(expected=expected):
                evidence = self.evaluate([], scanner_runs=runs)
                self.assertEqual("BLOCK", evidence["final_result"])
                self.assertIn(expected, evidence["reasons"])

    def test_required_scanners_are_derived_from_scope(self):
        for scope, required in (
            ("oci_images", "trivy"),
            ("repository_filesystem", "trivy"),
            ("reachable_go_vulnerabilities", "govulncheck"),
        ):
            with self.subTest(scope=scope):
                evidence = self.evaluate(
                    [], scope=scope, scanner_runs=[], required_scanners=[]
                )
                self.assertEqual("BLOCK", evidence["final_result"])
                self.assertIn(required, evidence["required_scanners"])
                self.assertTrue(
                    any(
                        f"required scanner missing: {required}" in reason
                        for reason in evidence["reasons"]
                    )
                )

    def test_malformed_trivy_output_is_rejected(self):
        self.assertEqual(
            [],
            SECURITY.trivy_findings(
                {"SchemaVersion": 2, "ArtifactType": "filesystem"},
                artifact="repository",
                scope="repository_filesystem",
            ),
        )
        with self.assertRaisesRegex(ValueError, "missing Results"):
            SECURITY.trivy_findings(
                {}, artifact="repository", scope="repository_filesystem"
            )
        with self.assertRaisesRegex(TypeError, "malformed"):
            SECURITY.trivy_findings(
                {"Results": ["invalid"]},
                artifact="repository",
                scope="repository_filesystem",
            )

    def test_duplicate_findings_are_deduplicated_but_conflicts_block(self):
        finding = self.finding("LOW")
        self.datasets(scores={finding["finding_id"]: 0.1})
        exact = self.evaluate([finding, dict(finding)])
        self.assertEqual("PASS", exact["final_result"])
        self.assertEqual(1, len(exact["findings"]))
        conflict = self.evaluate(
            [
                finding,
                {**finding, "fix_available": True, "fixed_version": "1.0.1"},
            ]
        )
        self.assertEqual("BLOCK", conflict["final_result"])
        self.assertTrue(
            any("conflicting duplicate" in reason for reason in conflict["reasons"])
        )

    def test_same_advisory_in_distinct_packages_remains_distinct(self):
        first = self.finding("LOW", package="first", installed_version="1.0.0")
        second = self.finding("LOW", package="second", installed_version="2.0.0")
        self.datasets(scores={first["finding_id"]: 0.1})
        evidence = self.evaluate([first, second])
        self.assertEqual("PASS", evidence["final_result"])
        self.assertEqual(2, len(evidence["findings"]))
        self.assertEqual(
            ["first", "second"],
            sorted(item["package"] for item in evidence["findings"]),
        )

    def test_supported_advisory_namespaces_and_malformed_identifier(self):
        for finding_id in (
            "CVE-2026-93990",
            "GO-2026-5932",
            "GHSA-XXXX-XXXX-XXXX",
            "OSV-2026-1234",
        ):
            with self.subTest(finding_id=finding_id):
                finding = self.finding(
                    "LOW",
                    finding_id=finding_id,
                    scanner="govulncheck",
                    ecosystem="Go",
                    reachable=False,
                    presence="module",
                    reachability_evidence={
                        "scanner": "govulncheck",
                        "scan_mode": "binary",
                        "scan_level": "symbol",
                    },
                )
                if finding_id.startswith("CVE-"):
                    self.datasets(scores={finding_id: 0.1})
                evidence = self.evaluate([finding])
                self.assertEqual("PASS", evidence["final_result"])
                self.assertEqual(
                    finding_id.split("-", 1)[0],
                    evidence["findings"][0]["identifier_namespace"],
                )
        malformed = self.evaluate(
            [self.finding("LOW", finding_id="NOT-A-VULNERABILITY")]
        )
        self.assertEqual("BLOCK", malformed["final_result"])
        self.assertTrue(
            any(
                "malformed advisory identifier" in item for item in malformed["reasons"]
            )
        )

    def test_non_cve_alias_drives_cve_risk_datasets(self):
        finding = self.finding(
            "MEDIUM",
            finding_id="GO-2026-2000",
            aliases=["CVE-2026-2000"],
            ecosystem="Go",
            package="example.org/vulnerable",
        )
        self.datasets(kev=["CVE-2026-2000"], scores={"CVE-2026-2000": 0.1})
        evidence = self.evaluate([finding])
        decision = evidence["policy_decisions"][0]
        self.assertEqual("BLOCK", decision["decision"])
        self.assertTrue(decision["kev"])
        self.assertEqual("APPLICABLE", decision["kev_status"])

    def test_non_cve_without_alias_is_not_a_false_pass(self):
        finding = self.finding(
            "LOW",
            finding_id="GO-2026-2001",
            ecosystem="Go",
            package="example.org/vulnerable",
            reachable=None,
            presence="module",
        )
        evidence = self.evaluate([finding])
        self.assertEqual("BLOCK", evidence["final_result"])
        decision = evidence["policy_decisions"][0]
        self.assertEqual("BLOCK", decision["decision"])
        self.assertEqual("NOT_APPLICABLE_NO_CVE_ALIAS", decision["kev_status"])
        self.assertEqual(
            "NOT_APPLICABLE_NO_CVE_ALIAS",
            evidence["kev_dataset_identity"]["status"],
        )

    def test_go_reachability_is_fail_closed_unless_exactly_unreachable(self):
        base = {
            "finding_id": "GO-2026-5932",
            "scanner": "govulncheck",
            "ecosystem": "Go",
            "package": "golang.org/x/crypto",
            "presence": "module",
            "reachability_evidence": {
                "scanner": "govulncheck",
                "scan_mode": "binary",
                "scan_level": "symbol",
            },
        }
        unreachable = self.evaluate([self.finding("UNKNOWN", reachable=False, **base)])
        self.assertEqual("PASS", unreachable["final_result"])
        self.assertEqual("REPORT", unreachable["policy_decisions"][0]["decision"])
        reachable = self.evaluate(
            [
                self.finding(
                    "UNKNOWN",
                    reachable=True,
                    presence="symbol",
                    **{k: v for k, v in base.items() if k != "presence"},
                )
            ]
        )
        self.assertEqual("BLOCK", reachable["final_result"])
        unknown = self.evaluate([self.finding("UNKNOWN", reachable=None, **base)])
        self.assertEqual("BLOCK", unknown["final_result"])

    def test_aliases_deduplicate_multi_scanner_observations(self):
        trivy = self.finding(
            "HIGH",
            finding_id="CVE-2026-3000",
            aliases=["GO-2026-3000", "GO-2026-3000"],
            ecosystem="Go",
            package="example.org/vulnerable",
        )
        govulncheck = self.finding(
            "UNKNOWN",
            finding_id="GO-2026-3000",
            aliases=["CVE-2026-3000"],
            scanner="govulncheck",
            ecosystem="Go",
            package="example.org/vulnerable",
            reachable=True,
            presence="symbol",
        )
        self.datasets(scores={"CVE-2026-3000": 0.1})
        evidence = self.evaluate([trivy, govulncheck])
        self.assertEqual(1, len(evidence["findings"]))
        self.assertEqual(2, len(evidence["observations"]))
        self.assertEqual(
            ["CVE-2026-3000", "GO-2026-3000"],
            evidence["findings"][0]["identifiers"],
        )

    def test_multiple_binary_targets_preserve_observations_and_any_reachability(self):
        base = {
            "finding_id": "GO-2026-3001",
            "scanner": "govulncheck",
            "ecosystem": "Go",
            "package": "example.org/vulnerable",
            "reachability_evidence": {
                "scanner": "govulncheck",
                "scan_mode": "binary",
                "scan_level": "symbol",
            },
        }
        manager = self.finding(
            "UNKNOWN",
            reachable=False,
            presence="module",
            target="manager",
            **base,
        )
        adapter = self.finding(
            "UNKNOWN",
            reachable=True,
            presence="symbol",
            target="pipeline-adapter",
            **base,
        )
        evidence = self.evaluate(
            [manager, adapter],
            scanner_runs=[{"name": "govulncheck", "status": "PASS"}],
            required_scanners=["govulncheck"],
        )
        self.assertEqual(2, len(evidence["observations"]))
        self.assertEqual(1, len(evidence["findings"]))
        self.assertTrue(evidence["findings"][0]["reachable"])
        self.assertEqual("BLOCK", evidence["final_result"])

    def test_conflicting_scanner_data_and_invalid_alias_fail_closed(self):
        first = self.finding(
            "HIGH",
            finding_id="CVE-2026-4000",
            aliases=["GO-2026-4000"],
            ecosystem="Go",
            package="example.org/vulnerable",
        )
        second = self.finding(
            "MEDIUM",
            finding_id="GO-2026-4000",
            aliases=["CVE-2026-4000"],
            scanner="govulncheck",
            ecosystem="Go",
            package="example.org/vulnerable",
        )
        self.datasets(scores={"CVE-2026-4000": 0.1})
        conflict = self.evaluate([first, second])
        self.assertEqual("BLOCK", conflict["final_result"])
        self.assertTrue(
            any("conflicting scanner severity" in item for item in conflict["reasons"])
        )
        invalid_alias = self.evaluate(
            [self.finding("LOW", aliases=["arbitrary identifier"])]
        )
        self.assertEqual("BLOCK", invalid_alias["final_result"])
        self.assertTrue(
            any("invalid alias" in item for item in invalid_alias["reasons"])
        )

    def test_govulncheck_binary_evidence_distinguishes_presence_and_reachability(self):
        events = [
            {
                "config": {
                    "scanner_name": "govulncheck",
                    "scanner_version": "v1.8.0",
                    "scan_mode": "binary",
                    "scan_level": "symbol",
                    "db": "https://vuln.go.dev",
                    "db_last_modified": "2026-09-16T18:00:43Z",
                }
            },
            {
                "osv": {
                    "id": "GO-2026-5932",
                    "aliases": [],
                    "published": "2026-07-07T22:15:29Z",
                    "affected": [
                        {
                            "package": {
                                "name": "golang.org/x/crypto",
                                "ecosystem": "Go",
                            }
                        }
                    ],
                }
            },
            {
                "finding": {
                    "osv": "GO-2026-5932",
                    "trace": [{"module": "golang.org/x/crypto", "version": "v0.56.0"}],
                }
            },
        ]
        findings, config = SECURITY.govulncheck_findings(
            events,
            artifact="kratix@sha256:" + "d" * 64,
            scope="oci_images",
        )
        self.assertEqual("binary", config["scan_mode"])
        self.assertEqual("module", findings[0]["presence"])
        self.assertFalse(findings[0]["reachable"])

    def test_sbom_artifact_and_exact_sha_mismatches_block(self):
        evidence = self.evaluate(
            [],
            sbom_artifact_digest="sha256:" + "e" * 64,
            source_head_sha="f" * 40,
        )
        self.assertEqual("BLOCK", evidence["final_result"])
        self.assertIn("SBOM/artifact mismatch", evidence["reasons"])
        self.assertIn("exact-SHA mismatch", evidence["reasons"])

    def test_spdx_sbom_binds_only_the_described_root_artifact(self):
        artifact_digest = "sha256:" + "d" * 64
        other_digest = "sha256:" + "e" * 64
        base = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "product-image",
            "documentNamespace": "https://example.test/spdx/product",
            "documentDescribes": ["SPDXRef-RootPackage"],
            "packages": [
                {
                    "SPDXID": "SPDXRef-RootPackage",
                    "name": "product",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": f"pkg:oci/product@{artifact_digest}",
                        }
                    ],
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sbom.spdx.json"
            path.write_text(json.dumps(base), encoding="utf-8")
            _, described = SECURITY.sbom_identity(path, artifact_digest)
            self.assertEqual(artifact_digest, described)

            wrong = json.loads(json.dumps(base))
            wrong["packages"][0]["externalRefs"][0]["referenceLocator"] = (
                f"pkg:oci/product@{other_digest}?note={artifact_digest}"
            )
            path.write_text(json.dumps(wrong), encoding="utf-8")
            _, described = SECURITY.sbom_identity(path, artifact_digest)
            self.assertIsNone(described)

            path.write_text("not-json", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "malformed"):
                SECURITY.sbom_identity(path, artifact_digest)

    def test_cvss_floor_and_deadlines_are_canonical(self):
        finding = self.finding(
            "LOW", cvss=9.1, detected_at=(NOW - timedelta(hours=73)).isoformat()
        )
        self.datasets(scores={finding["finding_id"]: 0.1})
        evidence = self.evaluate([finding])
        self.assertEqual("CRITICAL", evidence["policy_decisions"][0]["severity"])
        self.assertTrue(evidence["policy_decisions"][0]["remediation_overdue"])
        self.assertEqual(
            72, POLICY["vulnerability_policy"]["critical"]["remediation_deadline_hours"]
        )
        self.assertEqual(
            7, POLICY["vulnerability_policy"]["high"]["remediation_deadline_days"]
        )
        self.assertEqual(
            30, POLICY["vulnerability_policy"]["medium"]["remediation_deadline_days"]
        )

    def test_dataset_sync_records_official_provenance_and_checksums(self):
        kev_raw = json.dumps(
            {
                "catalogVersion": "test",
                "dateReleased": NOW.isoformat(),
                "vulnerabilities": [],
            }
        ).encode()
        epss_raw = gzip.compress(
            b"#model_version:test,score_date:2026-09-24T00:00:00+00:00\ncve,epss,percentile\n"
        )
        with mock.patch.object(
            SECURITY, "urlopen", side_effect=[io.BytesIO(kev_raw), io.BytesIO(epss_raw)]
        ):
            manifest_path = SECURITY.sync_datasets(POLICY, self.dataset_dir, now=NOW)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(
            POLICY["risk_datasets"]["kev"]["source"],
            manifest["datasets"]["kev"]["source"],
        )
        self.assertEqual(
            hashlib.sha256(epss_raw).hexdigest(), manifest["datasets"]["epss"]["sha256"]
        )
        state = SECURITY._read_dataset_manifest(POLICY, self.root, NOW)
        self.assertEqual(set(), state["kev_ids"])


if __name__ == "__main__":
    unittest.main()
