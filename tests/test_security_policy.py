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
            "severity": severity,
            "cvss": values.pop("cvss", None),
            "fix_available": values.pop("fix_available", False),
            "reachable": values.pop("reachable", None),
            "artifact": "product@sha256:" + "d" * 64,
            "scope": "oci_images",
            "scanner": "trivy",
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
        return SECURITY.evaluate(
            self.payload(findings, **values), POLICY, self.root, now=NOW
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
            "approval": f"/owner-authorization approve scope=cve-exception:{finding['finding_id']} sha={'b' * 40}",
            "exact_sha": "b" * 40,
            "environment": "release",
            "mitigation": "network isolation",
            "remediation_issue": "#999",
        }
        item.update(values)
        return item

    def test_severity_decisions_fix_and_unfixed(self):
        cases = (
            (self.finding("CRITICAL", fix_available=True), "BLOCK"),
            (self.finding("HIGH", fix_available=True), "BLOCK"),
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
        evidence = self.evaluate([finding], exceptions=[self.exception(finding)])
        self.assertEqual("PASS", evidence["final_result"])
        self.assertEqual(
            "ACCEPTED_TEMPORARILY", evidence["policy_decisions"][0]["decision"]
        )
        self.assertEqual(1, len(evidence["exceptions_used"]))

    def test_exception_validation_is_fail_closed(self):
        finding = self.finding("HIGH")
        self.datasets(scores={finding["finding_id"]: 0.1})
        invalid = (
            ({"owner": ""}, "missing owner"),
            ({"expires_at": ""}, "missing expires_at"),
            ({"expires_at": (NOW - timedelta(minutes=1)).isoformat()}, "expired"),
            ({"scope": "repository_filesystem"}, "wrong CVE scope"),
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

    def test_malformed_trivy_output_is_rejected(self):
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
        conflict = self.evaluate([finding, {**finding, "fix_available": True}])
        self.assertEqual("BLOCK", conflict["final_result"])
        self.assertTrue(
            any("conflicting duplicate" in reason for reason in conflict["reasons"])
        )

    def test_sbom_artifact_and_exact_sha_mismatches_block(self):
        evidence = self.evaluate(
            [],
            sbom_artifact_digest="sha256:" + "e" * 64,
            source_head_sha="f" * 40,
        )
        self.assertEqual("BLOCK", evidence["final_result"])
        self.assertIn("SBOM/artifact mismatch", evidence["reasons"])
        self.assertIn("exact-SHA mismatch", evidence["reasons"])

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
