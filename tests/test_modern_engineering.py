import copy
import importlib.util
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "modern_engineering", ROOT / "scripts/modern_engineering.py"
)
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)
NOW = datetime(2026, 9, 24, 12, 0, tzinfo=timezone.utc)


class ModernEngineeringTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lock, cls.roadmap, cls.qualification = MOD._qce_contracts(ROOT)
        cls.policy = MOD.load_metrics_policy(ROOT)

    def test_qce_has_exactly_nine_sectors_and_data_driven_is_transverse(self):
        qce = self.lock["developer_platform"]["quality_cloud_engineering"]
        self.assertEqual(9, qce["sector_count"])
        self.assertEqual(9, len(qce["sectors"]))
        data = qce["cross_cutting"]["data_driven"]
        self.assertTrue(data["applies_to_all_sectors"])
        self.assertEqual("measuring_engineering", data["measurement_owner"])
        self.assertEqual(
            [
                "observe",
                "measure",
                "detect",
                "hypothesis",
                "small-experiment",
                "measure-outcome",
                "keep-rollback-improve",
                "standardise",
            ],
            data["decision_model"],
        )

    def test_ai_agent_cannot_satisfy_merge_review_or_gate_authority(self):
        ai = self.lock["developer_platform"]["quality_cloud_engineering"][
            "cross_cutting"
        ]["ai_agent"]
        self.assertFalse(ai["authoritative_gate"])
        self.assertFalse(ai["may_bypass_required_gates"])
        self.assertFalse(ai["may_merge"])
        self.assertFalse(ai["may_deploy_production_directly"])
        self.assertEqual("required", ai["human_accountability"])
        review = MOD.yaml_file(ROOT / "config/contracts/review-policy.yaml")[
            "pull_request_review"
        ]["ai_reviewer"]
        self.assertFalse(review["may_approve"])
        self.assertFalse(review["may_merge"])

    def test_qce_rejects_tenth_sector_missing_fields_and_missing_gate(self):
        cases = []
        tenth = copy.deepcopy(self.lock)
        tenth["developer_platform"]["quality_cloud_engineering"]["sectors"]["tenth"] = {
            "owner": "x",
            "input": "x",
            "output": "x",
            "evidence": "x",
        }
        cases.append((tenth, self.roadmap, "exactly nine"))
        missing = copy.deepcopy(self.lock)
        del missing["developer_platform"]["quality_cloud_engineering"]["sectors"][
            "continuous_testing"
        ]["owner"]
        cases.append((missing, self.roadmap, "lacks owner/input/output/evidence"))
        roadmap = copy.deepcopy(self.roadmap)
        roadmap["qce_traceability"]["capabilities"]["continuous_testing"][0][
            "gates"
        ] = ["unknown"]
        cases.append((self.lock, roadmap, "unknown gate"))
        invalid_proof = copy.deepcopy(self.roadmap)
        invalid_proof["qce_traceability"]["capabilities"]["golden_path"][1]["proof"] = {
            "kind": "manual-claim"
        }
        cases.append((self.lock, invalid_proof, "invalid proof contract"))
        for lock, roadmap_value, expected in cases:
            with (
                self.subTest(expected=expected),
                self.assertRaisesRegex(ValueError, expected),
            ):
                MOD.validate_qce_traceability(
                    lock, roadmap_value, self.qualification, ROOT
                )

    def test_qce_state_machine_is_closed_and_manual_proven_is_rejected(self):
        self.assertEqual(
            set(MOD.QCE_STATUSES), set(self.roadmap["qce_traceability"]["statuses"])
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "metadata.json"
            path.write_text(json.dumps({"status": "PROVEN"}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "cannot be manually declared"):
                MOD._github_metadata(
                    path,
                    list(
                        self.lock["developer_platform"]["quality_cloud_engineering"][
                            "sectors"
                        ]
                    ),
                )

    def test_qce_unknown_label_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "metadata.json"
            path.write_text(
                json.dumps({"issues": [{"number": 1, "labels": ["qce:not-a-sector"]}]}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "unknown QCE label"):
                MOD._github_metadata(
                    path,
                    list(
                        self.lock["developer_platform"]["quality_cloud_engineering"][
                            "sectors"
                        ]
                    ),
                )

    def test_proven_requires_fresh_exact_sha_gate_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            evidence = {
                "status": "PASS",
                "exact_commit_evidence": True,
                "head_sha": "a" * 40,
                "head_tree_sha": "b" * 40,
                "created_at_epoch": NOW.timestamp(),
                "gates": [{"gate": "governance", "status": "PASS"}],
            }
            path.write_text(json.dumps(evidence), encoding="utf-8")
            gates, error = MOD._qualification_evidence(
                path,
                "a" * 40,
                "b" * 40,
                86400,
                NOW,
                canonical_validator=lambda candidate: candidate == path,
            )
            self.assertIsNone(error)
            self.assertEqual("PASS", gates["governance"])
            values, problem = MOD._qualification_evidence(
                path, "a" * 40, "b" * 40, 86400, NOW
            )
            self.assertEqual({}, values)
            self.assertIn("canonical exact-SHA validation", problem)

    def test_minimal_hand_authored_qualification_cannot_prove_qce(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "minimal.json"
            path.write_text(
                json.dumps(
                    {
                        "status": "PASS",
                        "exact_commit_evidence": True,
                        "head_sha": "a" * 40,
                        "head_tree_sha": "b" * 40,
                        "created_at_epoch": NOW.timestamp(),
                        "gates": [{"gate": "governance", "status": "PASS"}],
                    }
                ),
                encoding="utf-8",
            )
            gates, problem = MOD._qualification_evidence(
                path, "a" * 40, "b" * 40, 86400, NOW
            )
            self.assertEqual({}, gates)
            self.assertIn("canonical exact-SHA validation", problem)

    def test_runtime_proof_requires_execution_exact_sha_freshness_and_capability(self):
        contract = self.roadmap["qce_traceability"]["runtime_evidence_contract"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.json"
            evidence = {
                "schema_version": 1,
                "status": "PASS",
                "exact_commit_evidence": True,
                "runtime_execution": True,
                "head_sha": "a" * 40,
                "head_tree_sha": "b" * 40,
                "created_at_epoch": NOW.timestamp(),
                "capabilities": ["platform-self-service"],
                "environment": "preprod",
                "runtime_identity": {"kind": "rke2-cluster", "id": "preprod-01"},
                "outcome": "PASS",
            }
            path.write_text(json.dumps(evidence), encoding="utf-8")
            proven, problem = MOD._runtime_capability_evidence(
                path,
                "platform-self-service",
                "a" * 40,
                "b" * 40,
                86400,
                NOW,
                contract,
            )
            self.assertTrue(proven)
            self.assertIsNone(problem)
            for mutation, expected in (
                ({"runtime_execution": False}, "not an exact execution PASS"),
                ({"head_sha": "c" * 40}, "wrong SHA or tree"),
                (
                    {"created_at_epoch": (NOW - timedelta(days=2)).timestamp()},
                    "stale or future-dated",
                ),
                ({"created_at_epoch": float("nan")}, "timestamp is invalid"),
                ({"capabilities": ["another-capability"]}, "does not claim"),
                ({"environment": "development"}, "invalid environment"),
                ({"runtime_identity": {"kind": "rke2-cluster"}}, "identity is invalid"),
                ({"outcome": "CLAIMED"}, "not an exact execution PASS"),
            ):
                with self.subTest(expected=expected):
                    path.write_text(
                        json.dumps({**evidence, **mutation}), encoding="utf-8"
                    )
                    proven, problem = MOD._runtime_capability_evidence(
                        path,
                        "platform-self-service",
                        "a" * 40,
                        "b" * 40,
                        86400,
                        NOW,
                        contract,
                    )
                    self.assertFalse(proven)
                    self.assertIn(expected, problem)

    def test_runtime_only_capability_can_become_proven(self):
        with mock.patch.object(
            MOD, "_runtime_capability_evidence", return_value=(True, None)
        ):
            payload = MOD.qce_status(ROOT, sector="developer_hub", now=NOW)
        capability = payload["sectors"][0]["capabilities"][0]
        self.assertEqual("PROVEN", capability["status"])
        self.assertEqual("PROVEN", payload["sectors"][0]["status"])

    def test_qce_projection_maps_milestones_issues_gates_and_is_deterministic(self):
        first = MOD.qce_status(ROOT, now=NOW)
        second = MOD.qce_status(ROOT, now=NOW)
        self.assertEqual(
            json.dumps(first, sort_keys=True, separators=(",", ":")),
            json.dumps(second, sort_keys=True, separators=(",", ":")),
        )
        self.assertEqual(9, len(first["sectors"]))
        continuous = next(
            item for item in first["sectors"] if item["sector"] == "continuous_testing"
        )
        self.assertIn("governance", continuous["gates"])
        self.assertIn(13, continuous["issues"])
        if continuous["status"] == "PROVEN":
            self.assertEqual("fresh-exact-sha", first["evidence_state"])
            self.assertTrue(continuous["evidence"])
        else:
            self.assertIn(continuous["status"], {"PARTIAL", "IMPLEMENTED"})
        monitoring = next(
            item
            for item in first["sectors"]
            if item["sector"] == "monitoring_observability"
        )
        self.assertIn(monitoring["status"], {"PARTIAL", "CONTRACTED"})
        for sector_name in ("automation", "golden_path"):
            guarded = next(
                item for item in first["sectors"] if item["sector"] == sector_name
            )
            self.assertEqual("BLOCKED", guarded["status"])
            self.assertTrue(
                any(
                    "kratix-platform.yaml#security_qualification.final_result=BLOCK"
                    in blocker
                    for blocker in guarded["blockers"]
                )
            )
        golden = next(
            item for item in first["sectors"] if item["sector"] == "golden_path"
        )
        self_service = next(
            item
            for item in golden["capabilities"]
            if item["id"] == "platform-self-service"
        )
        self.assertEqual("BLOCKED", self_service["status"])
        self.assertEqual([], self_service["evidence"])

    def event(self, event_id, kind, timestamp, **values):
        return {"event_id": event_id, "type": kind, "timestamp": timestamp, **values}

    def test_dora_calculations_are_order_independent(self):
        events = [
            self.event(
                "5", "deployment_reworked", "2026-09-05T00:00:00Z", deployment_id="d2"
            ),
            self.event("1", "change_committed", "2026-09-01T00:00:00Z", change_id="c1"),
            self.event(
                "4", "deployment_recovered", "2026-09-04T02:00:00Z", deployment_id="d2"
            ),
            self.event(
                "2",
                "deployment_succeeded",
                "2026-09-02T00:00:00Z",
                deployment_id="d1",
                change_id="c1",
            ),
            self.event(
                "3", "deployment_failed", "2026-09-04T00:00:00Z", deployment_id="d2"
            ),
        ]
        metrics = MOD.calculate_dora(events, self.policy)
        self.assertEqual(86400, metrics["change_lead_time"]["median_seconds"])
        self.assertEqual(
            7200, metrics["failed_deployment_recovery_time"]["median_seconds"]
        )
        self.assertEqual(50, metrics["change_fail_rate"]["percent"])
        self.assertEqual(50, metrics["deployment_rework_rate"]["percent"])
        self.assertAlmostEqual(
            1 / 30, metrics["deployment_frequency"]["deployments_per_day"]
        )

    def test_dora_zero_events_missing_and_invalid_events(self):
        empty = MOD.calculate_dora([], self.policy)
        self.assertEqual("MISSING", empty["deployment_frequency"]["status"])
        bad = (
            ([{"event_id": "1", "type": "x"}], "timestamp is missing"),
            ([self.event("1", "x", "invalid")], "timestamp is invalid"),
            (
                [
                    self.event("1", "x", "2026-09-01T00:00:00Z"),
                    self.event("1", "x", "2026-09-02T00:00:00Z"),
                ],
                "duplicate",
            ),
            (
                [
                    self.event(
                        "1", "change_committed", "2026-09-02T00:00:00Z", change_id="c"
                    ),
                    self.event(
                        "2",
                        "deployment_succeeded",
                        "2026-09-01T00:00:00Z",
                        deployment_id="d",
                        change_id="c",
                    ),
                ],
                "precedes",
            ),
        )
        for events, expected in bad:
            with (
                self.subTest(expected=expected),
                self.assertRaisesRegex(ValueError, expected),
            ):
                MOD.calculate_dora(events, self.policy)

    def test_dora_excludes_events_outside_declared_window(self):
        metrics = MOD.calculate_dora(
            [
                self.event(
                    "old-success",
                    "deployment_succeeded",
                    "2026-07-01T00:00:00Z",
                    deployment_id="old",
                ),
                self.event(
                    "new-success",
                    "deployment_succeeded",
                    "2026-09-24T00:00:00Z",
                    deployment_id="new",
                ),
                self.event(
                    "old-failure",
                    "deployment_failed",
                    "2026-07-02T00:00:00Z",
                    deployment_id="old-failed",
                ),
            ],
            self.policy,
            window_end="2026-09-24T00:00:00Z",
        )
        self.assertEqual("2026-08-25T00:00:00Z", metrics["window_start"])
        self.assertEqual("2026-09-24T00:00:00Z", metrics["window_end"])
        self.assertEqual(1, metrics["event_count"])
        self.assertEqual(1, metrics["deployment_frequency"]["successful_deployments"])
        self.assertEqual(0, metrics["change_fail_rate"]["failed"])

    def test_slo_error_budget_and_burn_boundaries(self):
        slo_policy = MOD.yaml_file(ROOT / "config/contracts/service-slo.yaml")
        MOD.validate_service_slo_policy(
            slo_policy,
            self.lock["business"]["services"],
        )
        healthy = MOD.calculate_slo(999, 1000, 99.0)
        self.assertEqual("HEALTHY", healthy["budget_state"])
        high_burn = MOD.calculate_slo(
            999,
            1000,
            99.0,
            slo_policy=slo_policy,
            window_measurements={
                "fast": {
                    "short": {"good_events": 85, "total_events": 100},
                    "long": {"good_events": 850, "total_events": 1000},
                }
            },
        )
        self.assertEqual("HIGH_BURN", high_burn["budget_state"])
        self.assertEqual(["fast"], high_burn["high_burn_windows"])
        exhausted = MOD.calculate_slo(989, 1000, 99.0)
        self.assertEqual("EXHAUSTED", exhausted["budget_state"])
        self.assertEqual(
            "RELIABILITY_WORK_AND_RELEASE_RESTRICTION", exhausted["release_decision"]
        )
        self.assertEqual("MISSING", MOD.calculate_slo(None, None, 99.0)["status"])
        self.assertEqual("MISSING", MOD.calculate_slo(0, 0, 99.0)["status"])

    def test_ai_outcomes_and_devex_anti_patterns(self):
        self.assertTrue(MOD.outcome_delta(10, 8, "decrease")["improved"])
        self.assertTrue(MOD.outcome_delta(10, 12, "increase")["improved"])
        with self.assertRaisesRegex(ValueError, "forbidden individual"):
            MOD.reject_forbidden_metrics(
                ["cycle_time_impact", "number_of_ai_prompts"], self.policy
            )

    def test_experiment_evaluation_requires_exact_evidence(self):
        experiment = {
            "experiment_id": "faster-qce-feedback",
            "owner": "developer-experience",
            "hypothesis": "affected execution reduces feedback time",
            "baseline_evidence": [".context/evidence/base.json"],
            "change_sha": "a" * 40,
            "metric": "test_feedback_latency",
            "expected_direction": "decrease",
            "measurement_window": "30-days",
            "result": {"baseline": 100, "measured": 70},
            "decision": "PENDING",
            "evidence": [".context/evidence/result.json"],
        }
        result = MOD.evaluate_experiment(experiment, self.policy)
        self.assertEqual("KEEP", result["decision"])
        self.assertTrue(result["comparison"]["improved"])
        invalid = dict(experiment)
        invalid["change_sha"] = "HEAD"
        with self.assertRaisesRegex(ValueError, "exact"):
            MOD.validate_experiment(invalid, self.policy)
        for invalid_result in (
            {"baseline": True, "measured": 70},
            {"baseline": 100, "measured": float("nan")},
            {"baseline": float("inf"), "measured": 70},
        ):
            with self.subTest(result=invalid_result), self.assertRaisesRegex(
                TypeError, "numeric baseline"
            ):
                MOD.evaluate_experiment(
                    {**experiment, "result": invalid_result}, self.policy
                )


if __name__ == "__main__":
    unittest.main()
