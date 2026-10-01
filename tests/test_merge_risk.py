"""Deterministic four-level merge-risk policy tests."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import yaml


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("merge_risk", ROOT / "scripts/merge_risk.py")
MERGE_RISK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MERGE_RISK)
BASE_SHA = "a" * 40
HEAD_SHA = "b" * 40


class MergeRiskPolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        contract = yaml.safe_load(
            (ROOT / "config/contracts/review-policy.yaml").read_text(encoding="utf-8")
        )
        cls.policy = contract["repository_delivery"]["pr_loop"]["risk_classification"]
        cls.owner_boundary = contract["repository_delivery"]["pr_loop"]["owner_boundary"]

    def classify(self, changes):
        paths = sorted(changes)
        return MERGE_RISK.evaluate_merge_risk(
            self.policy,
            base_sha=BASE_SHA,
            head_sha=HEAD_SHA,
            pr_number=171,
            changed_files=paths,
            file_changes=changes,
        )

    def test_policy_is_closed_world_and_has_four_classes(self):
        self.assertTrue(
            MERGE_RISK.merge_risk_policy_is_valid(self.policy, self.owner_boundary)
        )
        self.assertEqual(
            ["LOW_RISK", "SENSITIVE", "PRIVILEGED", "PRODUCTION"],
            self.policy["classifications"],
        )
        mutated = copy.deepcopy(self.policy)
        mutated["production"]["capabilities"]["production-inventory"]["paths"].remove(
            "config/infrastructure/prod-inventory.yaml"
        )
        self.assertFalse(
            MERGE_RISK.merge_risk_policy_is_valid(mutated, self.owner_boundary)
        )

    def test_paths_derive_each_level_and_requirements(self):
        cases = (
            ("docs/README.md", "LOW_RISK", "not-required-by-policy"),
            (
                "config/contracts/security-scan-policy.yaml",
                "SENSITIVE",
                "explicit-repository-owner",
            ),
            ("scripts/windows/LabNativeBoot.ps1", "PRIVILEGED", "explicit-repository-owner"),
            (
                "config/infrastructure/prod-inventory.yaml",
                "PRODUCTION",
                "explicit-repository-owner",
            ),
        )
        for path, level, owner in cases:
            with self.subTest(path=path):
                result = self.classify({path: "changed"})
                self.assertEqual(level, result["classification"])
                self.assertEqual(owner, result["requirements"]["owner_authorization"])
                self.assertEqual(
                    self.policy["class_requirements"][level], result["requirements"]
                )
                self.assertTrue(result["analysis_complete"])

    def test_content_signals_and_highest_class_win(self):
        privileged = self.classify(
            {"scripts/host_control.py": "subprocess.run(['bcdedit'])"}
        )
        self.assertEqual("PRIVILEGED", privileged["classification"])
        self.assertEqual("capture-restore-verify", privileged["requirements"]["recovery"])
        credentials = self.classify({"scripts/identity.py": "rotate credentials"})
        self.assertEqual("PRIVILEGED", credentials["classification"])
        production = self.classify(
            {"scripts/deploy.py": "perform production rollout"}
        )
        self.assertEqual("PRODUCTION", production["classification"])
        self.assertEqual(
            "production-runtime-before-mutation",
            production["requirements"]["runtime_evidence"],
        )
        mixed = self.classify(
            {
                "scripts/windows/LabNativeBoot.ps1": "changed",
                "config/infrastructure/prod-inventory.yaml": "changed",
            }
        )
        self.assertEqual("PRODUCTION", mixed["classification"])

    def test_ambiguous_input_remains_sensitive_and_owner_gated(self):
        result = MERGE_RISK.evaluate_merge_risk(
            self.policy,
            base_sha="invalid",
            head_sha=HEAD_SHA,
            pr_number=171,
            changed_files=["docs/README.md"],
            file_changes={"docs/README.md": "changed"},
        )
        self.assertEqual("SENSITIVE", result["classification"])
        self.assertFalse(result["analysis_complete"])
        self.assertEqual(
            "explicit-repository-owner",
            result["requirements"]["owner_authorization"],
        )


    def test_changed_line_records_keep_old_and_new_identity(self):
        patch = (
            "diff --git a/scripts/observer.py b/scripts/observer.py\n"
            "--- a/scripts/observer.py\n"
            "+++ b/scripts/observer.py\n"
            "@@ -4 +4 @@\n"
            "-old production credentials\n"
            "+new production credentials\n"
        )
        records = MERGE_RISK._changed_line_records(patch)
        self.assertEqual(
            [
                {"side": "-", "line": 4, "text": "old production credentials"},
                {"side": "+", "line": 4, "text": "new production credentials"},
            ],
            records,
        )
        self.assertIsNone(
            MERGE_RISK._changed_line_records(
                "@@ -4 +4 @@\n-old production credentials\n"
            )
        )

    def test_content_inventory_binds_every_high_rule_to_line_and_side(self):
        path = "scripts/observer.py"
        records = [
            {"side": "-", "line": 4, "text": "old production credentials"},
            {"side": "+", "line": 4, "text": "new production credentials"},
        ]
        changes = {path: "\n".join(item["text"] for item in records)}
        findings, unmapped, complete = MERGE_RISK._content_findings(
            self.policy, [path], changes, {path: records}
        )
        self.assertTrue(complete)
        self.assertFalse(unmapped)
        self.assertEqual(4, len(findings), findings)
        self.assertEqual(
            {"PRODUCTION", "PRIVILEGED"}, {item["tier"] for item in findings}
        )
        self.assertEqual({"+", "-"}, {item["side"] for item in findings})
        self.assertEqual(4, len({item["id"] for item in findings}))
        self.assertEqual(sorted(item["id"] for item in findings),
                         [item["id"] for item in findings])
        for item in findings:
            self.assertEqual(4, item["line"])
            source = next(line["text"] for line in records if line["side"] == item["side"])
            self.assertEqual(
                "sha256:" + __import__("hashlib").sha256(source.encode()).hexdigest(),
                item["line_sha256"],
            )
            identity = {key: value for key, value in item.items() if key != "id"}
            self.assertEqual(MERGE_RISK._canonical_sha256(identity), item["id"])

    def test_content_inventory_refuses_unsupported_or_oversized_context(self):
        path = "scripts/observer.py"
        records = [{"side": "+", "line": index + 1, "text": "VirtualBox"}
                   for index in range(MERGE_RISK.MAX_CONTENT_FINDINGS + 1)]
        changes = {path: "\n".join(item["text"] for item in records)}
        findings, _unmapped, complete = MERGE_RISK._content_findings(
            self.policy, [path], changes, {path: records}
        )
        self.assertFalse(complete)
        self.assertEqual([], findings)
        findings, _unmapped, complete = MERGE_RISK._content_findings(
            self.policy, [path], changes,
            {path: [{"side": "+", "line": 1, "text": "VirtualBox"}]},
        )
        self.assertFalse(complete)
        self.assertEqual([], findings)

    def test_repeated_matches_hash_the_line_and_identity_once(self):
        path = "scripts/observer.py"
        line = "# " + "VirtualBox " * 4000
        records = {path: [{"side": "+", "line": 1, "text": line}]}
        line_bytes = line.encode("utf-8")
        original_sha256 = hashlib.sha256
        original_canonical = MERGE_RISK._canonical_sha256
        line_hashes = 0
        identities = 0

        def counted_sha256(data, *args, **kwargs):
            nonlocal line_hashes
            if data == line_bytes:
                line_hashes += 1
            return original_sha256(data, *args, **kwargs)

        def counted_canonical(value):
            nonlocal identities
            identities += 1
            return original_canonical(value)

        with patch.object(MERGE_RISK.hashlib, "sha256", side_effect=counted_sha256), (
            patch.object(MERGE_RISK, "_canonical_sha256", side_effect=counted_canonical)
        ):
            findings, unmapped, complete = MERGE_RISK._content_findings(
                self.policy, [path], {path: line}, records
            )
        self.assertTrue(complete)
        self.assertFalse(unmapped)
        self.assertEqual(1, len(findings))
        self.assertEqual(44002, len(line_bytes))
        self.assertEqual(1, line_hashes)
        self.assertEqual(1, identities)

    def test_line_hash_is_reused_for_distinct_findings(self):
        path = "scripts/observer.py"
        line = "production credentials"
        records = {path: [{"side": "+", "line": 1, "text": line}]}
        original_sha256 = hashlib.sha256
        line_hashes = 0

        def counted_sha256(data, *args, **kwargs):
            nonlocal line_hashes
            if data == line.encode("utf-8"):
                line_hashes += 1
            return original_sha256(data, *args, **kwargs)

        with patch.object(MERGE_RISK.hashlib, "sha256", side_effect=counted_sha256):
            findings, unmapped, complete = MERGE_RISK._content_findings(
                self.policy, [path], {path: line}, records
            )
        self.assertTrue(complete)
        self.assertFalse(unmapped)
        self.assertEqual(2, len(findings))
        self.assertEqual(1, line_hashes)

    def test_match_budget_is_global_across_files_and_rules(self):
        paths = ["scripts/host_probe.py", "scripts/identity_probe.py"]
        changes = {
            paths[0]: "VirtualBox VirtualBox",
            paths[1]: "credentials credentials",
        }
        records = {
            path: [{"side": "+", "line": 1, "text": changes[path]}]
            for path in paths
        }
        original_finditer = MERGE_RISK.re.finditer
        matches_consumed = 0

        def counted_finditer(*args, **kwargs):
            nonlocal matches_consumed
            for match in original_finditer(*args, **kwargs):
                matches_consumed += 1
                yield match

        with patch.object(MERGE_RISK, "MAX_CONTENT_MATCHES", 3), (
            patch.object(MERGE_RISK.re, "finditer", side_effect=counted_finditer)
        ):
            findings, _unmapped, complete = MERGE_RISK._content_findings(
                self.policy, paths, changes, records
            )
        self.assertFalse(complete)
        self.assertEqual([], findings)
        self.assertEqual(4, matches_consumed)

    def test_match_budget_exhaustion_keeps_the_original_risk(self):
        path = "scripts/observer.py"
        budget = MERGE_RISK.MAX_CONTENT_MATCHES
        line = "# " + "VirtualBox " * (budget + 1)
        records = {path: [{"side": "+", "line": 1, "text": line}]}
        changes = {path: line}
        with patch.object(MERGE_RISK, "MAX_CONTENT_MATCHES", budget + 1):
            complete_findings, unmapped, complete = MERGE_RISK._content_findings(
                self.policy, [path], changes, records
            )
            self.assertTrue(complete)
            self.assertFalse(unmapped)
            self.assertEqual(1, len(complete_findings))
            assessment = {
                "schema_version": 1, "pr": 183,
                "base_sha": BASE_SHA, "head_sha": HEAD_SHA,
                "findings_sha256": MERGE_RISK._canonical_sha256(complete_findings),
                "dispositions": [{
                    "finding_id": complete_findings[0]["id"],
                    "kind": "metadata",
                    "rationale": "Static fixture label only.",
                    "effect_trace": "Literal is not consumed by host commands.",
                }],
            }
            reviewed = MERGE_RISK.evaluate_merge_risk(
                self.policy, base_sha=BASE_SHA, head_sha=HEAD_SHA,
                pr_number=183, changed_files=[path], file_changes=changes,
                changed_lines=records, assessment=assessment,
            )
            self.assertEqual("SENSITIVE", reviewed["classification"])

        original_finditer = MERGE_RISK.re.finditer
        matches_consumed = 0

        def counted_finditer(*args, **kwargs):
            nonlocal matches_consumed
            for match in original_finditer(*args, **kwargs):
                matches_consumed += 1
                yield match

        with patch.object(MERGE_RISK.re, "finditer", side_effect=counted_finditer):
            findings, unmapped, complete = MERGE_RISK._content_findings(
                self.policy, [path], changes, records
            )
        self.assertFalse(complete)
        self.assertEqual([], findings)
        self.assertFalse(unmapped)
        self.assertEqual(budget + 1, matches_consumed)

        baseline = MERGE_RISK.evaluate_merge_risk(
            self.policy, base_sha=BASE_SHA, head_sha=HEAD_SHA,
            pr_number=183, changed_files=[path], file_changes=changes,
            changed_lines=records,
        )
        attempted_downgrade = MERGE_RISK.evaluate_merge_risk(
            self.policy, base_sha=BASE_SHA, head_sha=HEAD_SHA,
            pr_number=183, changed_files=[path], file_changes=changes,
            changed_lines=records, assessment=assessment,
        )
        self.assertEqual("PRIVILEGED", baseline["classification"])
        self.assertEqual(baseline["classification"], attempted_downgrade["classification"])
        self.assertEqual([], attempted_downgrade["content_findings"])

    def test_assessment_structure_rejects_stale_missing_extra_and_duplicate_ids(self):
        path = "scripts/observer.py"
        line = "VirtualBox metadata"
        records = {path: [{"side": "+", "line": 7, "text": line}]}
        findings, _unmapped, complete = MERGE_RISK._content_findings(
            self.policy, [path], {path: line}, records
        )
        self.assertTrue(complete)
        self.assertEqual(1, len(findings))
        decision = {
            "finding_id": findings[0]["id"],
            "kind": "metadata",
            "rationale": "The value describes observed runtime identity.",
            "effect_trace": "literal to equality verification only",
        }
        assessment = {
            "schema_version": 1, "pr": 183,
            "base_sha": BASE_SHA, "head_sha": HEAD_SHA,
            "findings_sha256": MERGE_RISK._canonical_sha256(findings),
            "dispositions": [decision],
        }
        verify = lambda item: MERGE_RISK._disposed_finding_ids(
            item, base_sha=BASE_SHA, head_sha=HEAD_SHA,
            pr_number=183, findings=findings,
        )
        self.assertEqual({findings[0]["id"]}, verify(assessment))
        variants = (
            assessment | {"base_sha": "c" * 40},
            assessment | {"head_sha": "c" * 40},
            assessment | {"pr": 181},
            assessment | {"findings_sha256": "sha256:" + "0" * 64},
            assessment | {"dispositions": []},
            assessment | {"dispositions": [decision | {"finding_id": "sha256:" + "0" * 64}]},
            assessment | {"dispositions": [decision, decision]},
            assessment | {"dispositions": [decision | {"effect_trace": " "}]},
            assessment | {"dispositions": [decision | {"kind": "allow-all"}]},
        )
        for candidate in variants:
            with self.subTest(candidate=candidate):
                self.assertEqual(set(), verify(candidate))

    def test_pr183_real_trigger_fixture_has_all_seven_findings(self):
        # Exact changed lines and line numbers from the #183 diff, kept in this
        # fixture so CI does not need the original Git objects.
        lines = {
            "scripts/issue_completion.py": [
                {"side": "+", "line": 722,
                 "text": '                and identity.get("kind") == "virtualbox-vm"'},
            ],
            "scripts/native_recovery_evidence.py": [
                {"side": "+", "line": 142,
                 "text": "# tasks, VM configuration, credentials, or the contents of a private key."},
                {"side": "+", "line": 481,
                 "text": '    id_relative = f"{campaign}/smoke-run/.vagrant/machines/default/virtualbox/id"'},
                {"side": "+", "line": 516,
                 "text": '        "runtime_identity": {"kind": "virtualbox-vm", "id": vm_id},'},
                {"side": "+", "line": 538,
                 "text": '    _require(isinstance(identity, dict) and identity.get("kind") == "virtualbox-vm",'},
            ],
            "scripts/runtime_authority.py": [
                {"side": "+", "line": 182,
                 "text": '            "infrastructure", "production", "credentials", "destructive-cleanup",'},
            ],
        }
        changes = {
            path: "\n".join(item["text"] for item in records)
            for path, records in lines.items()
        }
        paths = sorted(changes)
        findings, unmapped, complete = MERGE_RISK._content_findings(
            self.policy, paths, changes, lines
        )
        self.assertTrue(complete)
        self.assertFalse(unmapped)
        self.assertEqual(7, len(findings), findings)
        self.assertEqual(
            {"production-operations": 1, "credential-identity": 2,
             "host-mutation": 4},
            {capability: sum(item["capability"] == capability for item in findings)
             for capability in {item["capability"] for item in findings}},
        )
        self.assertEqual(
            "sha256:65be3e129076b29f92549eca5bb0927c7f5d54a8ab84a382a4b7f8b316d8bba1",
            MERGE_RISK._canonical_sha256(findings),
        )
        baseline = MERGE_RISK.evaluate_merge_risk(
            self.policy, base_sha=BASE_SHA, head_sha=HEAD_SHA,
            pr_number=183, changed_files=paths, file_changes=changes,
            changed_lines=lines,
        )
        self.assertEqual("PRODUCTION", baseline["classification"])
        self.assertEqual(findings, baseline["content_findings"])

    def test_pr181_native_script_path_anchor_is_privileged_without_content_signal(self):
        # This unchanged trigger-free line was added under the native script path.
        path = "scripts/windows/LabNativeBoot.ps1"
        line = "function Get-NativeRecoverySnapshot {"
        result = MERGE_RISK.evaluate_merge_risk(
            self.policy, base_sha=BASE_SHA, head_sha=HEAD_SHA,
            pr_number=181, changed_files=[path], file_changes={path: line},
            changed_lines={path: [{"side": "+", "line": 1704, "text": line}]},
        )
        self.assertEqual("PRIVILEGED", result["classification"])
        self.assertIn("host-mutation", result["matched_capabilities"])
        self.assertEqual([], result["content_findings"])

    def test_exact_assessment_can_only_dismiss_fully_attested_content(self):
        path = "scripts/observer.py"
        line = 'label = "production credentials"'
        records = {path: [{"side": "+", "line": 8, "text": line}]}
        findings, unmapped, complete = MERGE_RISK._content_findings(
            self.policy, [path], {path: line}, records
        )
        self.assertTrue(complete)
        self.assertFalse(unmapped)
        self.assertEqual(2, len(findings))
        assessment = {
            "schema_version": 1, "pr": 183,
            "base_sha": BASE_SHA, "head_sha": HEAD_SHA,
            "findings_sha256": MERGE_RISK._canonical_sha256(findings),
            "dispositions": [
                {"finding_id": finding["id"], "kind": "metadata",
                 "rationale": "Reviewed as a static label.",
                 "effect_trace": "Literal assigned to inert metadata."}
                for finding in findings
            ],
        }
        def classify(candidate):
            return MERGE_RISK.evaluate_merge_risk(
                self.policy, base_sha=BASE_SHA, head_sha=HEAD_SHA,
                pr_number=183, changed_files=[path],
                file_changes={path: line}, changed_lines=records,
                assessment=candidate,
            )
        self.assertEqual("PRODUCTION", classify(None)["classification"])
        reviewed = classify(assessment)
        self.assertEqual("SENSITIVE", reviewed["classification"])
        self.assertEqual(
            "explicit-repository-owner",
            reviewed["requirements"]["owner_authorization"],
        )
        self.assertEqual(findings, reviewed["content_findings"])
        self.assertEqual(
            "PRODUCTION",
            classify(assessment | {"dispositions": assessment["dispositions"][:1]})[
                "classification"
            ],
        )
        self.assertEqual(
            "PRODUCTION",
            classify(assessment | {"dispositions": [
                assessment["dispositions"][0] | {"kind": []},
                assessment["dispositions"][1],
            ]})["classification"],
        )

    def test_assessment_never_dismisses_path_anchors_or_unmapped_matches(self):
        path = "scripts/windows/LabNativeBoot.ps1"
        line = "VirtualBox"
        records = {path: [{"side": "+", "line": 2, "text": line}]}
        findings, _unmapped, complete = MERGE_RISK._content_findings(
            self.policy, [path], {path: line}, records
        )
        self.assertTrue(complete)
        assessment = {
            "schema_version": 1, "pr": 181,
            "base_sha": BASE_SHA, "head_sha": HEAD_SHA,
            "findings_sha256": MERGE_RISK._canonical_sha256(findings),
            "dispositions": [
                {"finding_id": item["id"], "kind": "metadata",
                 "rationale": "Reviewed as a fixture label.",
                 "effect_trace": "No operation consumes this string."}
                for item in findings
            ],
        }
        native = MERGE_RISK.evaluate_merge_risk(
            self.policy, base_sha=BASE_SHA, head_sha=HEAD_SHA,
            pr_number=181, changed_files=[path], file_changes={path: line},
            changed_lines=records, assessment=assessment,
        )
        self.assertEqual("PRIVILEGED", native["classification"])
        self.assertIn("host-mutation", native["matched_capabilities"])

        contextual = copy.deepcopy(self.policy)
        contextual["production"]["capabilities"]["production-operations"][
            "content_patterns"
        ] = [r"production\s+credentials"]
        path = "scripts/configuration.py"
        records = {path: [
            {"side": "+", "line": 1, "text": "production"},
            {"side": "+", "line": 2, "text": "credentials"},
        ]}
        changes = {path: "production\ncredentials"}
        findings, unmapped, complete = MERGE_RISK._content_findings(
            contextual, [path], changes, records
        )
        self.assertTrue(complete)
        self.assertIn(("PRODUCTION", "production-operations"), unmapped)
        assessment = {
            "schema_version": 1, "pr": 183,
            "base_sha": BASE_SHA, "head_sha": HEAD_SHA,
            "findings_sha256": MERGE_RISK._canonical_sha256(findings),
            "dispositions": [
                {"finding_id": item["id"], "kind": "metadata",
                 "rationale": "Reviewed as a fixture label.",
                 "effect_trace": "No operation consumes this string."}
                for item in findings
            ],
        }
        unresolved = MERGE_RISK.evaluate_merge_risk(
            contextual, base_sha=BASE_SHA, head_sha=HEAD_SHA,
            pr_number=183, changed_files=[path], file_changes=changes,
            changed_lines=records, assessment=assessment,
        )
        self.assertEqual("PRODUCTION", unresolved["classification"])

    def test_active_command_and_old_side_deletion_stay_high_without_exact_review(self):
        path = "scripts/host_control.py"
        line = 'cmd = ["vboxmanage", "startvm"]'
        records = {path: [{"side": "+", "line": 3, "text": line}]}
        active = MERGE_RISK.evaluate_merge_risk(
            self.policy, base_sha=BASE_SHA, head_sha=HEAD_SHA,
            pr_number=183, changed_files=[path], file_changes={path: line},
            changed_lines=records,
        )
        self.assertEqual("PRIVILEGED", active["classification"])
        removed = {path: [{"side": "-", "line": 3, "text": line}]}
        deleted = MERGE_RISK.evaluate_merge_risk(
            self.policy, base_sha=BASE_SHA, head_sha=HEAD_SHA,
            pr_number=183, changed_files=[path], file_changes={path: line},
            changed_lines=removed,
        )
        self.assertEqual("PRIVILEGED", deleted["classification"])
        self.assertNotEqual(
            active["content_findings_sha256"], deleted["content_findings_sha256"]
        )
    def test_assessment_file_rejects_duplicate_keys_and_size_overflow(self):
        with tempfile.TemporaryDirectory(prefix="risk-assessment-test-") as directory:
            path = Path(directory) / "assessment.json"
            path.write_text('{"pr":183,"pr":183}', encoding="utf-8")
            self.assertIsNone(MERGE_RISK._read_assessment_file(path))
            path.write_text("x" * (MERGE_RISK.MAX_ASSESSMENT_BYTES + 1),
                            encoding="utf-8")
            self.assertIsNone(MERGE_RISK._read_assessment_file(path))
            path.write_text(json.dumps({"schema_version": 1}), encoding="utf-8")
            self.assertEqual(
                {"schema_version": 1}, MERGE_RISK._read_assessment_file(path)
            )


if __name__ == "__main__":
    unittest.main()
