import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("capability_resolver", ROOT / "scripts/capability_resolver.py")
RESOLVER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(RESOLVER)
SHA = "b" * 40
ARTIFACT = "sha256:" + "c" * 64


class CapabilityResolverTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        for relative in (
            "config/contracts/tool-capabilities.yaml",
            "config/contracts/composed-capabilities.yaml",
            "config/contracts/toolchain-lock.json",
        ):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / relative).read_bytes())
        registry = self.load("config/contracts/tool-capabilities.yaml")
        lock = self.load("config/contracts/toolchain-lock.json")
        # Positive fixtures activate repository-external platform tools with exact versions.
        for tool, version_ref in (("fleet", "FLEET_VERSION"), ("buildkit", "DOCKER_BUILDX_VERSION")):
            lock["versions"].setdefault(version_ref, "1.0.0")
            lifecycle_name = "docker-buildx" if tool == "buildkit" else tool
            lock["tool_lifecycle"]["active"][lifecycle_name] = {"version_ref": version_ref}
        self.dump("config/contracts/toolchain-lock.json", lock)
        for entry in registry["tools"].values():
            for probe in entry.get("discovery", []):
                path = self.root / probe["path"]
                if path.suffix:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    with path.open("a", encoding="utf-8") as stream:
                        stream.write(probe.get("marker", "configured") + "\n")
                else:
                    path.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self.tmp.cleanup()

    def load(self, relative):
        return RESOLVER._load(self.root / relative)

    def dump(self, relative, value):
        (self.root / relative).write_text(json.dumps(value, sort_keys=True) + "\n")

    def evidence(self, tool, capability, requirements, **observations):
        record = {
            "id": f"{tool}-{capability}", "tool": tool, "capability": capability,
            "source_sha": SHA, "toolchain_digest": RESOLVER.toolchain_digest(self.root),
            "artifact_digest": ARTIFACT, "gate": "PASS", "gate_id": f"{tool}-{capability}",
            "requirements": {name: "PASS" for name in requirements},
            "observations": observations,
        }
        record["evidence_digest"] = "sha256:" + hashlib.sha256(
            json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return record

    def resolve_records(self, records):
        path = self.root / "evidence.json"
        path.write_text(json.dumps({"evidence": records}))
        return RESOLVER.resolve(self.root, evidence_path=path, source_sha=SHA)

    def requirements(self, tool, capability):
        registry = self.load("config/contracts/tool-capabilities.yaml")
        expression = registry["tools"][tool]["capabilities"][capability]["requires"]
        return RESOLVER._requirement_names(expression)

    def test_positive_ansible_packer_cosign_and_fleet_proofs(self):
        records = [
            self.evidence("ansible", "idempotency", self.requirements("ansible", "idempotency"), second_apply_changes=0),
            self.evidence("packer", "reproducibility", self.requirements("packer", "reproducibility")),
            self.evidence("cosign", "integrity", self.requirements("cosign", "integrity"), signature_verified=True),
            self.evidence("cosign", "provenance", self.requirements("cosign", "provenance"), signature_verified=True, attestation_verified=True),
            self.evidence("fleet", "convergence", self.requirements("fleet", "convergence")),
        ]
        result = self.resolve_records(records)
        for tool, capability in (("ansible", "idempotency"), ("packer", "reproducibility"), ("cosign", "integrity"), ("cosign", "provenance"), ("fleet", "convergence")):
            self.assertEqual("proven", result["tools"][tool]["capabilities"][capability]["status"])

    def test_installed_cosign_without_signature_is_never_proven(self):
        result = RESOLVER.resolve(self.root, source_sha=SHA)
        self.assertIn(result["tools"]["cosign"]["capabilities"]["integrity"]["status"], {"available", "configured"})

    def test_ansible_without_second_apply_is_not_proven(self):
        result = RESOLVER.resolve(self.root, source_sha=SHA)
        self.assertNotEqual("proven", result["tools"]["ansible"]["capabilities"]["idempotency"]["status"])

    def test_ansible_changed_one_fails_closed(self):
        record = self.evidence("ansible", "idempotency", self.requirements("ansible", "idempotency"), second_apply_changes=1)
        result = self.resolve_records([record])
        self.assertEqual("configured", result["tools"]["ansible"]["capabilities"]["idempotency"]["status"])
        self.assertIn("second_apply_changed_nonzero", result["stale_evidence"][0]["reasons"])

    def test_packer_latest_is_unsupported(self):
        lock = self.load("config/contracts/toolchain-lock.json")
        lock["versions"]["PACKER_VERSION"] = "latest"
        self.dump("config/contracts/toolchain-lock.json", lock)
        result = RESOLVER.resolve(self.root, source_sha=SHA)
        self.assertEqual("unsupported", result["tools"]["packer"]["detection"]["status"])

    def test_packer_without_checksum_is_not_proven(self):
        requirements = self.requirements("packer", "reproducibility") - {"checksums_verified"}
        result = self.resolve_records([self.evidence("packer", "reproducibility", requirements)])
        self.assertEqual("verified", result["tools"]["packer"]["capabilities"]["reproducibility"]["status"])

    def test_fleet_without_observed_state_is_not_proven(self):
        requirements = self.requirements("fleet", "convergence") - {"observed_state"}
        result = self.resolve_records([self.evidence("fleet", "convergence", requirements)])
        self.assertEqual("verified", result["tools"]["fleet"]["capabilities"]["convergence"]["status"])

    def test_foreign_sha_fails_closed(self):
        record = self.evidence("cosign", "integrity", self.requirements("cosign", "integrity"), signature_verified=True)
        record["source_sha"] = "a" * 40
        result = self.resolve_records([record])
        self.assertIn("stale_or_foreign_evidence", result["stale_evidence"][0]["reasons"])

    def test_unknown_capability_and_tool_fail_closed(self):
        unknown_cap = self.evidence("cosign", "magic_reproducibility", [])
        unknown_tool = self.evidence("magic", "verification", [])
        result = self.resolve_records([unknown_cap, unknown_tool])
        self.assertIn("unknown_capability:cosign.magic_reproducibility", result["unknown_states"])
        self.assertIn("unknown_tool:magic", result["unknown_states"])

    def test_incomplete_composed_capability_is_not_proven(self):
        result = RESOLVER.resolve(self.root, source_sha=SHA)
        self.assertEqual("not_proven", result["composed_capabilities"]["supply_chain_integrity"]["status"])

    def test_deterministic_for_identical_inputs(self):
        first = RESOLVER.resolve(self.root, source_sha=SHA)
        second = RESOLVER.resolve(self.root, source_sha=SHA)
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
