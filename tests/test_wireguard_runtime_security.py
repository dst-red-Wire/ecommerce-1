import base64
import copy
import importlib.util
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

import jinja2
import yaml
from ansible.errors import AnsibleFilterError

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "platform/ansible/roles/wireguard_gateway"
spec = importlib.util.spec_from_file_location("wg_filters", ROLE / "filter_plugins/mgmt_wireguard.py")
wg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wg)


class WireGuardRuntimeSecurityTests(unittest.TestCase):
    def setUp(self):
        self.material = {
            "private_key": base64.b64encode(bytes(range(32))).decode(),
            "peers": [
                {
                    "public_key": base64.b64encode(bytes(range(1, 33))).decode(),
                    "identity": "operator@example.test",
                    "allowed_ip": "10.246.0.17/32",
                }
            ],
        }

    def validate(self, material=None, authorized=False):
        return wg.validate_material(material or self.material, "10.246.0.16/28", "10.246.0.240/29", authorized)

    def test_valid_material_and_separate_break_glass_authorization(self):
        self.assertEqual(self.material, self.validate())
        peer = self.material["peers"][0]
        peer.update(scope="break-glass", allowed_ip="10.246.0.241/32")
        with self.assertRaises(AnsibleFilterError):
            self.validate()
        self.assertEqual(self.material, self.validate(authorized=True))

    def test_key_and_config_injection_rejected_without_secret_diagnostic(self):
        for field in ("private_key", "public_key", "allowed_ip", "identity"):
            for bad in ("\n[Interface]\nPreUp = malicious", "A" * 44, "<xml>", ""):
                if field == "identity" and bad == "A" * 44:
                    continue
                material = copy.deepcopy(self.material)
                target = material if field == "private_key" else material["peers"][0]
                target[field] = bad
                with self.subTest(field=field, bad=bad), self.assertRaises(AnsibleFilterError) as raised:
                    self.validate(material)
                self.assertNotIn(bad or "PreUp", str(raised.exception))

    def test_unexpected_peer_fields_are_rejected_before_audit(self):
        material = copy.deepcopy(self.material)
        material["peers"][0]["private_key"] = "must-not-reach-audit"
        with self.assertRaises(AnsibleFilterError) as raised:
            self.validate(material)
        self.assertNotIn("must-not-reach-audit", str(raised.exception))

    def test_bootstrap_peers_are_sanitized_before_persistent_staging(self):
        tasks = yaml.safe_load((ROLE / "tasks/main.yml").read_text())
        names = [task["name"] for task in tasks]
        sanitize = tasks[names.index("Validate and sanitize bootstrap peers before persistence")]
        stage = tasks[names.index("Stage non-secret bootstrap peer public records locally")]
        self.assertLess(names.index(sanitize["name"]), names.index(stage["name"]))
        self.assertIn("mgmt_wireguard_peers", sanitize["ansible.builtin.set_fact"]["wireguard_bootstrap_validated_peers"])
        self.assertIn("wireguard_bootstrap_validated_peers", stage["ansible.builtin.copy"]["content"])
        self.assertNotIn("wireguard_bootstrap_peers_json", stage["ansible.builtin.copy"]["content"])

    def test_openbao_reads_require_https_and_certificate_validation(self):
        tasks = yaml.safe_load((ROLE / "tasks/main.yml").read_text())
        auth = next(task for task in tasks if task["name"] == "Require runtime-only OpenBao authentication and canonical paths")
        self.assertIn("wireguard_openbao_addr is match('^https://[^\\s]+$')", auth["ansible.builtin.assert"]["that"])
        for name in (
            "Read the rotated gateway record from OpenBao at runtime",
            "List authoritative peer identities from OpenBao at runtime",
            "Read each authoritative peer record from OpenBao at runtime",
        ):
            task = next(task for task in tasks if task["name"] == name)
            self.assertIs(task["ansible.builtin.uri"]["validate_certs"], True)

    def test_single_host_pool_assignment_and_uniqueness(self):
        for bad in (
            "0.0.0.0/0",
            "10.246.0.16/28",
            "10.246.0.16/32",
            "10.246.0.31/32",
            "10.246.0.241/32",
            "10.243.1.4/32",
            "10.246.0.17/32,10.243.0.0/16",
        ):
            material = copy.deepcopy(self.material)
            material["peers"][0]["allowed_ip"] = bad
            with self.subTest(bad=bad), self.assertRaises(AnsibleFilterError):
                self.validate(material)
        self.material["peers"] *= 2
        with self.assertRaises(AnsibleFilterError):
            self.validate()

    def test_handshake_requires_approved_peer_and_post_activation_timestamp(self):
        public = self.material["peers"][0]["public_key"]
        self.assertFalse(wg.fresh_handshake(f"{public}\t0", self.material["peers"], 100))
        self.assertFalse(wg.fresh_handshake(f"{public}\t99", self.material["peers"], 100))
        self.assertFalse(wg.fresh_handshake("foreign\t101", self.material["peers"], 100))
        self.assertFalse(wg.fresh_handshake("malformed", self.material["peers"], 100))
        self.assertTrue(wg.fresh_handshake(f"{public}\t101", self.material["peers"], 100))

    def test_forwarding_is_persistent_scoped_and_audited_before_snat(self):
        env = jinja2.Environment(loader=jinja2.FileSystemLoader(ROLE / "templates"), undefined=jinja2.StrictUndefined)
        args = dict(wireguard_validated_material=self.validate(), wireguard_allowed_routes=["10.243.0.0/16"])
        policy = ET.fromstring(env.get_template("wg-policy.xml.j2").render(**args))
        self.assertEqual("DROP", policy.attrib["target"])
        self.assertEqual("wg-mgmt", policy.find("ingress-zone").attrib["name"])
        rule = policy.find("rule")
        self.assertEqual("10.246.0.17/32", rule.find("source").attrib["address"])
        self.assertEqual("10.243.0.0/16", rule.find("destination").attrib["address"])
        self.assertEqual("1/s", rule.find("log/limit").attrib["value"])
        self.assertIsNotNone(rule.find("accept"))
        self.assertNotIn("PostUp", (ROLE / "templates/wg0.conf.j2").read_text())

    def test_openbao_list_keys_does_not_resolve_dict_method(self):
        tasks = yaml.safe_load((ROLE / "tasks/main.yml").read_text())
        task = next(t for t in tasks if t["name"] == "Read each authoritative peer record from OpenBao at runtime")
        rendered = (
            jinja2.Environment(undefined=jinja2.StrictUndefined)
            .from_string(task["loop"])
            .render(wireguard_openbao_peer_list={"json": {"data": {"keys": ["operator"]}}})
        )
        self.assertEqual("['operator']", rendered)

    def test_rotation_cleanup_and_rollback_guards_are_fail_closed(self):
        tasks = yaml.safe_load((ROLE / "tasks/main.yml").read_text())
        names = [task["name"] for task in tasks]
        self.assertLess(
            names.index("Refuse to restore bootstrap after OpenBao transition"),
            names.index("Generate the temporary gateway key locally on wg-01"),
        )
        self.assertLess(
            names.index("Validate keys and separately authorized peer assignments before rendering"),
            names.index("Render fail-closed WireGuard gateway configuration"),
        )
        sequence = [
            "Activate forwarding and rotated WireGuard before authority cleanup",
            "Verify the replacement key is active before cleanup",
            "Require a fresh authenticated peer handshake on the activated tunnel",
            "Require provider bootstrap SSH teardown before completing transition",
            "Record completed OpenBao authority rotation",
            "Revoke temporary bootstrap authority and peer staging after rotation",
        ]
        self.assertEqual(sorted(names.index(name) for name in sequence), [names.index(name) for name in sequence])
        handshake = tasks[names.index(sequence[2])]
        self.assertNotIn("ignore_errors", handshake)
        self.assertEqual(60, handshake["retries"])
        teardown = tasks[names.index(sequence[3])]
        self.assertEqual(["mgmt_transport_phase == 'steady-state'"], teardown["ansible.builtin.assert"]["that"])
        self.assertIn("not wireguard_authority_state.stat.exists", teardown["when"])

    def test_first_openbao_transition_requires_explicit_human_gate_and_effective_key_rotation(self):
        tasks = yaml.safe_load((ROLE / "tasks/main.yml").read_text())
        names = [task["name"] for task in tasks]
        gate = tasks[names.index("Require explicit human authorization for first OpenBao authority transition")]
        self.assertEqual(["wireguard_openbao_transition_human_gate | bool"], gate["ansible.builtin.assert"]["that"])
        self.assertEqual(
            ["wireguard_secret_mode == 'runtime-openbao-read'", "not wireguard_authority_state.stat.exists"],
            gate["when"],
        )
        self.assertLess(
            names.index("Derive the bootstrap WireGuard public key for rotation proof"),
            names.index("Derive the OpenBao replacement WireGuard public key for rotation proof"),
        )
        proof = tasks[names.index("Prove the OpenBao key replaces the effective bootstrap credential")]
        self.assertEqual(
            ["wireguard_openbao_replacement_public_key.stdout | trim != wireguard_pre_transition_public_key.stdout | trim"],
            proof["ansible.builtin.assert"]["that"],
        )
        defaults = yaml.safe_load((ROLE / "defaults/main.yml").read_text())
        self.assertIs(defaults["wireguard_openbao_transition_human_gate"], False)
        self.assertIn(
            "MGMT_OPENBAO_AUTHORITY_TRANSITION_HUMAN_GATE",
            (ROOT / "platform/ansible/mgmt.yml").read_text(),
        )

    def test_first_openbao_transition_requires_preserved_bootstrap_key(self):
        tasks = yaml.safe_load((ROLE / "tasks/main.yml").read_text())
        names = [task["name"] for task in tasks]
        guard_name = "Require preserved bootstrap key for first OpenBao authority transition"
        guard = tasks[names.index(guard_name)]
        self.assertLess(
            names.index("Inspect temporary gateway key on wg-01"),
            names.index(guard_name),
        )
        self.assertLess(
            names.index(guard_name),
            names.index("Read the existing bootstrap key for mandatory rotation proof"),
        )
        self.assertEqual(
            ["wireguard_bootstrap_key_stat.stat.exists | default(false)"],
            guard["ansible.builtin.assert"]["that"],
        )
        self.assertEqual(
            [
                "wireguard_secret_mode == 'runtime-openbao-read'",
                "not wireguard_authority_state.stat.exists",
            ],
            guard["when"],
        )


if __name__ == "__main__":
    unittest.main()
