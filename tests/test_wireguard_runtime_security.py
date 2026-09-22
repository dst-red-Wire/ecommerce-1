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
            "Record completed OpenBao authority rotation",
            "Revoke temporary bootstrap authority and peer staging after rotation",
        ]
        self.assertEqual(sorted(names.index(name) for name in sequence), [names.index(name) for name in sequence])
        handshake = tasks[names.index(sequence[2])]
        self.assertNotIn("ignore_errors", handshake)
        self.assertEqual(60, handshake["retries"])


if __name__ == "__main__":
    unittest.main()
