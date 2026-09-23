import json
import hashlib
import importlib.util
import re
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
MACHINE_LOCK = ROOT / "config/contracts/machine-image-lock.yaml"
PACKAGE_LOCK = ROOT / "config/artifacts/rocky-10.2-base-packages.lock.json"
PACKER = ROOT / "platform/packer/rocky-10.2/rocky-10.2.pkr.hcl"
KICKSTART = ROOT / "platform/packer/rocky-10.2/http/rocky-10.2.ks"
MATERIALIZER_PATH = ROOT / "scripts/materialize_packer_rpm_repo.py"
SPEC = importlib.util.spec_from_file_location("materialize_packer_rpm_repo", MATERIALIZER_PATH)
MATERIALIZER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATERIALIZER)


class PackerImageContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = yaml.safe_load(MACHINE_LOCK.read_text(encoding="utf-8"))
        cls.image = cls.contract["packer_image"]
        cls.package_lock = json.loads(PACKAGE_LOCK.read_text(encoding="utf-8"))
        cls.packer = PACKER.read_text(encoding="utf-8")
        cls.kickstart = KICKSTART.read_text(encoding="utf-8")

    def test_exact_rocky_10_2_dvd_and_x86_64_v3(self):
        self.assertEqual(
            self.image["source"],
            {
                "iso": "Rocky-10.2-x86_64-dvd1.iso",
                "url": "https://download.rockylinux.org/pub/rocky/10.2/isos/x86_64/Rocky-10.2-x86_64-dvd1.iso",
                "sha256": "16ca9c96cdb221ba6e1f68579f21bd69fd8da81c6a921d9068949796f91c8feb",
                "mutable_aliases": "forbidden",
            },
        )
        self.assertEqual(self.image["os"]["architecture"], "x86_64-v3")

    def test_one_package_definition_drives_both_outputs(self):
        self.assertTrue(self.image["packages"]["single_definition_for_all_outputs"])
        self.assertEqual(self.package_lock["image"], "rocky-10.2-base")
        packages = {entry["package"]: entry for entry in self.package_lock["packages"]}
        for required in (
            "kernel", "kernel-modules-extra", "container-selinux", "NetworkManager",
            "openssh-server", "python3", "chrony", "nftables", "iptables-nft",
            "qemu-guest-agent", "conntrack-tools", "ripgrep", "fd-find", "fzf", "yq",
            "bat", "tmux", "tree", "less", "lsof", "bind-utils",
        ):
            self.assertIn(required, packages)
            self.assertRegex(packages[required]["sha256"], r"^[0-9a-f]{64}$")
        self.assertNotIn("firewalld", packages)
        self.assertNotIn("rke2-selinux", packages)
        self.assertEqual(packages["kernel"]["nevra"], self.image["kernel"]["nevra"])
        unsigned = dict(self.package_lock)
        approved = unsigned.pop("approved_manifest_sha256")
        body = json.dumps(unsigned, sort_keys=True, indent=2) + "\n"
        self.assertEqual(hashlib.sha256(body.encode()).hexdigest(), approved)

    def test_materializer_fails_closed_on_tamper(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "package.rpm"
            source.write_bytes(b"tampered")
            lock = {
                "image": "rocky-10.2-base",
                "dependency_closure": "complete",
                "rpm_signing_keys": [],
                "packages": [{
                    "file": source.name,
                    "url": source.as_uri(),
                    "sha256": "0" * 64,
                }],
            }
            lock_path = root / "lock.json"
            lock_path.write_text(json.dumps(lock), encoding="utf-8")
            with self.assertRaises(MATERIALIZER.MaterializationError):
                MATERIALIZER.materialize(lock_path, root / "output")

    def test_packer_plugins_and_outputs_are_exact(self):
        expected = {"virtualbox": "1.1.5", "qemu": "1.1.6", "vagrant": "1.1.7"}
        for plugin, version in expected.items():
            block = re.search(rf"{plugin}\s*=\s*\{{(?P<body>.*?)\n\s*\}}", self.packer, re.S)
            self.assertIsNotNone(block)
            self.assertIn(f'version = "= {version}"', block.group("body"))
        self.assertIn("rocky-10.2-virtualbox.box", self.packer)
        self.assertEqual(self.image["outputs"]["qemu_kvm"], "rocky-10.2-kvm.qcow2")

    def test_packer_owns_only_immutable_os_base(self):
        packer_tree = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (ROOT / "platform/packer").rglob("*") if path.is_file()
        )
        for forbidden in ("ansible", "rke2-token", "cluster-init", "cilium", "haproxy"):
            self.assertNotIn(forbidden, packer_tree.lower())
        self.assertEqual(self.contract["rules"]["packer_may_invoke_ansible"], "forbidden")
        renderer = (ROOT / "scripts/render_packer_vars.py").read_text(encoding="utf-8")
        self.assertIn('contract["packer_image"]', renderer)
        self.assertNotIn("Rocky-10.2-x86_64-dvd1.iso", self.packer)

    def test_image_hardening_and_clone_hygiene_are_executable(self):
        expected_kickstart = (
            "selinux --enforcing", "firewall --disabled", "-firewalld",
            "kernel-modules-extra", "swapoff -a", "net.ipv4.ip_forward = 1",
            "overlay", "br_netfilter", "nf_conntrack", "vxlan", "NetworkManager",
            "chronyd", "sshd",
        )
        for value in expected_kickstart:
            self.assertIn(value, self.kickstart)
        for value in (
            "truncate -s 0 /etc/machine-id", "rm -f /var/lib/dbus/machine-id /etc/ssh/ssh_host_*",
            "PasswordAuthentication no", "hostnamectl set-hostname rocky-10-2-base",
            "cgroup2fs", "grep -qw bpf /proc/filesystems",
        ):
            self.assertIn(value, self.packer)

    def test_rke2_selinux_stays_in_bundle_and_runtime_config(self):
        bundle = json.loads((ROOT / "config/artifacts/mgmt-rke2-offline-v1.37.0-rke2r1.lock.json").read_text())
        packages = {entry["package"] for entry in bundle["rpms"]}
        self.assertIn("rke2-selinux", packages)
        for template in ("rke2_server", "rke2_agent"):
            text = (ROOT / f"platform/ansible/roles/{template}/templates/config.yaml.j2").read_text()
            self.assertIn("selinux: true", text)
        server = (ROOT / "platform/ansible/roles/rke2_server/templates/config.yaml.j2").read_text()
        self.assertIn("cluster-init: true", server)
        mgmt = (ROOT / "platform/ansible/mgmt.yml").read_text()
        self.assertIn("ansible.builtin.hostname", mgmt)
        self.assertIn('name: "{{ inventory_hostname }}"', mgmt)


if __name__ == "__main__":
    unittest.main()
