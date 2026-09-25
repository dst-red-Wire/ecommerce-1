import hashlib
import importlib.util
import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
MACHINE_LOCK = ROOT / "config/contracts/machine-image-lock.yaml"
TOOLCHAIN_LOCK = ROOT / "config/contracts/toolchain-lock.json"
PACKAGE_LOCK = ROOT / "config/artifacts/rocky-10.2-base-packages.lock.json"
PACKER = ROOT / "platform/packer/rocky-10.2/rocky-10.2.pkr.hcl"
PACKER_VARIABLES = ROOT / "platform/packer/rocky-10.2/variables.pkr.hcl"
KICKSTART = ROOT / "platform/packer/rocky-10.2/http/rocky-10.2.ks"
MATERIALIZER_PATH = ROOT / "scripts/materialize_packer_rpm_repo.py"
RENDERER_PATH = ROOT / "scripts/render_packer_vars.py"
INSTALLER = ROOT / "scripts/install_packer_tools.py"
GENERATOR = ROOT / "scripts/generate_packer_rpm_lock.py"
REPOCTL_PATH = ROOT / "scripts/repoctl.py"
SPEC = importlib.util.spec_from_file_location(
    "materialize_packer_rpm_repo", MATERIALIZER_PATH
)
MATERIALIZER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATERIALIZER)
RENDERER_SPEC = importlib.util.spec_from_file_location(
    "render_packer_vars", RENDERER_PATH
)
RENDERER = importlib.util.module_from_spec(RENDERER_SPEC)
RENDERER_SPEC.loader.exec_module(RENDERER)
INSTALLER_SPEC = importlib.util.spec_from_file_location(
    "install_packer_tools", INSTALLER
)
PACKER_INSTALLER = importlib.util.module_from_spec(INSTALLER_SPEC)
INSTALLER_SPEC.loader.exec_module(PACKER_INSTALLER)
REPOCTL_SPEC = importlib.util.spec_from_file_location(
    "repoctl_image_artifact_transport", REPOCTL_PATH
)
REPOCTL = importlib.util.module_from_spec(REPOCTL_SPEC)
REPOCTL_SPEC.loader.exec_module(REPOCTL)


def manifest_is_valid(document):
    unsigned = dict(document)
    approved = unsigned.pop("approved_manifest_sha256")
    body = json.dumps(unsigned, sort_keys=True, indent=2) + "\n"
    return hashlib.sha256(body.encode()).hexdigest() == approved


class PackerImageContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = yaml.safe_load(MACHINE_LOCK.read_text(encoding="utf-8"))
        cls.image = cls.contract["packer_image"]
        cls.toolchain = json.loads(TOOLCHAIN_LOCK.read_text(encoding="utf-8"))
        cls.package_lock = json.loads(PACKAGE_LOCK.read_text(encoding="utf-8"))
        cls.packer = PACKER.read_text(encoding="utf-8") + "\n" + PACKER_VARIABLES.read_text(
            encoding="utf-8"
        )
        cls.kickstart = KICKSTART.read_text(encoding="utf-8")
        cls.repoctl = REPOCTL_PATH.read_text(encoding="utf-8")

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

    def test_vm_resources_have_one_contract_authority(self):
        self.assertEqual(
            {
                "authority": "shared-all-hypervisors",
                "vcpus": 4,
                "memory_mib": 4096,
                "disk_mib": 32768,
                "headless": True,
            },
            self.image["build"]["resources"],
        )
        self.assertEqual(
            {
                "authority": "shared-all-hypervisors",
                "firmware": "bios",
                "partition_table": "gpt",
                "bios_boot_mib": 1,
                "boot_mib": 2048,
                "root_min_mib": 10240,
                "root_filesystem": "xfs",
                "lvm": "forbidden",
                "swap": "forbidden",
            },
            self.image["build"]["storage"],
        )
        self.assertEqual(
            {"authority": "shared-all-hypervisors", "ssh_seconds": 3600},
            self.image["build"]["timeouts"],
        )
        self.assertEqual(
            2,
            len(re.findall(r"^\s*cpus\s*=\s*var\.vm_cpus$", self.packer, re.MULTILINE)),
        )
        self.assertEqual(
            2,
            len(
                re.findall(
                    r"^\s*memory\s*=\s*var\.vm_memory_mib$",
                    self.packer,
                    re.MULTILINE,
                )
            ),
        )
        self.assertNotRegex(self.packer, r"(?m)^\s*cpus\s*=\s*2$")
        self.assertNotRegex(self.packer, r"(?m)^\s*memory\s*=\s*4096$")
        self.assertEqual(
            2,
            len(
                re.findall(
                    r"^\s*headless\s*=\s*var\.vm_headless$",
                    self.packer,
                    re.MULTILINE,
                )
            ),
        )
        self.assertRegex(self.packer, r"(?m)^\s*disk_size\s*=\s*var\.vm_disk_mib$")
        self.assertIn('disk_size            = "${var.vm_disk_mib}M"', self.packer)
        self.assertIn("firmware               = var.vm_firmware", self.packer)
        self.assertIn('efi_boot             = var.vm_firmware == "efi"', self.packer)
        self.assertEqual(
            2,
            len(
                re.findall(
                    r'^\s*ssh_timeout\s*=\s*"\$\{var\.vm_ssh_timeout_seconds\}s"$',
                    self.packer,
                    re.MULTILINE,
                )
            ),
        )

    def test_renderer_projects_shared_vm_resources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "bundle"
            iso = bundle / "iso" / "source.iso"
            iso.parent.mkdir(parents=True)
            iso.write_bytes(b"test-iso")
            (bundle / "rpms/base").mkdir(parents=True)
            (bundle / "tools/base").mkdir(parents=True)
            (bundle / "evidence.json").write_text("{}\n", encoding="utf-8")
            (bundle / "rpms/base/SHA256SUMS").write_text("", encoding="utf-8")
            (bundle / "tools/base/SHA256SUMS").write_text("", encoding="utf-8")
            contract = {
                "packer_image": {
                    "id": "rocky-10.2-base",
                    "source": {
                        "iso": iso.name,
                        "sha256": hashlib.sha256(b"test-iso").hexdigest(),
                        "mutable_aliases": "forbidden",
                    },
                    "build": {
                        "resources": {
                            "authority": "shared-all-hypervisors",
                            "vcpus": 4,
                            "memory_mib": 8192,
                            "disk_mib": 65536,
                            "headless": False,
                        },
                        "storage": {
                            "authority": "shared-all-hypervisors",
                            "firmware": "bios",
                            "partition_table": "gpt",
                            "bios_boot_mib": 1,
                            "boot_mib": 4096,
                            "root_min_mib": 20480,
                            "root_filesystem": "xfs",
                            "lvm": "forbidden",
                            "swap": "forbidden",
                        },
                        "timeouts": {
                            "authority": "shared-all-hypervisors",
                            "ssh_seconds": 5400,
                        },
                        "virtualbox": {
                            "acceleration": {
                                "required": "native-vtx",
                                "forbidden": ["nem"],
                                "hyper_v_present": False,
                            }
                        },
                    },
                    "hypervisors": {
                        "virtualbox": {"network_adapter": "virtio"}
                    },
                    "profiles": {
                        "base": {"rpm_packages": ["kernel", "openssh-server"]},
                        "rke2": {"rpm_packages": ["openscap-scanner"]},
                    },
                }
            }
            contract_path = root / "contract.yaml"
            contract_path.write_text(yaml.safe_dump(contract), encoding="utf-8")
            public_key = root / "build.pub"
            private_key = root / "build"
            public_key.write_text("ssh-ed25519 AAAA test\n", encoding="utf-8")
            private_key.write_text("test\n", encoding="utf-8")
            output = root / "generated.pkrvars.hcl"
            runtime_output = root / "runtime-contract.json"
            RENDERER.render(
                contract_path,
                bundle,
                public_key,
                private_key,
                output,
                target_platform="linux",
                runtime_contract_output=runtime_output,
            )
            rendered = output.read_text(encoding="utf-8")
            self.assertIn("vm_cpus = 4\n", rendered)
            self.assertIn("vm_memory_mib = 8192\n", rendered)
            self.assertIn("vm_disk_mib = 65536\n", rendered)
            self.assertIn("vm_headless = false\n", rendered)
            self.assertIn('vm_firmware = "bios"\n', rendered)
            self.assertIn('vm_partition_table = "gpt"\n', rendered)
            self.assertIn("vm_bios_boot_mib = 1\n", rendered)
            self.assertIn("vm_boot_mib = 4096\n", rendered)
            self.assertIn("vm_root_min_mib = 20480\n", rendered)
            self.assertIn('vm_root_filesystem = "xfs"\n', rendered)
            self.assertIn("vm_ssh_timeout_seconds = 5400\n", rendered)
            self.assertIn('vm_virtualbox_nic_type = "virtio"\n', rendered)
            self.assertIn(
                'virtualbox_serial_log_file = "',
                rendered,
            )
            runtime = json.loads(runtime_output.read_text(encoding="utf-8"))
            self.assertEqual(
                {
                    "vcpus": 4,
                    "memory_mib": 8192,
                    "disk_mib": 65536,
                    "headless": False,
                },
                runtime["resources"],
            )
            self.assertEqual("virtio", runtime["virtualbox"]["network_adapter"])
            self.assertEqual(
                ["kernel", "openssh-server", "openscap-scanner"],
                runtime["rpm_profile_roots"],
            )

    def test_renderer_rejects_invalid_vm_resources(self):
        with self.assertRaisesRegex(TypeError, "vcpus must be an integer"):
            RENDERER._bounded_contract_integer(
                {"vcpus": True}, "vcpus", minimum=1, maximum=64
            )
        with self.assertRaisesRegex(ValueError, "memory_mib must be between"):
            RENDERER._bounded_contract_integer(
                {"memory_mib": 1024}, "memory_mib", minimum=2048, maximum=262144
            )

    def test_profile_roots_have_one_central_definition(self):
        profiles = self.image["profiles"]
        base = set(profiles["base"]["rpm_packages"])
        rke2 = set(profiles["rke2"]["rpm_packages"])
        admin = set(profiles["admin-qualification"]["rpm_packages"])
        qemu = set(self.image["hypervisors"]["qemu_kvm"]["rpm_packages"])
        self.assertFalse(base & admin)
        self.assertFalse(base & rke2)
        self.assertFalse(base & qemu)
        self.assertFalse(admin & qemu)
        for required in (
            "kernel-modules-extra",
            "container-selinux",
            "NetworkManager",
            "openssh-server",
            "python3",
            "cloud-init",
            "chrony",
            "nftables",
            "iptables-nft",
            "conntrack-tools",
            "socat",
            "nmap-ncat",
            "zstd",
            "zip",
            "acl",
            "attr",
            "openssl",
            "fzf",
            "jq",
            "bat",
            "tmux",
            "curl",
        ):
            self.assertIn(required, base)
        self.assertEqual(admin, {"git", "strace", "sysstat", "mtr", "ShellCheck"})
        self.assertEqual(rke2, {"openscap-scanner", "scap-security-guide"})
        self.assertEqual(qemu, {"qemu-guest-agent"})
        self.assertNotIn("qemu-guest-agent", base)
        self.assertTrue(
            {"cloud-init-local", "cloud-init", "cloud-config", "cloud-final"}
            <= set(self.image["services"]["enabled"])
        )

    def test_profile_package_lock_is_a_valid_projection(self):
        self.assertEqual(
            {
                "repositories": "forbidden",
                "local_package_gpg_check": "required",
                "iso_conflict_replacement": "allowerasing",
                "skip_broken": "forbidden",
                "nobest": "forbidden",
                "qualification": "exact-profile-roots",
            },
            self.image["packages"]["transaction"],
        )
        self.assertEqual(4, self.packer.count("--allowerasing install"))
        self.assertNotIn("--skip-broken", self.packer)
        self.assertNotIn("--nobest", self.packer)
        self.assertEqual(self.package_lock["schema_version"], 2)
        self.assertEqual(self.package_lock["image"], "rocky-10.2-base")
        self.assertTrue(manifest_is_valid(self.package_lock))
        roots = {
            "base": self.image["profiles"]["base"]["rpm_packages"],
            "rke2": self.image["profiles"]["rke2"]["rpm_packages"],
            "qemu-kvm": self.image["hypervisors"]["qemu_kvm"]["rpm_packages"],
            "admin-qualification": self.image["profiles"]["admin-qualification"][
                "rpm_packages"
            ],
        }
        files = {}
        for profile, expected_roots in roots.items():
            definition = self.package_lock["profiles"][profile]
            self.assertEqual(definition["roots"], expected_roots)
            self.assertTrue(manifest_is_valid(definition))
            names = {entry["package"] for entry in definition["packages"]}
            for required in expected_roots:
                self.assertIn(required, names)
            for entry in definition["packages"]:
                self.assertRegex(entry["sha256"], r"^[0-9a-f]{64}$")
                self.assertIn(entry["architecture"], {"x86_64", "noarch"})
                self.assertNotIn("nevra", entry)
            files[profile] = {entry["file"] for entry in definition["packages"]}
        self.assertFalse(files["base"] & files["qemu-kvm"])
        self.assertFalse(files["base"] & files["rke2"])
        self.assertFalse(files["base"] & files["admin-qualification"])
        sources = self.image["packages"]["sources"]
        self.assertEqual(
            self.package_lock["rpm_signing_keys"],
            [sources["rocky"]["signing_key"], sources["epel"]["signing_key"]],
        )

    def test_kernel_nevra_matches_the_approved_package_lock(self):
        kernels = [
            entry
            for entry in self.package_lock["profiles"]["base"]["packages"]
            if entry["package"] == "kernel"
        ]
        self.assertEqual(1, len(kernels))
        kernel = kernels[0]
        expected = (
            f"{kernel['package']}-{kernel['epoch']}:{kernel['version']}-"
            f"{kernel['release']}.{kernel['architecture']}"
        )
        self.assertEqual(expected, self.image["kernel"]["nevra"])
        self.assertEqual(
            "exact-plus-one-previous",
            self.image["kernel"]["installonly_retention"],
        )
        self.assertEqual("exact", self.image["kernel"]["default_boot_nevra"])
        self.assertIn("grubby --default-kernel", self.packer)

    def test_rpm_root_version_qualification_handles_installonly_packages(self):
        expected = "0:6.12.0-211.58.1.el10_2.x86_64"
        previous = "0:6.12.0-211.16.1.el10_2.0.1.x86_64"
        PACKER_INSTALLER.validate_rpm_versions(
            "kernel", expected, {previous, expected}
        )
        with self.assertRaisesRegex(PACKER_INSTALLER.ToolInstallError, "kernel"):
            PACKER_INSTALLER.validate_rpm_versions(
                "kernel", expected, {"old-a", "old-b", expected}
            )
        with self.assertRaisesRegex(PACKER_INSTALLER.ToolInstallError, "curl"):
            PACKER_INSTALLER.validate_rpm_versions(
                "curl",
                "0:8.0-1.x86_64",
                {"0:7.0-1.x86_64", "0:8.0-1.x86_64"},
            )

    def test_materializer_reports_expected_and_actual_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "gh.rpm"
            artifact.write_bytes(b"tampered")
            with self.assertRaisesRegex(
                MATERIALIZER.MaterializationError,
                r"artifact=gh\.rpm expected_version=2\.101\.0 "
                r"expected_sha256=0{64} actual_sha256=[0-9a-f]{64}",
            ):
                MATERIALIZER._verify(
                    artifact,
                    artifact="gh.rpm",
                    version="2.101.0",
                    expected="0" * 64,
                )

    def test_materializer_cache_copy_avoids_sendfile_fast_path(self):
        content = (b"bounded-cross-filesystem-copy\n" * 150_000) + b"end"
        expected = hashlib.sha256(content).hexdigest()
        entry = {
            "file": "large.iso",
            "sha256": expected,
            "version": "test",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cached = root / "cache" / expected / entry["file"]
            cached.parent.mkdir(parents=True)
            cached.write_bytes(content)
            destination = root / "staging" / entry["file"]
            destination.parent.mkdir()
            with mock.patch.object(
                MATERIALIZER.shutil,
                "copyfile",
                side_effect=AssertionError("sendfile-backed copy is forbidden"),
            ), mock.patch.object(
                MATERIALIZER, "COPY_SYNC_BYTES", 1024 * 1024
            ), mock.patch.object(
                MATERIALIZER.os, "fsync", wraps=MATERIALIZER.os.fsync
            ) as fsync:
                MATERIALIZER._acquire(entry, destination, root / "cache", offline=True)
            self.assertEqual(content, destination.read_bytes())
            self.assertGreaterEqual(fsync.call_count, 4)

    def test_external_tools_use_the_central_toolchain_authority(self):
        expected = {
            "ripgrep": ("15.2.0", "rocky-10.2-base"),
            "fd": ("10.4.2", "rocky-10.2-base"),
            "yq": ("4.53.6", "rocky-10.2-base"),
            "gh": ("2.101.0", "rocky-10.2-admin-qualification"),
            "shfmt": ("3.14.1", "rocky-10.2-admin-qualification"),
            "kube-bench": ("0.16.0", "rocky-10.2-rke2"),
        }
        for name, (version, scope) in expected.items():
            tool = self.toolchain["tools"][name]
            self.assertEqual(self.toolchain["versions"][tool["version_ref"]], version)
            self.assertEqual(tool["architecture"], "amd64")
            self.assertIn(scope, tool["scope"])
            self.assertRegex(
                self.toolchain["versions"][tool["sha256_ref"]],
                r"^[0-9a-f]{64}$",
            )
        gh = self.toolchain["tools"]["gh"]
        self.assertEqual(gh["artifact"]["filename"], "gh_2.101.0_linux_amd64.rpm")
        self.assertEqual(
            self.toolchain["versions"][gh["sha256_ref"]],
            "72ef6dcd0ee459645cda485f2e55f18eca7b9252fce85a3be4c2446ae7627f36",
        )
        self.assertEqual(
            gh["qualification"]["stdout_contains"], ["--paginate", "--slurp"]
        )
        self.assertEqual(gh["qualification"]["network"], "forbidden")

    def test_oras_and_rsync_are_exact_distribution_tools(self):
        distribution = self.image["distribution"]
        self.assertEqual("oras", distribution["authority"])
        self.assertEqual("harbor", distribution["registry"])
        self.assertEqual(
            {
                "ca_file_environment": "ORAS_CA_FILE",
                "registry_config_environment": "ORAS_REGISTRY_CONFIG",
                "insecure_skip_verify": "forbidden",
            },
            distribution["runtime_tls"],
        )
        self.assertEqual("ORAS_CACHE", distribution["cache"]["environment"])
        self.assertEqual("rsync", distribution["cache"]["synchronization"])
        self.assertEqual(
            "sha256-before-and-after-sync", distribution["cache"]["integrity"]
        )
        self.assertIn("published-exact-source-sha", distribution["push"]["requires"])
        self.assertEqual("forbidden", distribution["pull"]["mutable_tag"])
        expected = {
            "oras": (
                "1.3.3",
                "9ce999f8d2de03fc03968b29d743077a58783e545e5eaa53917ca177352d0e59",
            ),
            "rsync": (
                "3.2.7",
                "8f952895697d19a6f1caa71f17c7d4e8c1f1fb485eb824ffe3e4c77dd587b338",
            ),
        }
        for name, (version, checksum) in expected.items():
            tool = self.toolchain["tools"][name]
            lifecycle = self.toolchain["tool_lifecycle"]["active"][name]
            self.assertEqual(version, self.toolchain["versions"][tool["version_ref"]])
            self.assertEqual(checksum, self.toolchain["versions"][tool["sha256_ref"]])
            self.assertEqual("required", lifecycle["scenario_policy"])
            self.assertIn("tests/test_packer_image_contract.py", lifecycle["proofs"])
        self.assertEqual(
            "3.2.7-1ubuntu1.5",
            self.toolchain["versions"][
                self.toolchain["tools"]["rsync"]["artifact"]["package_version_ref"]
            ],
        )

    def test_oras_references_are_fail_closed(self):
        repository = "harbor.example.com:443/machine-images/rocky"
        self.assertEqual(repository, REPOCTL._validate_oras_repository(repository))
        digest = "sha256:" + ("a" * 64)
        self.assertEqual(
            (repository, digest),
            REPOCTL._validate_oras_digest_reference(f"{repository}@{digest}"),
        )
        for invalid in (
            "https://harbor.example.com/machine-images/rocky",
            "harbor.example.com/machine-images/rocky:latest",
            "harbor.example.com/machine-images/rocky@sha256:" + ("A" * 64),
            "harbor.example.com/machine-images/rocky:git-deadbeef",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(RuntimeError):
                REPOCTL._validate_oras_digest_reference(invalid)

    def test_oras_cache_sync_is_sha256_verified_and_non_destructive(self):
        self.assertIn('environment["ORAS_CACHE"] = str(cache)', self.repoctl)
        for flag in ("--archive", "--checksum", "--partial", "--delay-updates"):
            self.assertIn(f'"{flag}"', self.repoctl)
        self.assertNotIn('"--delete"', self.repoctl)
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "rocky.box"
            artifact.write_bytes(b"exact machine image")
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            checksums = Path(directory) / "SHA256SUMS"
            checksums.write_text(f"{digest}  rocky.box\n", encoding="utf-8")
            self.assertEqual(
                digest, REPOCTL._verified_artifact_sha256(artifact, checksums)
            )
            cache = Path(directory) / "cache"
            cache.mkdir()
            sentinel = cache / "preserved.txt"
            sentinel.write_text("preserve", encoding="utf-8")
            synced_artifact, synced_checksums, synced_digest = (
                REPOCTL._rsync_artifact_pair(
                    artifact, checksums, cache, timeout_seconds=30
                )
            )
            self.assertEqual(digest, synced_digest)
            self.assertEqual(digest, REPOCTL._file_sha256(synced_artifact))
            self.assertEqual(
                digest,
                REPOCTL._verified_artifact_sha256(
                    synced_artifact, synced_checksums
                ),
            )
            self.assertTrue(sentinel.is_file())
            artifact.write_bytes(b"tampered")
            with self.assertRaisesRegex(RuntimeError, "SHA-256 mismatch"):
                REPOCTL._verified_artifact_sha256(artifact, checksums)
            checksums.write_bytes(b"x" * 4097)
            with self.assertRaisesRegex(RuntimeError, "4096-byte safety limit"):
                REPOCTL._verified_artifact_sha256(artifact, checksums)

    def test_oras_runtime_tls_arguments_are_explicit_and_secret_config_is_private(self):
        distribution = self.image["distribution"]
        with tempfile.TemporaryDirectory() as directory:
            ca = Path(directory) / "ca.pem"
            config = Path(directory) / "config.json"
            ca.write_text("runtime CA", encoding="utf-8")
            config.write_text("{}", encoding="utf-8")
            config.chmod(0o600)
            with mock.patch.dict(
                os.environ,
                {"ORAS_CA_FILE": str(ca), "ORAS_REGISTRY_CONFIG": str(config)},
                clear=False,
            ):
                self.assertEqual(
                    ["--ca-file", str(ca), "--registry-config", str(config)],
                    REPOCTL._oras_runtime_arguments(distribution),
                )
            config.chmod(0o644)
            with mock.patch.dict(os.environ, {"ORAS_REGISTRY_CONFIG": str(config)}, clear=False):
                with self.assertRaisesRegex(RuntimeError, "group/world accessible"):
                    REPOCTL._oras_runtime_arguments(distribution)
            config.chmod(0o600)
            link = Path(directory) / "config-link.json"
            link.symlink_to(config)
            with mock.patch.dict(os.environ, {"ORAS_REGISTRY_CONFIG": str(link)}, clear=False):
                with self.assertRaisesRegex(RuntimeError, "non-symlink"):
                    REPOCTL._oras_runtime_arguments(distribution)

    def test_oras_make_entrypoints_are_explicit(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn("image-rocky-oras-push:", makefile)
        self.assertIn("image-rocky-oras-pull:", makefile)
        self.assertIn("ORAS_REPOSITORY", makefile)
        self.assertIn("ORAS_REF", makefile)

    def test_packer_plugins_profiles_and_outputs_are_exact(self):
        expected = {"virtualbox": "1.1.5", "qemu": "1.1.6", "vagrant": "1.1.7"}
        for plugin, version in expected.items():
            block = re.search(
                rf"{plugin}\s*=\s*\{{(?P<body>.*?)\n\s*\}}", self.packer, re.DOTALL
            )
            self.assertIsNotNone(block)
            self.assertIn(f'version = "= {version}"', block.group("body"))
        self.assertIn(
            'contains(["rke2", "admin-qualification"], var.image_profile)', self.packer
        )
        self.assertIn("${local.image_name}-virtualbox.box", self.packer)
        self.assertIn("${local.image_name}-kvm", self.packer)
        self.assertIn('"c<wait5>"', self.packer)
        self.assertIn(
            "linux /images/pxeboot/vmlinuz "
            "inst.stage2=hd:LABEL=Rocky-10-2-x86_64-dvd inst.text inst.ks=http://",
            self.packer,
        )
        self.assertIn("initrd /images/pxeboot/initrd.img<enter>", self.packer)
        self.assertIn('"boot<enter>"', self.packer)
        self.assertNotIn("<tab>", self.packer)
        self.assertIn('boot_keygroup_interval = "500ms"', self.packer)

    def test_virtualbox_requires_native_vtx_and_is_observable(self):
        acceleration = self.image["build"]["virtualbox"]["acceleration"]
        self.assertEqual(
            {
                "required": "native-vtx",
                "forbidden": ["nem"],
                "hyper_v_present": False,
            },
            acceleration,
        )
        self.assertNotIn("virtualbox_kernel_arguments", self.packer)
        self.assertEqual(
            "virtio", self.image["hypervisors"]["virtualbox"]["network_adapter"]
        )
        self.assertIn("nic_type               = var.vm_virtualbox_nic_type", self.packer)
        self.assertIn('bootloader_kernel_arguments = "quiet console=tty0"', self.packer)
        self.assertIn("--uartmode1", self.packer)
        self.assertIn("virtualbox_serial_log_file", self.packer)
        for index in range(3, 13):
            self.assertIn(f"ECOMMERCE_MILESTONE T{index}_", self.packer + self.kickstart)

    def test_packer_build_is_offline_and_profile_separated(self):
        self.assertIn("install -d -m 0700 /tmp/packer-offline", self.packer)
        for relative in ("rpm-keys", "rpms", "tools", "install_tools.py"):
            self.assertIn(f"${{var.offline_bundle_dir}}/{relative}", self.packer)
        self.assertNotIn("${var.offline_bundle_dir}/iso", self.packer)
        self.assertNotIn("source      = var.offline_bundle_dir", self.packer)
        self.assertIn("sha256sum --check SHA256SUMS", self.packer)
        self.assertIn("--disablerepo='*'", self.packer)
        self.assertNotIn("curl ", self.packer)
        self.assertNotIn("wget ", self.packer)
        self.assertNotIn("releases/download", self.packer)
        self.assertIn("PACKER_BUILDER_TYPE", self.packer)
        self.assertIn("qemu-guest-agent; else ! rpm -q qemu-guest-agent", self.packer)
        self.assertIn("--profile admin-qualification", self.packer)
        self.assertIn("--profile rke2", self.packer)
        self.assertIn("--rpm-profile rke2", self.packer)
        self.assertIn("oscap --version", self.packer)
        self.assertIn("ssg-rl10-ds.xml", self.packer)
        self.assertIn("kube-bench version", self.packer)
        for version in ("15.2.0", "10.4.2", "4.53.6", "2.101.0", "3.14.1"):
            self.assertNotIn(version, self.packer)

    def test_build_credentials_are_runtime_injected_and_removed(self):
        credential = self.image["build"]["credential"]
        self.assertEqual("runtime-injected-temporary-ssh-key", credential["type"])
        self.assertEqual("forbidden", credential["committed_private_key"])
        self.assertEqual("forbidden", credential["committed_password_or_hash"])
        self.assertEqual("forbidden", credential["password_authentication"])
        self.assertEqual(
            "host-local-outside-repository",
            credential["private_key_storage"],
        )
        self.assertEqual("required", credential["private_key_cleanup_after_qualification"])
        self.assertEqual("forbidden", credential["released_artifact_private_key_exists"])
        self.assertNotIn("build_password", self.packer)
        self.assertNotIn("ssh_password", self.packer)
        self.assertIn("ssh_private_key_file", self.packer)
        self.assertIn("build_ssh_public_key", self.packer)
        self.assertIn(
            'sshkey --username=packer "${build_ssh_public_key}"', self.kickstart
        )
        self.assertIn("user --name=packer --groups=wheel --lock", self.kickstart)
        self.assertNotRegex(self.kickstart, r"\$[156]\$")
        self.assertIn("PasswordAuthentication no", self.kickstart)
        self.assertIn("passwd --status packer", self.packer)
        self.assertIn("test -s /home/packer/.ssh/authorized_keys", self.packer)
        self.assertNotIn("/home/packer/.ssh/id_", self.packer)

    def test_rke2_profile_excludes_admin_tools_and_credentials(self):
        forbidden = set(self.image["profiles"]["rke2"]["forbidden_tools"])
        self.assertEqual(
            forbidden,
            {"gh", "git", "strace", "sysstat", "mtr", "shellcheck", "shfmt"},
        )
        self.assertIn("! command -v gh", self.packer)
        self.assertIn("/root/.config/gh/hosts.yml", self.packer)
        self.assertIn("GH_TOKEN|GITHUB_TOKEN", self.packer)
        for tool in forbidden:
            self.assertNotIn(tool, self.kickstart.lower())

    def test_image_hardening_and_kubernetes_baseline_are_executable(self):
        expected_kickstart = (
            "selinux --enforcing",
            "firewall --disabled",
            "-firewalld",
            "kernel-modules-extra",
            "swapoff -a",
            "net.ipv4.ip_forward = 1",
            "overlay",
            "br_netfilter",
            "nf_conntrack",
            "vxlan",
            "NetworkManager",
            "chronyd",
            "sshd",
            "/etc/sysctl.d/90-kubernetes.conf",
            "/etc/modules-load.d/kubernetes.conf",
        )
        for value in expected_kickstart:
            self.assertIn(value, self.kickstart)
        for value in (
            "truncate -s 0 /etc/machine-id",
            "rm -f /var/lib/dbus/machine-id /etc/ssh/ssh_host_*",
            "PasswordAuthentication no",
            "hostnamectl set-hostname rocky-10-2-base",
            "cgroup2fs",
            "grep -qw bpf /proc/filesystems",
            "net.bridge.bridge-nf-call-iptables",
            "fs.inotify.max_user_instances",
        ):
            self.assertIn(value, self.packer)
        self.assertNotIn("qemu-guest-agent", self.kickstart)

    def test_storage_layout_is_explicit_and_has_no_lvm_or_swap_partition(self):
        for expected in (
            "clearpart --all --initlabel --disklabel=${partition_table}",
            "part biosboot --size=${bios_boot_mib}",
            "part /boot --fstype=${root_filesystem} --size=${boot_mib}",
            "part / --fstype=${root_filesystem} --size=${root_min_mib} --grow",
        ):
            self.assertIn(expected, self.kickstart)
        for forbidden in ("autopart", "volgroup", "logvol", "part swap"):
            self.assertNotIn(forbidden, self.kickstart)

    def test_packer_owns_only_stable_os_prerequisites(self):
        packer_tree = self.packer + "\n" + self.kickstart
        for forbidden in ("rke2-token", "cluster-init", "cilium", "haproxy"):
            self.assertNotIn(forbidden, packer_tree.lower())
        self.assertEqual(
            self.contract["rules"]["packer_may_invoke_ansible"], "forbidden"
        )
        self.assertNotIn("Rocky-10.2-x86_64-dvd1.iso", self.packer)

    def test_rke2_selinux_stays_in_bundle_and_runtime_config(self):
        bundle = json.loads(
            (
                ROOT / "config/artifacts/mgmt-rke2-offline-v1.37.0-rke2r1.lock.json"
            ).read_text()
        )
        packages = {entry["package"] for entry in bundle["rpms"]}
        self.assertIn("rke2-selinux", packages)
        for template in ("rke2_server", "rke2_agent"):
            text = (
                ROOT / f"platform/ansible/roles/{template}/templates/config.yaml.j2"
            ).read_text()
            self.assertIn("selinux: true", text)

    def test_generators_and_installer_are_python_not_shell(self):
        self.assertTrue(GENERATOR.is_file())
        mgmt_generator = (ROOT / "scripts/generate_mgmt_rpm_lock.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("image-package-lock", mgmt_generator)
        self.assertNotIn("write_image_package_lock", mgmt_generator)
        installer = INSTALLER.read_text(encoding="utf-8")
        self.assertIn('"--disablerepo=*"', installer)
        self.assertNotIn("urllib", installer)


if __name__ == "__main__":
    unittest.main()
