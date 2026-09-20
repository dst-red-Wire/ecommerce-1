"""Offline bootstrap contract tests; these do not claim a six-node cold installation."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('mgmt_airgap', ROOT / 'scripts/mgmt_airgap.py')
AIRGAP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AIRGAP)
VERSION = 'v1.37.0+rke2r1'


class OfflineBundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.bundle = Path(self.temp.name)
        self.entries = []
        self.signer_fingerprint = "0123456789abcdef0123456789abcdefdeadbeef"
        key_name = "rocky-rpm-signing-key.asc"
        (self.bundle / key_name).write_text("fixture approved RPM signing key")
        self.entry("rpm-signing-key", key_name, fingerprint=self.signer_fingerprint)
        for category, name in AIRGAP.REQUIRED_ARTIFACTS.items():
            if category.startswith('images-'):
                self.archive(name)
            else:
                (self.bundle / name).write_bytes(b'pinned fixture binary')
            self.entry(category, name)
        for package in sorted(AIRGAP.REQUIRED_RPMS):
            name = package + '-1-1.x86_64.rpm'
            (self.bundle / name).write_bytes(b'fixture RPM: ' + package.encode())
            self.entry('rpm', name, package=package, nevra=package + '-0:1-1.x86_64',
                       signer_fingerprint=self.signer_fingerprint)
        image_inventory = {
            category: AIRGAP.validate_image_archive(self.bundle / name)
            for category, name in AIRGAP.REQUIRED_ARTIFACTS.items()
            if category.startswith('images-')
        }
        self.manifest = {
            'schema_version': 1,
            'rke2_version': VERSION,
            'os': 'rocky-9',
            'architecture': 'amd64',
            'rpm_dependency_closure': 'complete',
            'image_inventory': {'rke2_version': VERSION, 'archives': image_inventory},
            'artifacts': self.entries,
        }

    def archive(self, filename, member='manifest.json', kind=tarfile.REGTYPE, tag='docker.io/test/image:v1.0.0'):
        with tarfile.open(self.bundle / filename, 'w') as archive:
            info = tarfile.TarInfo(member)
            info.type = kind
            info.linkname = '/etc/shadow' if kind == tarfile.SYMTYPE else ''
            body = json.dumps([{"RepoTags": [tag], "Config": "config.json", "Layers": ["layer.tar"]}]).encode()
            info.size = len(body) if kind == tarfile.REGTYPE else 0
            archive.addfile(info, io.BytesIO(body) if info.size else None)
            for component_name in ('config.json', 'layer.tar'):
                component = tarfile.TarInfo(component_name)
                component.size = 2
                archive.addfile(component, io.BytesIO(b'{}'))

    def oci_archive(self, filename, corrupt_layer=False):
        config = b'{"architecture":"amd64"}'
        good_layer = b"verified-layer"
        stored_layer = b"tampered-layer" if corrupt_layer else good_layer

        def descriptor(body):
            return {
                "mediaType": "application/octet-stream",
                "digest": "sha256:" + hashlib.sha256(body).hexdigest(),
                "size": len(body),
            }

        config_descriptor = descriptor(config)
        layer_descriptor = descriptor(good_layer)
        manifest = json.dumps({
            "schemaVersion": 2,
            "config": config_descriptor,
            "layers": [layer_descriptor],
        }, sort_keys=True, separators=(",", ":")).encode()
        manifest_descriptor = {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": "sha256:" + hashlib.sha256(manifest).hexdigest(),
            "size": len(manifest),
        }
        index = json.dumps({"schemaVersion": 2, "manifests": [manifest_descriptor]},
                           sort_keys=True, separators=(",", ":")).encode()
        members = {
            "index.json": index,
            "blobs/sha256/" + manifest_descriptor["digest"].split(":", 1)[1]: manifest,
            "blobs/sha256/" + config_descriptor["digest"].split(":", 1)[1]: config,
            "blobs/sha256/" + layer_descriptor["digest"].split(":", 1)[1]: stored_layer,
        }
        with tarfile.open(self.bundle / filename, "w") as archive:
            for name, body in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(body)
                archive.addfile(info, io.BytesIO(body))
        return manifest_descriptor["digest"]

    def filtered_multiarch_oci_archive(self, filename, include_target=True):
        config = b'{"architecture":"amd64","os":"linux"}'
        layer = b"verified-amd64-layer"

        def descriptor(body, media_type="application/octet-stream", platform=None):
            result = {
                "mediaType": media_type,
                "digest": "sha256:" + hashlib.sha256(body).hexdigest(),
                "size": len(body),
            }
            if platform is not None:
                result["platform"] = platform
            return result

        config_descriptor = descriptor(config)
        layer_descriptor = descriptor(layer)
        target_manifest = json.dumps({
            "schemaVersion": 2,
            "config": config_descriptor,
            "layers": [layer_descriptor],
        }, sort_keys=True, separators=(",", ":")).encode()
        target_descriptor = descriptor(
            target_manifest,
            "application/vnd.oci.image.manifest.v1+json",
            {"os": "linux", "architecture": "amd64"},
        )
        absent_manifest = b'{"schemaVersion":2,"architecture":"arm64"}'
        absent_descriptor = descriptor(
            absent_manifest,
            "application/vnd.oci.image.manifest.v1+json",
            {"os": "linux", "architecture": "arm64"},
        )
        children = [absent_descriptor]
        if include_target:
            children.insert(0, target_descriptor)
        image_index = json.dumps({"schemaVersion": 2, "manifests": children},
                                 sort_keys=True, separators=(",", ":")).encode()
        image_descriptor = descriptor(
            image_index, "application/vnd.oci.image.index.v1+json")
        index = json.dumps({"schemaVersion": 2, "manifests": [image_descriptor]},
                           sort_keys=True, separators=(",", ":")).encode()
        members = {
            "index.json": index,
            "blobs/sha256/" + image_descriptor["digest"].split(":", 1)[1]: image_index,
            "blobs/sha256/" + config_descriptor["digest"].split(":", 1)[1]: config,
            "blobs/sha256/" + layer_descriptor["digest"].split(":", 1)[1]: layer,
        }
        if include_target:
            members["blobs/sha256/" + target_descriptor["digest"].split(":", 1)[1]] = target_manifest
        with tarfile.open(self.bundle / filename, "w") as archive:
            for name, body in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(body)
                archive.addfile(info, io.BytesIO(body))
        return image_descriptor["digest"]

    def entry(self, category, name, **extra):
        self.entries.append(dict(category=category, file=name, sha256=AIRGAP.digest(self.bundle / name), **extra))

    def seal(self):
        path = self.bundle / 'manifest.json'
        path.write_text(json.dumps(self.manifest, sort_keys=True))
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def validate(self):
        return AIRGAP.validate_bundle(self.bundle, self.seal(), VERSION)

    def test_complete_fixture_bundle_is_accepted_without_network(self):
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            result = self.validate()
        self.assertEqual(len(result['rpms']), len(AIRGAP.REQUIRED_RPMS))

    def test_archive_identities_must_match_approved_release_inventory(self):
        entry = next(entry for entry in self.entries if entry['category'] == 'images-core')
        self.archive(entry['file'], tag='docker.io/test/other:v2.0.0')
        entry['sha256'] = AIRGAP.digest(self.bundle / entry['file'])
        with self.assertRaisesRegex(ValueError, 'identit'):
            self.validate()

    def test_manifest_requires_independent_digest_approval(self):
        self.seal()
        with self.assertRaisesRegex(ValueError, 'differs from approval'):
            AIRGAP.validate_bundle(self.bundle, '0' * 64, VERSION)

    def test_modified_artifact_fails_even_when_manifest_is_approved(self):
        (self.bundle / 'rke2.linux-amd64').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'integrity'):
            self.validate()

    def test_missing_or_extra_file_fails(self):
        path = self.bundle / 'rke2.linux-amd64'
        original = path.read_bytes()
        path.unlink()
        with self.assertRaisesRegex(ValueError, 'required bundle member missing'):
            self.validate()
        path.write_bytes(original)
        (self.bundle / 'unexpected').write_text('extra')
        with self.assertRaisesRegex(ValueError, 'unlisted'):
            self.validate()

    def test_symlink_to_matching_external_artifact_fails(self):
        path = self.bundle / 'rke2.linux-amd64'
        original = path.read_bytes()
        path.unlink()
        with tempfile.NamedTemporaryFile() as external:
            Path(external.name).write_bytes(original)
            path.symlink_to(external.name)
            with self.assertRaisesRegex(ValueError, 'regular'):
                self.validate()

    def test_unlisted_executable_or_unknown_category_cannot_enter_install_plan(self):
        (self.bundle / 'unapproved-executable').write_bytes(b'#!/bin/sh\nexit 0\n')
        with self.assertRaisesRegex(ValueError, 'unlisted'):
            self.validate()
        self.entry('installer', 'unapproved-executable')
        with self.assertRaisesRegex(ValueError, 'unexpected artifact'):
            self.validate()

    def test_missing_cilium_archive_fails(self):
        self.entries[:] = [entry for entry in self.entries if entry['category'] != 'images-cilium']
        (self.bundle / AIRGAP.REQUIRED_ARTIFACTS['images-cilium']).unlink()
        with self.assertRaisesRegex(ValueError, 'core/Cilium'):
            self.validate()

    def test_preserve_minimal_curl_without_package_erasure(self):
        entry = next(entry for entry in self.entries if entry.get('package') == 'curl')
        (self.bundle / entry['file']).rename(self.bundle / 'curl-minimal-1-1.x86_64.rpm')
        entry.update(file='curl-minimal-1-1.x86_64.rpm', package='curl-minimal', nevra='curl-minimal-0:1-1.x86_64')
        result = self.validate()
        self.assertEqual(result['curl_package'], 'curl-minimal')

    def test_conflicting_full_and_minimal_packages_fail_before_transaction(self):
        for full, minimal in (('curl', 'curl-minimal'), ('libcurl', 'libcurl-minimal'),
                              ('coreutils', 'coreutils-single')):
            with self.subTest(packages=(full, minimal)):
                entries = list(self.entries)
                for package in (full, minimal):
                    if any(entry.get('package') == package for entry in self.entries):
                        continue
                    name = package + '-1-1.x86_64.rpm'
                    (self.bundle / name).write_bytes(b'variant fixture')
                    self.entry('rpm', name, package=package, nevra=package + '-0:1-1.x86_64',
                       signer_fingerprint=self.signer_fingerprint)
                with self.assertRaisesRegex(ValueError, 'conflicting minimal and full'):
                    self.validate()
                for entry in self.entries[len(entries):]:
                    (self.bundle / entry['file']).unlink()
                self.entries[:] = entries

    def test_missing_selinux_dependency_fails(self):
        self.entries[:] = [entry for entry in self.entries if entry.get('package') != 'container-selinux']
        (self.bundle / 'container-selinux-1-1.x86_64.rpm').unlink()
        with self.assertRaisesRegex(ValueError, 'SELinux'):
            self.validate()

    def test_unpinned_or_mismatched_version_fails(self):
        for version in ('latest', 'v1.36.0+rke2r1'):
            self.manifest['rke2_version'] = version
            with self.assertRaisesRegex(ValueError, 'canonical pin'):
                self.validate()

    def test_filename_traversal_and_duplicate_records_fail(self):
        target = next(entry for entry in self.entries if entry['category'] == 'binary')
        target['file'] = '../rke2.linux-amd64'
        with self.assertRaisesRegex(ValueError, 'unsafe or duplicate'):
            self.validate()
        target['file'] = 'rke2.linux-amd64'
        self.entries.append(dict(target))
        with self.assertRaisesRegex(ValueError, 'unsafe or duplicate'):
            self.validate()

    def test_archive_traversal_absolute_paths_and_links_fail(self):
        entry = next(entry for entry in self.entries if entry['category'] == 'images-core')
        for member, kind in (('../escape', tarfile.REGTYPE), ('/etc/shadow', tarfile.REGTYPE),
                             ('link', tarfile.SYMTYPE), ('dev', tarfile.CHRTYPE)):
            with self.subTest(member=member):
                self.archive(entry['file'], member, kind)
                entry['sha256'] = AIRGAP.digest(self.bundle / entry['file'])
                with self.assertRaisesRegex(ValueError, 'unsafe|forbidden'):
                    self.validate()

    def test_image_archive_requires_manifest(self):
        entry = next(entry for entry in self.entries if entry['category'] == 'images-core')
        self.archive(entry['file'], 'random-file')
        entry['sha256'] = AIRGAP.digest(self.bundle / entry['file'])
        with self.assertRaisesRegex(ValueError, 'lacks'):
            self.validate()

    def test_empty_or_unpinned_image_inventory_fails(self):
        entry = next(entry for entry in self.entries if entry['category'] == 'images-core')
        for body in (b'[]', b'[{"RepoTags":["docker.io/test/image:latest"],"Config":"config.json","Layers":["layer.tar"]}]'):
            with self.subTest(body=body):
                with tarfile.open(self.bundle / entry['file'], 'w') as archive:
                    info = tarfile.TarInfo('manifest.json')
                    info.size = len(body)
                    archive.addfile(info, io.BytesIO(body))
                entry['sha256'] = AIRGAP.digest(self.bundle / entry['file'])
                with self.assertRaisesRegex(ValueError, 'empty|unpinned'):
                    self.validate()

    def test_oci_descriptor_digest_and_size_are_verified_recursively(self):
        entry = next(entry for entry in self.entries if entry['category'] == 'images-core')
        identity = self.oci_archive(entry['file'], corrupt_layer=True)
        entry['sha256'] = AIRGAP.digest(self.bundle / entry['file'])
        self.manifest['image_inventory']['archives']['images-core'] = [identity]
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            self.validate()

    def test_filtered_oci_archive_allows_only_explicit_non_target_blobs_to_be_absent(self):
        entry = next(entry for entry in self.entries if entry['category'] == 'images-core')
        identity = self.filtered_multiarch_oci_archive(entry['file'])
        entry['sha256'] = AIRGAP.digest(self.bundle / entry['file'])
        self.manifest['image_inventory']['archives']['images-core'] = [identity]
        self.validate()

        identity = self.filtered_multiarch_oci_archive(entry['file'], include_target=False)
        entry['sha256'] = AIRGAP.digest(self.bundle / entry['file'])
        self.manifest['image_inventory']['archives']['images-core'] = [identity]
        with self.assertRaisesRegex(ValueError, 'target platform'):
            self.validate()

    def test_manifest_referencing_missing_image_content_fails(self):
        entry = next(entry for entry in self.entries if entry['category'] == 'images-core')
        with tarfile.open(self.bundle / entry['file'], 'w') as archive:
            body = b'[{"RepoTags":["test:v1"],"Config":"absent.json","Layers":["absent.tar"]}]'
            info = tarfile.TarInfo('manifest.json')
            info.size = len(body)
            archive.addfile(info, io.BytesIO(body))
        entry['sha256'] = AIRGAP.digest(self.bundle / entry['file'])
        with self.assertRaisesRegex(ValueError, 'referenced content missing'):
            self.validate()

    def test_dns_ntp_must_be_explicit_internal_ips(self):
        AIRGAP.validate_services(['10.243.1.2'], ['10.243.1.3'])
        for bad in ([], ['8.8.8.8'], ['pool.ntp.org'], ['::1'], ['10.243.1.1\nserver attacker']):
            with self.subTest(value=bad), self.assertRaises(ValueError):
                AIRGAP.validate_services(bad, ['10.243.1.3'])
            with self.subTest(value=bad), self.assertRaises(ValueError):
                AIRGAP.validate_services(['10.243.1.2'], bad)

    def test_unsigned_rpm_digest_success_is_not_signature_success(self):
        digest = self.seal()
        with patch.object(AIRGAP.subprocess, 'run') as command:
            command.return_value.stdout = 'fixture.rpm: digests OK'
            with self.assertRaisesRegex(ValueError, 'signature'):
                AIRGAP.validate_bundle(self.bundle, digest, VERSION, rpm_signatures=True)

    def test_rpm_signature_is_bound_to_manifest_signer_in_isolated_trust(self):
        digest = self.seal()

        def run(argv, **_kwargs):
            if '--checksig' in argv:
                return SimpleNamespace(stdout='Header V4 RSA/SHA256 Signature, key ID badc0ffe: OK')
            return SimpleNamespace(stdout='')

        with (
            patch.object(AIRGAP.subprocess, 'run', side_effect=run),
            self.assertRaisesRegex(ValueError, 'approved fingerprint'),
        ):
            AIRGAP.validate_bundle(self.bundle, digest, VERSION, rpm_signatures=True)

    def test_root_signature_check_uses_selinux_labeled_isolated_rpm_database(self):
        digest = self.seal()
        with tempfile.TemporaryDirectory() as rpmdb:
            manager = MagicMock()
            manager.__enter__.return_value = rpmdb
            manager.__exit__.return_value = False

            def run(argv, **_kwargs):
                if '--checksig' in argv:
                    return SimpleNamespace(
                        stdout='Header V4 RSA/SHA256 Signature, key ID deadbeef: OK')
                return SimpleNamespace(stdout='')

            with (
                patch.object(AIRGAP.os, 'geteuid', return_value=0),
                patch.object(AIRGAP.Path, 'is_dir', return_value=True),
                patch.object(AIRGAP.tempfile, 'TemporaryDirectory', return_value=manager) as temporary,
                patch.object(AIRGAP.subprocess, 'run', side_effect=run),
            ):
                AIRGAP.validate_bundle(self.bundle, digest, VERSION, rpm_signatures=True)
        temporary.assert_called_once_with(prefix='ecommerce-rpmdb-', dir='/var/lib/rpm')

    def test_rpm_nevra_must_match_real_metadata_before_install(self):
        digest = self.seal()
        with patch.object(AIRGAP.subprocess, 'run') as command:
            command.return_value.stdout = 'wrong-package-0:1-1.x86_64'
            with self.assertRaisesRegex(ValueError, 'NEVRA'):
                AIRGAP.validate_bundle(self.bundle, digest, VERSION, rpm_metadata=True)

    def test_rpm_actual_architecture_must_match_amd64_target(self):
        target = next(entry for entry in self.entries if entry.get('category') == 'rpm')
        target['nevra'] = target['nevra'].rsplit('.', 1)[0] + '.aarch64'
        digest = self.seal()
        with self.assertRaisesRegex(ValueError, 'architecture'):
            AIRGAP.validate_bundle(self.bundle, digest, VERSION)


class OfflineAnsibleContractTests(unittest.TestCase):
    def test_bootstrap_installs_offline_dependencies_before_other_roles(self):
        play = (ROOT / 'platform/ansible/mgmt.yml').read_text()
        self.assertLess(play.index('name: mgmt_offline_artifacts'), play.index('name: rocky_baseline'))
        self.assertLess(play.index('name: mgmt_private_network'), play.index('name: rke2_server'))
        role = (ROOT / 'platform/ansible/roles/mgmt_offline_artifacts/tasks/main.yml').read_text()
        self.assertLess(role.index('Validate controller bundle'), role.index('Create digest-specific node artifact directory'))
        self.assertLess(role.index('Validate controller bundle'), role.index('Transfer approved bundle'))
        self.assertLess(role.index('Verify transferred bytes'), role.index('Install complete local RPM set'))
        self.assertLess(role.index('Verify every local RPM signature'), role.index('Install complete local RPM set'))
        self.assertIn("disablerepo: '*'", role)
        self.assertIn('disable_gpg_check: false', role)
        self.assertIn('mgmt_offline_selinux.stdout != \'Enforcing\'', role)

    def test_both_rke2_roles_refuse_downloads_and_registry_fallback(self):
        for role in ('rke2_server', 'rke2_agent'):
            directory = ROOT / 'platform/ansible/roles' / role
            tasks = (directory / 'tasks/main.yml').read_text()
            self.assertNotIn('get_url', tasks)
            self.assertNotIn('get.rke2.io', tasks)
            self.assertIn('mgmt_offline_artifacts_verified', tasks)
            self.assertIn('ecommerce_mgmt_bootstrap', tasks)
            self.assertIn('Requires=ecommerce-mgmt-egress.service', tasks)
            self.assertIn('After=network-online.target ecommerce-mgmt-egress.service', tasks)
            config = (directory / 'templates/config.yaml.j2').read_text()
            self.assertIn('disable-default-registry-endpoint: true', config)
            self.assertIn('selinux: true', config)
        registry = (ROOT / 'platform/ansible/roles/mgmt_offline_artifacts/tasks/main.yml').read_text()
        self.assertIn('"*":', registry)
        self.assertIn('https://127.0.0.1:1', registry)

    def test_rke2_server_flushes_handlers_and_bounds_notify_readiness(self):
        tasks = (ROOT / 'platform/ansible/roles/rke2_server/tasks/main.yml').read_text()
        enable = tasks.index('- name: Enable RKE2 server')
        flush = tasks.index('- name: Apply pending RKE2 restart handlers')
        readiness = tasks.index('- name: Wait boundedly for the native RKE2 service readiness')
        self.assertLess(enable, flush)
        self.assertLess(flush, readiness)
        self.assertIn('no_block: true', tasks[enable:flush])
        self.assertIn('until:', tasks[readiness:])
        self.assertIn('retries:', tasks[readiness:])


if __name__ == '__main__':
    unittest.main()
