"""Simulated command tests for the post-merge image publisher.

These tests validate fail-closed orchestration; they are not runtime evidence.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import unittest
from pathlib import Path

from scripts import runner_image as image

ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 40
EXPECTED = "sha256:" + "b" * 64
OTHER = "sha256:" + "c" * 64


class FakeExecutor:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []
        self.sources = {path: (ROOT / path).read_bytes() for path in image.SOURCE_PATHS}
        self.branch = "main"
        self.dirty = False
        self.github_shas = [SHA]
        self.github_reads = 0
        self.registry_digest = EXPECTED
        self.pulled_digest = EXPECTED
        self.build_context_paths: set[str] | None = None

    def done(self, command: list[str], output: bytes = b"", code: int = 0):
        return subprocess.CompletedProcess(command, code, stdout=output, stderr=b"")

    def __call__(self, command: list[str], cwd: Path | None, timeout: int):
        self.commands.append(command)
        if command[0] == "git":
            if command[-2:] == ["rev-parse", "--show-toplevel"]:
                return self.done(command, f"{ROOT}\n".encode())
            if command[-4:] == ["symbolic-ref", "--quiet", "--short", "HEAD"]:
                return self.done(command, (self.branch + "\n").encode())
            if command[-3:] == ["remote", "get-url", "origin"]:
                return self.done(command, (image.ORIGIN_URL + "\n").encode())
            if command[-3:] == ["status", "--porcelain=v1", "--untracked-files=all"]:
                return self.done(command, b" M dirty\n" if self.dirty else b"")
            if command[-2:] == ["rev-parse", "HEAD"]:
                return self.done(command, (SHA + "\n").encode())
            if command[-2:] == ["rev-parse", "refs/remotes/origin/main"]:
                return self.done(command, (SHA + "\n").encode())
            if command[-3:] == ["ls-remote", "origin", "refs/heads/main"]:
                return self.done(command, f"{SHA}\trefs/heads/main\n".encode())
            if "ls-tree" in command:
                path = command[-1]
                self.assert_source(path)
                return self.done(
                    command,
                    f"100644 blob {'d' * 40}\t{path}\n".encode(),
                )
            if command[-2] == "show":
                requested_sha, path = command[-1].split(":", 1)
                if requested_sha != SHA:
                    raise AssertionError("unapproved git show SHA")
                self.assert_source(path)
                return self.done(command, self.sources[path])
        if command[:2] == ["gh", "api"]:
            index = min(self.github_reads, len(self.github_shas) - 1)
            self.github_reads += 1
            payload = {
                "ref": "refs/heads/main",
                "object": {"type": "commit", "sha": self.github_shas[index]},
            }
            return self.done(command, json.dumps(payload).encode())
        if command[:4] == ["docker", "buildx", "imagetools", "inspect"]:
            digest = (
                image.BASE_REFERENCE.rsplit("@", 1)[1]
                if command[4] == image.BASE_REFERENCE
                else self.registry_digest
            )
            return self.done(command, f"Name: test\nDigest:    {digest}\n".encode())
        if command[:3] == ["docker", "buildx", "build"]:
            context = Path(command[-1])
            self.build_context_paths = {
                path.relative_to(context).as_posix()
                for path in context.rglob("*")
                if path.is_file()
            }
            for path in image.SOURCE_PATHS:
                if (context / path).read_bytes() != self.sources[path]:
                    raise AssertionError(f"build context differs from Git: {path}")
            if f"AUTHORITY_SOURCE_SHA={SHA}" not in command:
                raise AssertionError("build lacks exact source SHA")
            return self.done(command, b"build ok")
        if command[:3] == ["docker", "image", "inspect"]:
            if command[4] == "{{json .Config}}":
                config = {
                    "User": "10001:10001",
                    "Labels": {"org.opencontainers.image.revision": SHA},
                }
                return self.done(command, json.dumps(config).encode())
            if command[4] == "{{json .RepoDigests}}":
                reference = f"{image.IMAGE_REPOSITORY}@{self.pulled_digest}"
                return self.done(command, json.dumps([reference]).encode())
        if command[:2] == ["docker", "push"]:
            return self.done(
                command,
                f"sha-{SHA}: digest: {EXPECTED} size: 1234\n".encode(),
            )
        if command[:2] == ["docker", "pull"]:
            return self.done(command, b"pulled")
        if command[:2] == ["docker", "run"]:
            digests = {
                f"/opt/runner/{path}": hashlib.sha256(data).hexdigest()
                for path, data in self.sources.items()
                if path != "platform/runner/Containerfile"
            }
            return self.done(
                command, json.dumps({"uid": 10001, "digests": digests}).encode()
            )
        raise AssertionError(f"unexpected simulated command: {command}")

    def assert_source(self, path: str) -> None:
        if path not in self.sources:
            raise AssertionError(f"unapproved build input: {path}")


class RunnerImageTests(unittest.TestCase):
    def test_recipe_uses_observed_digest_and_nonroot_source_allowlist(self) -> None:
        recipe = (ROOT / "platform/runner/Containerfile").read_text()
        self.assertIn("FROM " + image.BASE_REFERENCE, recipe)
        self.assertIn("USER 10001:10001", recipe)
        self.assertNotIn(":latest", recipe)
        for path in image.SOURCE_PATHS[1:]:
            self.assertIn(path.split("/")[-1], recipe)

    def test_exact_transport_round_trip_is_not_authority_activation(self) -> None:
        fake = FakeExecutor()
        report = image.publish_merged_runner(ROOT, fake)
        self.assertEqual("BLOCKED_RUNTIME", report["status"])
        self.assertEqual("NOT_ACTIVE", report["runner_authority"])
        self.assertFalse(report["formal_proof"])
        self.assertEqual("PASS", report["image_transport_status"])
        self.assertEqual(EXPECTED, report["expected_digest"])
        self.assertEqual(EXPECTED, report["registry_digest"])
        self.assertEqual(EXPECTED, report["pulled_digest"])
        self.assertEqual(set(image.SOURCE_PATHS), fake.build_context_paths)
        docker_actions = [cmd[:2] for cmd in fake.commands if cmd[0] == "docker"]
        self.assertIn(["docker", "push"], docker_actions)
        self.assertIn(["docker", "pull"], docker_actions)
        self.assertIn(["docker", "run"], docker_actions)

    def test_unmerged_dirty_or_stale_source_blocks_before_docker(self) -> None:
        for change in (
            {"branch": "feature"},
            {"dirty": True},
            {"github_shas": ["e" * 40]},
        ):
            with self.subTest(change=change):
                fake = FakeExecutor()
                for key, value in change.items():
                    setattr(fake, key, value)
                report = image.publish_merged_runner(ROOT, fake)
                self.assertEqual("BLOCKED_RUNTIME", report["image_transport_status"])
                self.assertFalse(any(cmd[0] == "docker" for cmd in fake.commands))

    def test_registry_digest_mismatch_blocks_pull_and_smoke(self) -> None:
        fake = FakeExecutor()
        fake.registry_digest = OTHER
        report = image.publish_merged_runner(ROOT, fake)
        self.assertEqual("BLOCKED_RUNTIME", report["status"])
        self.assertEqual("BLOCKED_RUNTIME", report["image_transport_status"])
        self.assertEqual(EXPECTED, report["expected_digest"])
        self.assertEqual(OTHER, report["registry_digest"])
        self.assertFalse(
            any(
                cmd[:2] in (["docker", "pull"], ["docker", "run"])
                for cmd in fake.commands
            )
        )

    def test_main_advancing_after_build_blocks_push(self) -> None:
        fake = FakeExecutor()
        fake.github_shas = [SHA, "f" * 40]
        report = image.publish_merged_runner(ROOT, fake)
        self.assertEqual("BLOCKED_RUNTIME", report["image_transport_status"])
        self.assertTrue(
            any(cmd[:3] == ["docker", "buildx", "build"] for cmd in fake.commands)
        )
        self.assertFalse(any(cmd[:2] == ["docker", "push"] for cmd in fake.commands))

    def test_pulled_reference_mismatch_blocks_smoke(self) -> None:
        fake = FakeExecutor()
        fake.pulled_digest = OTHER
        report = image.publish_merged_runner(ROOT, fake)
        self.assertEqual("BLOCKED_RUNTIME", report["image_transport_status"])
        self.assertFalse(any(cmd[:2] == ["docker", "run"] for cmd in fake.commands))


if __name__ == "__main__":
    unittest.main()
