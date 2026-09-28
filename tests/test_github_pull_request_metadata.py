from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("repoctl_pr_metadata", ROOT / "scripts/repoctl.py")
assert SPEC and SPEC.loader
REPOCTL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPOCTL)


class GitHubPullRequestMetadataTests(unittest.TestCase):
    def payload(self) -> dict:
        return {
            "number": 148,
            "html_url": "https://github.com/dst-red-Wire/ecommerce-1/pull/148",
            "state": "open",
            "draft": False,
            "merged": False,
            "merged_at": None,
            "base": {"ref": "main", "sha": "a" * 40},
            "head": {"ref": "feature", "sha": "b" * 40},
        }

    def test_reads_base_and_head_sha_from_canonical_rest_payload(self):
        with mock.patch.object(REPOCTL, "output", return_value=json.dumps(self.payload())) as call:
            metadata = REPOCTL.github_pull_request_metadata("gh", 148)

        self.assertEqual("a" * 40, metadata["base_sha"])
        self.assertEqual("b" * 40, metadata["head_sha"])
        call.assert_called_once_with(["gh", "api", "repos/{owner}/{repo}/pulls/148"])

    def test_rejects_missing_or_invalid_rest_sha(self):
        for side in ("base", "head"):
            with self.subTest(side=side):
                payload = self.payload()
                payload[side]["sha"] = "not-a-full-sha"
                with (
                    mock.patch.object(REPOCTL, "output", return_value=json.dumps(payload)),
                    self.assertRaises(RuntimeError),
                ):
                    REPOCTL.github_pull_request_metadata("gh", 148)


if __name__ == "__main__":
    unittest.main()
