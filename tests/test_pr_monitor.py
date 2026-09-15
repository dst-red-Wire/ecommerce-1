import argparse, json
from pathlib import Path
import tempfile, unittest
from unittest import mock
from scripts import pr_monitor


class PRMonitorTest(unittest.TestCase):
    def test_adaptive_interval(self):
        self.assertEqual(pr_monitor.next_interval(0, 900, 3600), 900)
        self.assertEqual(pr_monitor.next_interval(4, 900, 3600), 1800)
        self.assertEqual(pr_monitor.next_interval(8, 900, 3600), 3600)

    def test_delta_ignores_poll_metadata(self):
        self.assertEqual(
            pr_monitor.delta(
                {"head_sha": "a", "checks": {}, "polled_at": 1, "etag": "one"},
                {"head_sha": "a", "checks": {}, "polled_at": 2, "etag": "two"},
            ),
            {},
        )

    def test_unchanged_response_does_not_invoke_codex(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.json"
            state.write_text(json.dumps({"etag": "same", "unchanged_polls": 3}))
            args = argparse.Namespace(owner="o", repo="r", pr=7, codex_command=["codex"], abandoned=False)
            with (
                mock.patch.object(pr_monitor, "github_request", return_value=(304, None, "same")),
                mock.patch.object(pr_monitor, "invoke_codex") as invoke,
            ):
                terminal, unchanged = pr_monitor.poll_once(args, state, "token")
            self.assertFalse(terminal)
            self.assertEqual(unchanged, 4)
            invoke.assert_not_called()
            self.assertEqual(json.loads(state.read_text())["unchanged_polls"], 4)

    def test_snapshot_tracks_only_open_findings(self):
        pr = {
            "headRefOid": "abc",
            "reviews": {"nodes": []},
            "commits": {"nodes": []},
            "reviewThreads": {
                "nodes": [
                    {"id": "open", "isResolved": False, "comments": {"nodes": [{"id": "c1", "path": "x"}]}},
                    {"id": "done", "isResolved": True, "comments": {"nodes": [{"id": "c2"}]}},
                ]
            },
            "state": "OPEN",
            "merged": False,
        }
        result = pr_monitor.snapshot(pr, etag="tag", timestamp=1)
        self.assertEqual(result["open_findings_count"], 1)
        self.assertEqual(list(result["open_findings"]), ["open"])


if __name__ == "__main__":
    unittest.main()
