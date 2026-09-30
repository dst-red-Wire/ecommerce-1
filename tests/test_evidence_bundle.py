import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts import evidence_bundle as bundle


class EvidenceBundleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        lock = self.root / "config/contracts/toolchain-lock.json"
        lock.parent.mkdir(parents=True)
        lock.write_text('{"version":1}\n', encoding="utf-8")
        (self.root / ".gitignore").write_text(".context/\n", encoding="utf-8")
        self.git("init", "-q")
        self.git("add", ".")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "-q", "-m", "fixture")
        self.head = self.git("rev-parse", "HEAD")
        self.tree = self.git("rev-parse", "HEAD^{tree}")
        self.toolchain = bundle.digest_file(lock)
        self.identity = "qualification-v1"
        self.proof = self.root / ".context/evidence" / (self.head + ".json")
        self.proof.parent.mkdir(parents=True)
        self.proof.write_text(json.dumps({
            "base_sha": self.head,
            "head_sha": self.head,
            "head_tree_sha": self.tree,
            "qualification_identity": self.identity,
            "exact_commit_evidence": True,
            "status": "PASS",
        }, sort_keys=True) + "\n", encoding="utf-8")

    def git(self, *args):
        result = subprocess.run(["git", *args], cwd=self.root, capture_output=True, text=True, check=True)
        return result.stdout.strip()

    def create(self, **changes):
        arguments = {
            "base_sha": self.head,
            "head_sha": self.head,
            "tree_sha": self.tree,
            "qualification_identity": self.identity,
            "toolchain_digest": self.toolchain,
        }
        arguments.update(changes)
        return bundle.create_bundle(self.root, **arguments)

    def test_exact_qualification_and_digests_pass(self):
        evidence = self.root / ".context/runtime.json"
        evidence.write_text('{"status":"PASS","kind":"observed-runtime"}\n', encoding="utf-8")
        result = self.create(runtime_evidence=[".context/runtime.json"])
        self.assertEqual("BUNDLED", result["status"])
        checked = bundle.verify_bundle(self.root, self.head)
        self.assertEqual("PASS", checked["status"])
        self.assertEqual("bundle-integrity-only", checked["authority"])
        manifest = json.loads((self.root / result["manifest"]).read_text(encoding="utf-8"))
        self.assertEqual(self.head, manifest["head_sha"])
        self.assertEqual(self.toolchain, manifest["toolchain_digest"])
        self.assertEqual(bundle.digest_file(evidence), manifest["evidence_digests"][".context/runtime.json"])
        self.assertFalse(manifest["verdict_authority"])

    def test_modified_evidence_fails_closed(self):
        self.create()
        self.proof.write_text(self.proof.read_text(encoding="utf-8") + " ", encoding="utf-8")
        with self.assertRaisesRegex(bundle.EvidenceBundleError, "evidence digest mismatch"):
            bundle.verify_bundle(self.root, self.head)

    def test_modified_manifest_fails_closed(self):
        self.create()
        manifest = self.root / ".context/evidence" / self.head / "manifest.json"
        manifest.write_bytes(manifest.read_bytes() + b" ")
        with self.assertRaisesRegex(bundle.EvidenceBundleError, "manifest digest mismatch"):
            bundle.verify_bundle(self.root, self.head)

    def test_wrong_head_or_tree_fails(self):
        other = "f" * 40
        with self.assertRaisesRegex(bundle.EvidenceBundleError, "HEAD differs"):
            self.create(head_sha=other)
        with self.assertRaisesRegex(bundle.EvidenceBundleError, "tree differs"):
            self.create(tree_sha=other)
        self.create()
        with self.assertRaisesRegex(bundle.EvidenceBundleError, "wrong head_sha"):
            bundle.verify_bundle(self.root, self.head, expected_identity={"head_sha": other})

    def test_wrong_toolchain_or_qualification_fails(self):
        with self.assertRaisesRegex(bundle.EvidenceBundleError, "toolchain lock digest changed"):
            self.create(toolchain_digest="sha256:" + "0" * 64)
        with self.assertRaisesRegex(bundle.EvidenceBundleError, "qualification_identity"):
            self.create(qualification_identity="other")

    def test_no_qualification_pass_no_bundle(self):
        payload = json.loads(self.proof.read_text(encoding="utf-8"))
        payload["status"] = "FAIL"
        self.proof.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(bundle.EvidenceBundleError, "qualification PASS"):
            self.create()

    def test_rejects_symlink_and_traversal(self):
        outside = self.root.parent / "outside-evidence-for-test.json"
        # A symlink target inside the repository is still forbidden.
        target = self.root / ".context/target.json"
        target.write_text("{}\n", encoding="utf-8")
        (self.root / ".context/link.json").symlink_to(target)
        with self.assertRaisesRegex(bundle.EvidenceBundleError, "symlink"):
            self.create(artifacts=[".context/link.json"])
        with self.assertRaisesRegex(bundle.EvidenceBundleError, "unsafe evidence path"):
            self.create(artifacts=[".context/../config/contracts/toolchain-lock.json"])
        del outside

    def test_manifest_revisions_are_content_addressed_and_historical(self):
        first = self.create()
        review = self.root / ".context/review.json"
        review.write_text('{"provider":"ChatGPT","status":"PASS"}\n', encoding="utf-8")
        second = self.create(review_evidence=[".context/review.json"])
        self.assertNotEqual(first["manifest_digest"], second["manifest_digest"])
        history = self.root / ".context/evidence" / self.head / "history"
        self.assertTrue((history / (first["manifest_digest"].split(":")[1] + ".json")).is_file())
        self.assertEqual("PASS", bundle.verify_bundle(self.root, self.head)["status"])

    def test_identity_change_supersedes_without_erasing_history(self):
        identity = {
            "base_sha": self.head,
            "head_sha": self.head,
            "tree_sha": self.tree,
            "toolchain_digest": self.toolchain,
            "qualification_identity": self.identity,
            "runtime_identity": "lab-a",
        }
        self.assertEqual("CURRENT", bundle.authority_state(identity, dict(identity)))
        changed = dict(identity, head_sha="e" * 40)
        self.assertEqual("SUPERSEDED", bundle.authority_state(identity, changed))
        changed = dict(identity, toolchain_digest="sha256:" + "d" * 64)
        self.assertEqual("SUPERSEDED", bundle.authority_state(identity, changed))
        changed = dict(identity, runtime_identity="lab-b")
        self.assertEqual("SUPERSEDED", bundle.authority_state(identity, changed))
        self.assertEqual("FAIL", bundle.authority_state({}, identity))


if __name__ == "__main__":
    unittest.main()
