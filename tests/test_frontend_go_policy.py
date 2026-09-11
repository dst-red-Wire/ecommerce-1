import subprocess
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
class FrontendGoPolicyTest(unittest.TestCase):
 def test_node_artifacts_absent_from_index_and_worktree(self):
  tracked=subprocess.check_output(["git","ls-files"],cwd=ROOT,text=True).splitlines()
  untracked=subprocess.check_output(["git","ls-files","--others","--exclude-standard"],cwd=ROOT,text=True).splitlines()
  names={"package.json","pnpm-lock.yaml","package-lock.json","yarn.lock",".node-version",".nvmrc","turbo.json","pnpm-workspace.yaml"}
  bad=[p for p in tracked+untracked if Path(p).name in names or Path(p).suffix in {".ts",".tsx"}]
  self.assertEqual([],bad)
