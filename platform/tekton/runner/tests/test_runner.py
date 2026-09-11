import pathlib,re,unittest,yaml
ROOT=pathlib.Path(__file__).resolve().parents[4]
class RunnerTest(unittest.TestCase):
 def test_contract_and_container_are_immutable(self):
  c=yaml.safe_load((ROOT/'config/contracts/ci-runner.yaml').read_text()); text=(ROOT/'platform/tekton/runner/Containerfile').read_text()
  self.assertIn('@sha256:',c['base_image']);self.assertIn('@sha256:',text);self.assertNotRegex(text,r'(?i)(token|private.key|kubeconfig)\s*=')
 def test_tools_are_locked(self):
  lock=yaml.safe_load((ROOT/'platform/tekton/runner/tools.lock.yaml').read_text());self.assertTrue(all(x.get('version') and x.get('sha256') for x in lock['tools'].values()))
