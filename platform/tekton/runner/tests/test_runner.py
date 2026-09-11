import pathlib,re,unittest,yaml
ROOT=pathlib.Path(__file__).resolve().parents[4]
class RunnerTest(unittest.TestCase):
 def test_contract_and_container_are_immutable(self):
  c=yaml.safe_load((ROOT/'config/contracts/ci-runner.yaml').read_text()); text=(ROOT/'platform/tekton/runner/Containerfile').read_text()
  self.assertIn('@sha256:',c['base_image']);self.assertIn('@sha256:',text);self.assertNotRegex(text,r'(?i)(token|private.key|kubeconfig)\s*=')
 def test_python_dependencies_use_the_canonical_lock(self):
  text=(ROOT/'platform/tekton/runner/Containerfile').read_text(); lock=(ROOT/'config/python/requirements.lock').read_text()
  version=re.search(r'^PyYAML==([^ ]+)',lock,re.MULTILINE).group(1)
  self.assertEqual('6.0.2',version);self.assertIn('COPY config/python/requirements.lock /tmp/requirements.lock',text)
  self.assertIn('pip install --no-cache-dir --require-hashes -r /tmp/requirements.lock',text);self.assertNotIn('python3-yaml',text)
 def test_tools_are_locked(self):
  lock=yaml.safe_load((ROOT/'platform/tekton/runner/tools.lock.yaml').read_text());self.assertTrue(all(x.get('version') and x.get('sha256') for x in lock['tools'].values()))
