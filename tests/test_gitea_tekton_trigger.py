import pathlib,unittest,yaml
ROOT=pathlib.Path(__file__).resolve().parents[1]
class Trigger(unittest.TestCase):
 def docs(self,path):return list(yaml.safe_load_all((ROOT/path).read_text()))
 def test_signature_contract_identity(self):
  a=yaml.safe_load((ROOT/'config/contracts/ci-topology.yaml').read_text())['trigger_flow']['webhook_authentication']['accepted_signature_headers'];b=yaml.safe_load((ROOT/'config/contracts/tekton-trigger-runtime.yaml').read_text())['webhook_authentication']['accepted_signature_header'];self.assertEqual(['X-Hub-Signature-256'],a);self.assertEqual(a,[b])
 def test_hmac_and_events(self):
  text=(ROOT/'platform/tekton/triggers/eventlistener.yaml').read_text();self.assertIn('secretRef',text);self.assertIn('pull_request',text);self.assertNotIn('X-Gitea-Signature',text)
 def test_no_wildcard_rbac(self):
  for d in self.docs('platform/tekton/triggers/service-accounts.yaml'):
   if d['kind']=='Role':
    for r in d['rules']:self.assertNotIn('*',r.get('resources',[]));self.assertNotIn('*',r.get('verbs',[]));self.assertNotIn('*',r.get('apiGroups',[]))
 def test_no_plain_secret(self):
  self.assertNotIn('kind: Secret',(ROOT/'platform/tekton/triggers/security.yaml').read_text())
 def test_runner_is_digest(self):self.assertIn('@sha256:',(ROOT/'platform/tekton/triggers/template.yaml').read_text())
