import json,subprocess,sys,tempfile,unittest
SHA='a'*40;IMG='harbor/releases/product@sha256:'+'b'*64;CMD=[sys.executable,'scripts/cicd_policy.py','promote-validate']
class Promotion(unittest.TestCase):
 def invoke(self,component='product',env='preprod',image=IMG,proof=None,path=''):
  f=tempfile.NamedTemporaryFile(mode='w',delete=False);json.dump(proof or {'qualified':True,'git_sha':SHA,'component':'product','image':IMG},f);f.close();return subprocess.run(CMD+['--component',component,'--environment',env,'--sha',SHA,'--image',image,'--proof',f.name,'--changed-path',path]).returncode
 def test_valid(self):self.assertEqual(0,self.invoke())
 def test_unknown_component(self):self.assertNotEqual(0,self.invoke(component='void'))
 def test_unknown_environment(self):self.assertNotEqual(0,self.invoke(env='dev'))
 def test_mutable(self):self.assertNotEqual(0,self.invoke(image='harbor/product:latest'))
 def test_unqualified(self):self.assertNotEqual(0,self.invoke(proof={'qualified':False}))
 def test_wrong_scope(self):self.assertNotEqual(0,self.invoke(path='README.md'))
 def test_rollout_strategy(self):self.assertIn('canary:',open('platform/gitops/base/rollout.yaml').read())
