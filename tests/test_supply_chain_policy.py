import json,pathlib,subprocess,sys,tempfile,unittest
CMD=[sys.executable,'scripts/cicd_policy.py','supply-validate']; SHA='a'*40; IMG='harbor/candidates/product@sha256:'+'b'*64; RUN='harbor/runner@sha256:'+'c'*64
class Supply(unittest.TestCase):
 def invoke(self,**change):
  d={'git_sha':SHA,'repository':'harbor/candidates/product','component':'product','runner_digest':RUN,'build_inputs':['source'],'output_digest':IMG,'tool_versions':{'syft':'1'}};d.update(change.pop('proof',{}));f=tempfile.NamedTemporaryFile(mode='w',delete=False);json.dump(d,f);f.close();args=['--component',change.get('component','product'),'--sha',change.get('sha',SHA),'--image',change.get('image',IMG),'--runner',RUN,'--provenance',f.name,'--scan',change.get('scan','pass'),'--signature',change.get('signature','valid')];return subprocess.run(CMD+args).returncode
 def test_valid(self):self.assertEqual(0,self.invoke())
 def test_missing_digest(self):self.assertNotEqual(0,self.invoke(image='harbor/product:tag'))
 def test_blocking_scan(self):self.assertNotEqual(0,self.invoke(scan='fail'))
 def test_invalid_signature(self):self.assertNotEqual(0,self.invoke(signature='invalid'))
 def test_wrong_sha(self):self.assertNotEqual(0,self.invoke(proof={'git_sha':'d'*40}))
 def test_wrong_component(self):self.assertNotEqual(0,self.invoke(proof={'component':'admin'}))
