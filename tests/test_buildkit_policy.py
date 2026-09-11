import subprocess,sys,unittest
CMD=[sys.executable,'scripts/cicd_policy.py','buildkit-validate']
BASE=['--component','storefront','--context','frontend','--sha','a'*40,'--candidates','harbor/candidates','--cache','harbor/cache','--affected','storefront']
class BuildkitPolicy(unittest.TestCase):
 def test_valid(self): self.assertEqual(0,subprocess.run(CMD+BASE).returncode)
 def test_unknown(self): self.assertNotEqual(0,subprocess.run(CMD+['--component','unknown']+BASE[2:]).returncode)
 def test_traversal(self):
  x=BASE.copy();x[x.index('--context')+1]='../etc';self.assertNotEqual(0,subprocess.run(CMD+x).returncode)
 def test_absolute(self):
  x=BASE.copy();x[x.index('--context')+1]='/etc';self.assertNotEqual(0,subprocess.run(CMD+x).returncode)
 def test_mutable_latest(self):
  x=BASE.copy();x[x.index('--candidates')+1]='harbor/candidates:latest';self.assertNotEqual(0,subprocess.run(CMD+x).returncode)
