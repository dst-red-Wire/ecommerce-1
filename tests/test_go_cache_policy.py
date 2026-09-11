import pathlib,unittest,yaml
ROOT=pathlib.Path(__file__).resolve().parents[1]
class CachePolicy(unittest.TestCase):
 def setUp(self): self.c=yaml.safe_load((ROOT/'config/contracts/go-cache.yaml').read_text())
 def test_cache_never_authorizes(self): self.assertFalse(self.c['trust']['cache_can_authorize_gate']);self.assertFalse(self.c['trust']['cache_can_authorize_promotion'])
 def test_untrusted_cannot_write(self): self.assertFalse(self.c['trust']['untrusted_pull_request_write']);self.assertTrue(self.c['trust']['publish_after_success_only'])
 def test_key_is_complete(self): self.assertEqual({'go-version','os','architecture','cgo','flags','module-sums','runner-digest'},set(self.c['key_fields']))
