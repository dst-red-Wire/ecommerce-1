import pathlib,unittest,yaml
ROOT=pathlib.Path(__file__).resolve().parents[1]
class Performance(unittest.TestCase):
 def test_every_pipeline_metrics(self):
  d=yaml.safe_load((ROOT/'config/contracts/ci-performance.yaml').read_text());self.assertEqual('every-pipeline',d['collection']);self.assertGreaterEqual(len(d['metrics']),16);self.assertFalse(d['periodic_monthly_benchmark'])
 def test_deep_analysis_is_event_driven(self):
  d=yaml.safe_load((ROOT/'config/contracts/ci-performance.yaml').read_text());self.assertEqual({'structural_change','runner_change','cache_change','automatic_regression'},set(d['deep_analysis_triggers']))
