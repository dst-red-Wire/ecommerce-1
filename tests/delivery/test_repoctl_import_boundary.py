from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class RepoctlImportBoundaryTest(unittest.TestCase):
    def test_repoctl_copy_without_delivery_helper_keeps_legacy_commands_importable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            temp = Path(temp_name)
            scripts = temp / "scripts"
            scripts.mkdir(parents=True)
            shutil.copy2(ROOT / "scripts/repoctl.py", scripts / "repoctl.py")
            shutil.copy2(ROOT / "scripts/contract_paths.py", scripts / "contract_paths.py")
            shutil.copy2(ROOT / "scripts/yaml_loader.py", scripts / "yaml_loader.py")
            subprocess.run(["git", "init", "-q"], cwd=temp, check=True)
            code = r"""
import importlib.util
from pathlib import Path
import sys

root = Path(sys.argv[1]).resolve()
repoctl = root / "scripts" / "repoctl.py"
spec = importlib.util.spec_from_file_location("repoctl_import_boundary_probe", repoctl)
if spec is None or spec.loader is None:
    raise SystemExit("unable to build repoctl module spec")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
if not callable(getattr(module, "api_generate", None)):
    raise SystemExit("legacy api_generate missing after standalone repoctl import")
try:
    module.evidence_metrics([])
except RuntimeError as exc:
    if "repository delivery helper unavailable" not in str(exc):
        raise
else:
    raise SystemExit("delivery helper boundary did not fail closed")
"""
            result = subprocess.run(
                [sys.executable, "-I", "-c", code, str(temp)],
                cwd=temp,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
