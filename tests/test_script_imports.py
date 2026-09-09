import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def import_from_external_cwd(module_name: str, relative_path: str):
    script = ROOT / relative_path
    old_cwd = Path.cwd()
    old_path = list(sys.path)
    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            os.chdir(temp_dir)
            sys.path[:] = [entry for entry in sys.path if Path(entry or ".").resolve() != script.parent]
            spec = importlib.util.spec_from_file_location(module_name, script)
            module = importlib.util.module_from_spec(spec)
            assert spec.loader is not None
            spec.loader.exec_module(module)
            return module
        finally:
            os.chdir(old_cwd)
            sys.path[:] = old_path


class ScriptImportTest(unittest.TestCase):
    def test_servicegen_imports_outside_repository_root(self):
        module = import_from_external_cwd("servicegen_external", "scripts/servicegen.py")
        self.assertTrue(callable(module.build_files))

    def test_nx_graph_imports_outside_repository_root(self):
        module = import_from_external_cwd("nx_graph_external", "scripts/nx-graph.py")
        self.assertEqual(ROOT, module.ROOT)


if __name__ == "__main__":
    unittest.main()
