import pathlib, subprocess, sys, tempfile, unittest
from runner_modules import load, ROOT


class GuestPackagingTests(unittest.TestCase):
    def test_guest_image_imports_its_runtime_without_controller_sources(self):
        builder = load("build_linux_image")
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "runner"
            builder.copy_guest_runtime(ROOT, output)
            self.assertFalse((output / "controller").exists())
            self.assertFalse((output / "personal_deployment.py").exists())
            probe = """
import pathlib,sys
sys.path.insert(0,sys.argv[1])
import importlib
for package in ('guest', 'protocol', 'verification_core'):
    for path in (pathlib.Path(sys.argv[1]) / package).glob('*.py'):
        importlib.import_module(package + '.' + path.stem)
try:
    importlib.import_module('controller.broker')
    raise AssertionError('controller available inside guest image')
except ModuleNotFoundError:
    pass
"""
            subprocess.run([sys.executable, "-I", "-c", probe, str(output)], check=True, timeout=10)
