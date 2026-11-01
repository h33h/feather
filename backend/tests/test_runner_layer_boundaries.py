"""Architecture and import probes for independently distributed runner layers."""

import ast
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from runner_modules import ROOT, load


CLIENTS = {"protocol.https_transport", "protocol.stdio"}


def imported_modules(source, module, *, package=False):
    """Include nested imports and literal dynamic imports, resolving relative names."""
    result = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            result.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                parent = module.split(".") if package else module.split(".")[:-1]
                base = ".".join(parent[: len(parent) - node.level + 1] + ([base] if base else []))
            result.add(base)
            result.update(base + "." + alias.name for alias in node.names)
        elif isinstance(node, ast.Call) and node.args:
            target = node.func
            dynamic = isinstance(target, ast.Name) and target.id == "__import__"
            dynamic |= isinstance(target, ast.Attribute) and target.attr == "import_module"
            if (
                dynamic
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                result.add(node.args[0].value)
    return result


def import_graph():
    graph = {}
    for path in ROOT.rglob("*.py"):
        parts = list(path.relative_to(ROOT).with_suffix("").parts)
        package = parts[-1] == "__init__"
        if package:
            parts.pop()
        name = ".".join(parts)
        graph[name] = imported_modules(path.read_text(), name, package=package)
    resolved = {}
    for name, targets in graph.items():
        dependencies = set()
        for target in targets:
            parts = target.split(".")
            dependencies.update(".".join(parts[:index]) for index in range(1, len(parts) + 1))
        resolved[name] = dependencies & graph.keys()
    return resolved


def belongs_to(module, *roots):
    return any(module == root or module.startswith(root + ".") for root in roots)


def reachable(graph, module):
    found = set()
    pending = list(graph[module])
    while pending:
        target = pending.pop()
        if target not in found:
            found.add(target)
            pending.extend(graph[target])
    return found


def probe(root, script):
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            "import sys\nsys.path.insert(0, sys.argv[1])\n" + script,
            str(root),
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode:
        raise AssertionError(result.stderr)


class RunnerLayerBoundaryTests(unittest.TestCase):
    def test_scanner_tracks_function_local_relative_and_dynamic_imports(self):
        targets = imported_modules(
            "def factory():\n import guest.device_cms\n from . import codec\n"
            " __import__('controller.broker')\n importlib.import_module('protocol.stdio')\n",
            "protocol.example",
        )
        self.assertTrue(
            {"guest.device_cms", "protocol.codec", "controller.broker", "protocol.stdio"} <= targets
        )

    def test_direction_guard_rejects_bare_runtime_imports_and_package_initializers(self):
        for entry, dependency in (
            ("controller.adapter", "guest"),
            ("guest.adapter", "controller"),
            ("controller", "guest.worker"),
            ("guest", "controller.worker"),
        ):
            with self.subTest(entry=entry, dependency=dependency):
                graph = {
                    entry: imported_modules("def factory():\n import " + dependency, entry),
                    dependency: set(),
                }
                with patch(__name__ + ".import_graph", return_value=graph):
                    with self.assertRaises(AssertionError):
                        self.test_controller_and_guest_have_no_transitive_dependency_on_each_other()

    def test_neutral_guard_rejects_runtime_roots_and_initializer_dependencies(self):
        for entry, dependency in (
            ("protocol.codec", "guest"),
            ("verification_core.certificates", "controller"),
            ("guest.handler", "controller"),
            ("protocol", "guest.worker"),
            ("verification_core", "controller.worker"),
            ("guest", "controller.worker"),
        ):
            with self.subTest(entry=entry, dependency=dependency):
                graph = {entry: imported_modules("import " + dependency, entry), dependency: set()}
                with patch(__name__ + ".import_graph", return_value=graph):
                    with self.assertRaises(AssertionError):
                        self.test_neutral_modules_and_guest_do_not_reach_concrete_transport_clients()

    def test_neutral_guard_rejects_concrete_client_roots_and_descendants(self):
        for entry in ("protocol", "verification_core", "guest", "protocol.codec"):
            for dependency in (
                "protocol.https_transport",
                "protocol.stdio",
                "protocol.https_transport.connection",
                "protocol.stdio.process",
            ):
                with self.subTest(entry=entry, dependency=dependency):
                    graph = {
                        entry: imported_modules("import " + dependency, entry),
                        dependency: set(),
                    }
                    with patch(__name__ + ".import_graph", return_value=graph):
                        with self.assertRaises(AssertionError):
                            self.test_neutral_modules_and_guest_do_not_reach_concrete_transport_clients()

    def test_controller_and_guest_have_no_transitive_dependency_on_each_other(self):
        graph = import_graph()
        violations = []
        for module in graph:
            opposite = "guest" if belongs_to(module, "controller") else "controller"
            if belongs_to(module, "controller", "guest"):
                violations.extend(
                    (module, target)
                    for target in reachable(graph, module)
                    if belongs_to(target, opposite)
                )
        self.assertEqual(violations, [])

    def test_neutral_modules_and_guest_do_not_reach_concrete_transport_clients(self):
        graph = import_graph()
        violations = []
        for module in graph:
            if (
                belongs_to(module, "protocol", "verification_core", "guest")
                and module not in CLIENTS
            ):
                forbidden = CLIENTS | {"controller"}
                if not belongs_to(module, "guest"):
                    forbidden.add("guest")
                violations.extend(
                    (module, target)
                    for target in reachable(graph, module)
                    if belongs_to(target, *forbidden)
                )
        self.assertEqual(violations, [])

    def test_controller_cms_factory_works_without_guest_distribution(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary)
            for package in ("controller", "protocol", "verification_core"):
                if (ROOT / package).exists():
                    shutil.copytree(ROOT / package, output / package)
            shutil.copy(ROOT / "runner_diagnostics.py", output)
            probe(
                output,
                """
import hashlib, importlib, pathlib
for path in (pathlib.Path(sys.argv[1]) / 'controller').glob('*.py'):
    importlib.import_module('controller.' + path.stem)
from controller.personal_deployment import device_cms_verifier
root = pathlib.Path(sys.argv[1]).resolve()
ca = root / 'public-ca.pem'
ca.write_bytes(b'public trust fixture')
config = {'deviceCms': {'caFile': str(ca), 'caSha256': hashlib.sha256(ca.read_bytes()).hexdigest(),
    'opensslPath': '/usr/bin/openssl', 'issuerDn': 'CN=Configured CA',
    'udidSubjectAttribute': 'CN', 'policyId': 'configured-policy'}}
verifier = device_cms_verifier(config, root)
assert verifier.policy_id == 'configured-policy'
assert verifier.ca_sha256 == config['deviceCms']['caSha256']
assert not any(name == 'guest' or name.startswith('guest.') for name in sys.modules)
""",
            )

    def test_minimal_helpers_work_without_either_runtime_or_clients(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary)
            for package in ("protocol", "verification_core"):
                source = ROOT / package
                if source.exists():
                    shutil.copytree(source, output / package)
            for client in CLIENTS:
                path = output / (client.replace(".", "/") + ".py")
                path.unlink(missing_ok=True)
            probe(
                output,
                """
import hashlib, io
from protocol.codec import canonical
from protocol.digests import canonical_digest
from protocol.framing import read_frame, write_frame
from protocol.limits import ARTIFACT_BATCH_LIMIT, ARTIFACT_SLICE_BYTES
from verification_core.certificates import one_pem_certificate
from verification_core.device_cms import DeviceCMSVerifier, DeviceLeafPolicy
assert canonical({'é': 1, 'a': False}) == b'{"a":false,"\\xc3\\xa9":1}'
assert canonical_digest({'é': 1, 'a': False}) == hashlib.sha256(b'{"a":false,"\\xc3\\xa9":1}').hexdigest()
stream = io.BytesIO()
write_frame(stream, b'abc')
assert stream.getvalue() == b'\\0\\0\\0\\x03abc'
stream.seek(0)
assert read_frame(stream) == b'abc'
assert one_pem_certificate(b'-----BEGIN CERTIFICATE-----AA-----END CERTIFICATE-----') == b'-----BEGIN CERTIFICATE-----AA-----END CERTIFICATE-----\\n'
assert ARTIFACT_SLICE_BYTES <= ARTIFACT_BATCH_LIMIT
assert not any(name == root or name.startswith(root + '.') for name in sys.modules for root in ('controller', 'guest', 'http.client', 'subprocess', 'protocol.https_transport', 'protocol.stdio'))
""",
            )

    def test_guest_image_does_not_ship_concrete_transport_clients(self):
        builder = load("build_linux_image")
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "runner"
            builder.copy_guest_runtime(ROOT, output)
            self.assertTrue((output / "verification_core" / "certificates.py").is_file())
            for module in CLIENTS:
                self.assertFalse((output / (module.replace(".", "/") + ".py")).exists())
