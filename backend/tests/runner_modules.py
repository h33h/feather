import pathlib, sys, importlib.util

ROOT = pathlib.Path(__file__).resolve().parents[1] / "packages/runner"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
MODULES = {
    "broker": "controller/broker.py",
    "http_host": "controller/http_host.py",
    "container_backend": "controller/container_backend.py",
    "disk_budget": "controller/disk_budget.py",
    "personal_deployment": "controller/personal_deployment.py",
    "zsign_patch": "controller/zsign_patch.py",
    "https_transport": "protocol/https_transport.py",
    "stdio_channel": "protocol/stdio.py",
    "bounded_io": "protocol/bounded_io.py",
    "proofs": "protocol/proofs.py",
    "grants": "protocol/grants.py",
    "digests": "protocol/digests.py",
    "stdio_backend": "controller/stdio_backend.py",
    "analyzer": "guest/analyzer.py",
    "executor": "guest/executor.py",
    "native": "guest/native.py",
    "verification": "guest/verification.py",
    "linux_executor": "guest/linux_executor.py",
    "linux_verification": "guest/linux_verification.py",
    "material_prepare": "guest/material_prepare.py",
    "bootstrap": "guest/bootstrap.py",
    "bootstrap_sealing": "guest/bootstrap_sealing.py",
    "device_cms": "guest/device_cms.py",
    "guest_runtime": "guest/runtime.py",
    "linux_runtime": "guest/linux_runtime.py",
    "guest_controller": "guest/controller.py",
    "guest_stdio": "guest/stdio.py",
    "guest_watchdog": "guest/watchdog.py",
    "linux_certificate_policy": "guest/linux_certificate_policy.py",
    "build_linux_image": "build_linux_image.py",
}


def module_path(name):
    if name not in MODULES:
        raise ValueError("UNKNOWN_RUNNER_TEST_MODULE")
    return ROOT / MODULES[name]


def load(name):
    spec = importlib.util.spec_from_file_location(name, module_path(name))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
