from runner_modules import module_path
import threading
import base64, hashlib, importlib.util, json, os, pathlib, struct, subprocess, sys, tempfile, time, unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load(name):
    s = importlib.util.spec_from_file_location(name, module_path(name))
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


class ContainerTests(unittest.TestCase):
    def test_readiness_checks_pinned_runtime_and_guest_without_launching(self):
        from unittest.mock import patch

        m = load("container_backend")
        backend = m.ContainerBackend.__new__(m.ContainerBackend)
        backend.path = "/usr/bin/docker"
        backend.runsc = "/synthetic/runsc"
        backend.runsc_digest = hashlib.sha256(b"synthetic runtime").hexdigest()
        backend.image = "sha256:" + "a" * 64
        calls = []

        class CLI:
            def run(self, args, **kwargs):
                calls.append(args)
                value = (
                    {"runsc": {"path": backend.runsc}}
                    if args[1] == "info"
                    else [
                        {
                            "Id": backend.image,
                            "Config": {
                                "User": "65532:65532",
                                "Entrypoint": ["/usr/local/bin/python3"],
                                "Cmd": ["/opt/isign/runner/guest_watchdog.py"],
                            },
                        }
                    ]
                )
                return {"exitCode": 0, "stdout": json.dumps(value).encode()}

        backend.cli = CLI()
        with patch.object(pathlib.Path, "read_bytes", return_value=b"synthetic runtime"):
            self.assertTrue(backend.check_ready())
        self.assertEqual([c[1] for c in calls], ["info", "inspect"])
        with patch.object(pathlib.Path, "read_bytes", return_value=b"changed runtime"):
            with self.assertRaisesRegex(ValueError, "ACTUAL_PINNED_RUNSC_REQUIRED"):
                backend.check_ready()
        with patch.object(pathlib.Path, "read_bytes", side_effect=FileNotFoundError):
            with self.assertRaises(FileNotFoundError):
                backend.check_ready()
        backend.cli.run = lambda *a, **kw: {"exitCode": 1, "stdout": b""}
        with self.assertRaisesRegex(ValueError, "DOCKER_RUNTIME_UNAVAILABLE"):
            backend.check_ready()

    def test_readiness_rejects_missing_or_mismatched_guest_image(self):
        from unittest.mock import patch

        m = load("container_backend")
        backend = m.ContainerBackend.__new__(m.ContainerBackend)
        backend.path = "/usr/bin/docker"
        backend.runsc = "/synthetic/runsc"
        backend.runsc_digest = hashlib.sha256(b"runtime").hexdigest()
        backend.image = "sha256:" + "a" * 64

        class CLI:
            def run(self, args, **kw):
                if args[1] == "info":
                    return {
                        "exitCode": 0,
                        "stdout": json.dumps({"runsc": {"path": backend.runsc}}).encode(),
                    }
                return {"exitCode": 0, "stdout": b"[]"}

        backend.cli = CLI()
        with patch.object(pathlib.Path, "read_bytes", return_value=b"runtime"):
            with self.assertRaisesRegex(ValueError, "PINNED_GUEST_IMAGE_REQUIRED"):
                backend.check_ready()

    def test_retirement_finds_failed_launch_handle_without_touching_other_nonce(self):
        m = load("container_backend")
        backend = m.ContainerBackend.__new__(m.ContainerBackend)
        backend.lock = threading.Lock()
        mine = {"id": "mine", "request": {"nonce": "mine-nonce"}}
        other = {"id": "other", "request": {"nonce": "other-nonce"}}
        backend.handles = {"mine": mine, "other": other}
        calls = []

        def destroy(handle):
            calls.append(handle["id"])
            backend.handles.pop(handle["id"])
            return True

        backend.destroy = destroy
        self.assertTrue(backend.retire_launch("mine-nonce"))
        self.assertEqual(calls, ["mine"])
        self.assertEqual(backend.handles, {"other": other})

    def test_watchdog_exits_and_cleans_after_deadline(self):
        m = load("guest_watchdog")
        clock = [1000]
        events = []
        m.run(
            1100,
            clock=lambda: clock[0],
            pause=lambda seconds: clock.__setitem__(0, clock[0] + 100),
            cleanup=lambda path, **kw: events.append(path),
        )
        self.assertEqual(events, ["/job"])


class LinuxBootstrapDelegationTests(unittest.TestCase):
    def test_scoped_job_key_bootstrap_receipt_resigned_without_master_in_guest(self):
        try:
            from cryptography import x509
        except ImportError:
            self.skipTest("Pinned crypto venv required")
        import hmac

        m = load("container_backend")
        runtime_module = load("linux_runtime")
        master = b"M" * 32
        job_key = b"J" * 32
        now = int(time.time() * 1000)
        binding = {
            "ownerId": "o",
            "connectionId": "c",
            "generation": 1,
            "nonce": "n",
            "expiresAt": now + 60000,
        }
        identity = {
            "ownerId": "o",
            "jobId": "bootstrap:n",
            "instanceId": "sandbox",
            "expiresAt": now + 60000,
        }
        evidence = {
            "type": "gvisor",
            "runtime": "runsc",
            **{k: True for k in m.native.LINUX_ISOLATION},
        }
        seal = {
            "version": 1,
            "operation": "bootstrap-seal",
            "lease": binding,
            "secretId": "synthetic",
            "grantNonce": "seal-nonce",
            "audience": "backend",
            "instanceId": "sandbox",
            "purpose": "distribution-key",
            "materialFormat": "encrypted-pem-with-password-v1",
            "expiresAt": now + 30000,
            "wrappedKey": "synthetic-wrapped",
            "aad": '{"owner":"o","connection":"c","purpose":"distribution-key","secret":"synthetic"}',
        }
        seal["signature"] = hmac.new(
            master, b"isign-bootstrap-grant-v1\0" + m.canonical(seal), hashlib.sha256
        ).hexdigest()
        payload = {
            "instanceId": "sandbox",
            "sealGrant": seal,
            "dataKey": base64.b64encode(b"K" * 32).decode(),
        }
        openssl = os.environ.get("ISIGN_TEST_OPENSSL")
        if not openssl:
            self.skipTest("Explicit synthetic OpenSSL3 fixture executable required")
        with tempfile.TemporaryDirectory() as td:

            def run(args, **kwargs):
                result = subprocess.run(
                    args,
                    cwd=kwargs["cwd"],
                    input=kwargs.get("input_bytes"),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=kwargs["timeout"],
                    check=True,
                )
                return {"stdout": result.stdout, "stderr": result.stderr}

            unused = pathlib.Path(td) / "synthetic-unused-signer"
            unused.write_bytes(b"not executed")
            unused_digest = hashlib.sha256(unused.read_bytes()).hexdigest()
            runtime = runtime_module.LinuxGuestRuntime(
                td,
                run,
                None,
                openssl_path=openssl,
                validate_vm=m.native.vm_proof_validator(lambda _: job_key),
                proof_key=job_key,
                key_id="job",
                zsign_path="/not-used/bootstrap",
                zsign_digest="0" * 64,
            )

            class Channel:
                def bootstrap_prepare(self, ch, binding, forward, grant, proof):
                    self.forward = forward
                    runtime.run = runtime_module.LinuxGuestRunner(
                        td,
                        grant,
                        proof,
                        m.native.vm_proof_validator(lambda _: job_key),
                        openssl_path=openssl,
                        zsign_path=unused,
                        zsign_digest=unused_digest,
                        launch=lambda args, **kwargs: run(args, **kwargs),
                    )
                    return runtime.bootstrap_prepare(binding, forward, grant, proof)

            backend = m.ContainerBackend.__new__(m.ContainerBackend)
            backend.channel = Channel()
            backend.key_provider = lambda: master
            backend.key_id = "job"
            backend.inspect = lambda handle: evidence
            handle = {
                "id": "sandbox",
                "binding": {"ownerId": "o", "jobId": "bootstrap:n"},
                "expiresAt": now + 60000,
                "jobKey": job_key,
                "dead": False,
                "channel": {},
                "evidence": evidence,
            }
            from unittest.mock import patch

            with patch.dict(os.environ, {"ISIGN_ISOLATED_EXECUTOR": "1"}):
                receipt = backend.bootstrap_prepare(handle, binding, payload)
                report = receipt["report"]
                self.assertEqual(report["grant"], seal)
                self.assertTrue(x509.load_pem_x509_csr(report["csr"].encode()).is_signature_valid)
                self.assertEqual(
                    receipt["attestation"],
                    hmac.new(
                        master,
                        b"isign-bootstrap-envelope-v1\0" + m.canonical(report),
                        hashlib.sha256,
                    ).hexdigest(),
                )
                self.assertNotIn(master, repr(backend.channel.forward).encode())
                self.assertFalse(list(pathlib.Path(td).glob("bootstrap-key-*")))
                forward = dict(backend.channel.forward, sealAttestation="0" * 64)
                grant, proof = backend.control_grant(handle, binding, "bootstrap-request")
                with self.assertRaisesRegex(ValueError, "SEALED_BOOTSTRAP_DELEGATION"):
                    runtime.bootstrap_prepare(binding, forward, grant, proof)
