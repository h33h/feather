from runner_modules import module_path
import importlib.util, pathlib, tempfile, unittest, json, time, hashlib, hmac, io, contextlib
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load():
    s = importlib.util.spec_from_file_location("broker", module_path("broker"))
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.m = load()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.key = b"synthetic-proof-key-32-bytes-only"
        self.token = "synthetic-service-token-32-chars-only"
        self.calls = []
        self.now = int(time.time() * 1000)
        parent = self

        class Backend:
            def launch(self, request):
                parent.calls.append("launch")
                return {
                    "id": "isign-0123456789abcdef",
                    "expiresAt": parent.now + request["maxRuntimeMs"],
                    "evidence": {k: True for k in parent.m.REQUIRED_ISOLATION},
                }

            def verify_instance(self, handle, request):
                return True

            def upload_source(self, handle, chunks, digest):
                data = b"".join(chunks)
                parent.calls.append("upload")
                return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}

            def analyze(self, handle, grant):
                return {
                    **grant,
                    "protocolVersion": 1,
                    "operation": "analysis",
                    "executionAuthorized": False,
                    "analysis": {
                        "sha256": grant["uploadDigest"],
                        "title": "Synthetic",
                        "bundleId": "org.example.app",
                        "version": "1.0",
                        "build": "1",
                        "components": [],
                    },
                }

            def execute(self, handle, grant, task):
                return {
                    "report": {
                        **grant,
                        "protocolVersion": 1,
                        "operation": "sign",
                        "executionAuthorized": False,
                        "artifactDigest": hashlib.sha256(b"SYNTHETIC-ARTIFACT").hexdigest(),
                        "artifactSize": 18,
                        "planDigest": grant["planDigest"],
                        "checks": {k: True for k in parent.m.REQUIRED_CHECKS},
                    },
                    "artifactRef": "artifact-1",
                }

            def verify_guest_report(self, *args):
                return True

            def artifact(self, handle, ref):
                yield b"SYNTHETIC-ARTIFACT"

            def destroy(self, handle):
                parent.calls.append("destroy")
                return True

        self.backend = Backend()
        self.state = self.m.SQLiteBrokerState(pathlib.Path(self.temp.name) / "state.sqlite")
        self.addCleanup(self.state.close)
        self.server = self.m.BrokerController(
            token=self.token,
            audience="test-audience",
            proof_key=self.key,
            state=self.state,
            backend=self.backend,
            authorize_binding=lambda *a: True,
            clock=lambda: self.now,
        )
        self.headers = {
            "authorization": "Bearer " + self.token,
            "x-runner-audience": "test-audience",
            "content-type": "application/json",
        }

    def request(self, path, body=None, headers=None, method="POST"):
        response = self.server.dispatch(
            method, path, headers or self.headers, [json.dumps(body or {}).encode()], tls=True
        )
        data = b"".join(response.body)
        return response.status, json.loads(data) if data else None

    def launch(self):
        return self.request(
            "/v1/instances",
            dict(
                ownerId="o",
                jobId="j",
                nonce="launch-nonce",
                audience="test-audience",
                maxRuntimeMs=60000,
                maxInputBytes=1024**3,
                maxUnpackedBytes=4 * 1024**3,
                maxEntries=20000,
            ),
        )

    def grant(self):
        return {
            "ownerId": "o",
            "jobId": "j",
            "leaseToken": "l",
            "connectionId": "c",
            "connectionGeneration": 1,
            "deviceId": "d",
            "uploadDigest": hashlib.sha256(b"SYNTHETIC-SOURCE").hexdigest(),
            "taskNonce": "analysis-nonce",
            "isolationInstanceId": "isign-0123456789abcdef",
            "expiresAt": self.now + 30000,
        }

    def source(self, chunks=None, digest=None):
        headers = {
            **self.headers,
            "content-type": "application/octet-stream",
            "x-source-digest": digest or self.grant()["uploadDigest"],
        }
        response = self.server.dispatch(
            "POST",
            "/v1/instances/isign-0123456789abcdef/source",
            headers,
            [b"SYNTHETIC-SOURCE"] if chunks is None else chunks,
            tls=True,
        )
        return response.status

    def test_retire_launch_finds_guest_even_without_a_persisted_web_grant(self):
        self.launch()
        response = self.server.dispatch(
            "POST",
            "/v1/retire-launch",
            self.headers,
            [json.dumps({"nonce": "launch-nonce"}).encode()],
            tls=True,
        )
        self.assertEqual(response.status, 204)
        self.assertIn("destroy", self.calls)

    def test_busy_backend_reports_capacity_without_generic_failure(self):
        with patch.object(
            self.server.backend,
            "launch",
            side_effect=ValueError("GLOBAL_EXECUTOR_SLOT_UNAVAILABLE"),
        ):
            status, envelope = self.launch()
        self.assertEqual(status, 409)
        self.assertEqual(envelope["error"], "RUNNER_BUSY")

    def test_retirement_waits_for_an_inflight_launch_and_destroys_before_ack(self):
        import threading

        entered = threading.Event()
        release = threading.Event()
        result = {}
        original = self.server.backend.launch

        def delayed(request):
            entered.set()
            if not release.wait(2):
                raise RuntimeError("test timeout")
            return original(request)

        with patch.object(self.server.backend, "launch", side_effect=delayed):
            launching = threading.Thread(target=lambda: result.update(launch=self.launch()[0]))
            launching.start()
            self.assertTrue(entered.wait(1))
            retiring = threading.Thread(
                target=lambda: result.update(
                    retire=self.server.dispatch(
                        "POST",
                        "/v1/retire-launch",
                        self.headers,
                        [b'{"nonce":"launch-nonce"}'],
                        tls=True,
                    ).status
                )
            )
            retiring.start()
            deadline = time.monotonic() + 1
            while (
                "launch-nonce" not in self.server.retired_launches and time.monotonic() < deadline
            ):
                time.sleep(0.001)
            self.assertTrue(retiring.is_alive())
            release.set()
            launching.join(2)
            retiring.join(2)
        self.assertEqual(result, {"launch": 409, "retire": 204})
        self.assertIn("destroy", self.calls)

    def test_retirement_requires_confirmation_for_a_backend_handle_missing_from_registry(self):
        self.backend.retire_launch = lambda nonce: False
        response = self.server.dispatch(
            "POST", "/v1/retire-launch", self.headers, [b'{"nonce":"lost-launch"}'], tls=True
        )
        self.assertEqual(response.status, 503)

    def test_fast_upload_checks_authorization_by_bytes_instead_of_fragment_count(self):
        self.launch()
        checks = []
        self.server.authorize = lambda principal, operation, binding: (
            checks.append(operation) or True
        )
        fragments = [b"x" * 16384] * 128
        with patch.object(self.m.time, "monotonic", return_value=0):
            self.assertEqual(
                self.source(fragments, hashlib.sha256(b"".join(fragments)).hexdigest()), 204
            )
        self.assertEqual(checks.count("source"), 3)
        self.assertEqual(self.calls, ["launch", "upload"])

    def test_slow_upload_rechecks_before_releasing_next_fragment_after_revocation(self):
        self.launch()
        tick = [0.0]
        received = []

        def fragments():
            yield b"first"
            tick[0] = 1.0
            yield b"second"

        def authorize(principal, operation, binding):
            return operation != "source" or tick[0] < 1.0

        def upload(handle, chunks, digest):
            for chunk in chunks:
                received.append(chunk)

        self.server.authorize = authorize
        self.backend.upload_source = upload
        with patch.object(self.m.time, "monotonic", side_effect=lambda: tick[0]):
            self.assertEqual(self.source(fragments()), 403)
        self.assertEqual(received, [b"first"])
        self.assertIn("destroy", self.calls)

    def test_revocation_after_last_fragment_prevents_upload_confirmation(self):
        self.launch()
        revoked = [False]
        original = self.backend.upload_source

        def upload(handle, chunks, digest):
            result = original(handle, chunks, digest)
            revoked[0] = True
            return result

        self.backend.upload_source = upload
        self.server.authorize = lambda principal, operation, binding: (
            operation != "source" or not revoked[0]
        )
        self.assertEqual(self.source(), 403)
        self.assertIn("destroy", self.calls)
        self.assertNotIn("sourceDigest", next(iter(self.server.instances.values())))

    def test_byte_budget_revocation_stops_before_releasing_another_fragment(self):
        self.launch()
        checks = [0]
        received = []

        def authorize(principal, operation, binding):
            if operation == "source":
                checks[0] += 1
                return checks[0] == 1
            return True

        def upload(handle, chunks, digest):
            for chunk in chunks:
                received.append(chunk)

        self.server.authorize = authorize
        self.backend.upload_source = upload
        with patch.object(self.m.time, "monotonic", return_value=0):
            self.assertEqual(self.source([b"x" * 16384] * 65), 403)
        self.assertEqual(sum(len(chunk) for chunk in received), 1048576)
        self.assertIn("destroy", self.calls)

    def test_denied_source_does_not_start_backend_upload(self):
        self.launch()
        self.server.authorize = lambda principal, operation, binding: operation != "source"
        self.assertEqual(self.source(), 403)
        self.assertEqual(self.calls, ["launch", "destroy"])

    def test_auth_audience_tls_and_nonce_replay(self):
        self.assertEqual(
            self.request(
                "/v1/instances", {}, headers={**self.headers, "authorization": "Bearer wrong"}
            )[0],
            401,
        )
        self.assertEqual(
            self.request(
                "/v1/instances", {}, headers={**self.headers, "x-runner-audience": "foreign"}
            )[0],
            403,
        )
        status, envelope = self.launch()
        self.assertEqual(status, 200)
        self.assertEqual(
            envelope["attestation"],
            hmac.new(self.key, self.m.canonical(envelope["report"]), hashlib.sha256).hexdigest(),
        )
        self.assertEqual(self.launch()[0], 409)
        self.assertEqual(self.calls, ["launch"])

    def test_source_analysis_signed_response_and_destroy(self):
        self.launch()
        self.assertEqual(self.source(), 204)
        status, result = self.request(
            "/v1/instances/isign-0123456789abcdef/analyze", {"grant": self.grant()}
        )
        self.assertEqual(status, 200)
        self.assertEqual(result["report"]["analysis"]["sha256"], self.grant()["uploadDigest"])
        self.assertEqual(
            self.request("/v1/instances/isign-0123456789abcdef", method="DELETE")[0], 204
        )
        self.assertEqual(
            self.request("/v1/instances/isign-0123456789abcdef/analyze", {"grant": self.grant()})[
                0
            ],
            410,
        )

    def test_cancellable_source_upload_preserves_backend_cancellation(self):
        from protocol.bounded_io import CancellableIterator

        self.launch()
        cancelled = []
        original = self.backend.upload_source

        def upload(handle, chunks, digest):
            result = original(handle, chunks, digest)
            chunks.cancel()
            return result

        self.backend.upload_source = upload
        chunks = CancellableIterator([b"SYNTHETIC-SOURCE"], lambda: cancelled.append(True))
        self.assertEqual(self.source(chunks), 204)
        self.assertEqual(cancelled, [True])
        self.assertEqual(
            self.request("/v1/instances/isign-0123456789abcdef/analyze", {"grant": self.grant()})[
                0
            ],
            200,
        )

    def test_source_failure_logged_before_cleanup_failure(self):
        self.launch()

        def upload(handle, chunks, digest):
            next(iter(chunks))
            raise ValueError("STDIO_CHANNEL_CLOSED")

        def destroy(handle):
            raise ValueError("CLEANUP_TEST_FAILURE")

        self.backend.upload_source = upload
        self.backend.destroy = destroy
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            self.assertEqual(self.source(), 503)
        entries = [json.loads(line) for line in output.getvalue().splitlines()]
        source = next(log for log in entries if log["event"] == "runner_source_failed")
        self.assertEqual(source["jobId"], "j")
        self.assertEqual(source["instanceId"], "isign-0123456789abcdef")
        self.assertEqual(source["bytesReceived"], len(b"SYNTHETIC-SOURCE"))
        self.assertEqual(source["error"]["message"], "STDIO_CHANNEL_CLOSED")
        self.assertTrue(any(log["event"] == "runner_source_cleanup_failed" for log in entries))
        self.assertNotIn(self.token, output.getvalue())

    def test_foreign_owner_source_digest_and_wrong_plan(self):
        self.launch()
        self.source()
        grant = dict(self.grant(), ownerId="foreign")
        self.assertEqual(
            self.request("/v1/instances/isign-0123456789abcdef/analyze", {"grant": grant})[0], 403
        )
        grant = dict(self.grant(), taskNonce="sign-nonce", planDigest="b" * 64)
        self.assertEqual(
            self.request(
                "/v1/instances/isign-0123456789abcdef/execute", {"grant": grant, "task": {}}
            )[0],
            409,
        )

    def test_capabilities_require_backend_readiness_before_attesting(self):
        self.server.sealed_bridge = True
        self.backend.material_prepare = lambda *args: None
        body = {
            "binding": {"nonce": "missing-readiness"},
            "payload": {},
            "audience": "test-audience",
        }
        self.assertEqual(self.request("/v1/control/capabilities", body)[0], 503)
        self.backend.check_ready = lambda: False
        body["binding"]["nonce"] = "failed-readiness"
        self.assertEqual(self.request("/v1/control/capabilities", body)[0], 503)
        self.backend.check_ready = lambda: True
        body["binding"]["nonce"] = "ready-backend"
        status, result = self.request("/v1/control/capabilities", body)
        self.assertEqual(status, 200)
        self.assertTrue(result["report"]["value"]["executorReady"])
        self.assertNotIn("launch", self.calls)

    def test_control_caps_not_faked_and_bound_device_cms(self):
        self.assertEqual(
            self.request(
                "/v1/control/capabilities",
                {"binding": {"nonce": "caps-nonce"}, "payload": {}, "audience": "test-audience"},
            )[0],
            503,
        )
        self.server.device_cms_verifier = lambda data: {
            "challenge": "challenge",
            "udid": "0" * 40,
            "product": "iPhone15,2",
            "version": "18.0",
            "signatureVerified": True,
            "issuerTrusted": True,
            "deviceCertificate": "a" * 64,
        }
        self.server.device_cms_verifier.policy_id = "test-policy"
        self.server.device_cms_verifier.ca_sha256 = "b" * 64
        import base64

        body = {
            "binding": {"nonce": "device-nonce"},
            "payload": {
                "cmsBase64": base64.b64encode(b"SYNTHETIC-CMS").decode(),
                "policyId": "test-policy",
                "caSha256": "b" * 64,
            },
            "audience": "test-audience",
        }
        status, result = self.request("/v1/control/device-cms", body)
        self.assertEqual(status, 200)
        self.assertEqual(result["report"]["binding"], body["binding"])
        self.assertEqual(result["report"]["value"]["payload"]["udid"], "0" * 40)

    def test_failed_destroy_can_retry_without_reopening_resource(self):
        self.launch()
        outcomes = iter([False, True])
        self.backend.destroy = lambda handle: next(outcomes)
        self.assertEqual(
            self.request("/v1/instances/isign-0123456789abcdef", method="DELETE")[0], 503
        )
        self.assertTrue(self.state.pending())
        self.assertEqual(self.source(), 410)
        self.assertEqual(
            self.request("/v1/instances/isign-0123456789abcdef", method="DELETE")[0], 204
        )
        self.assertFalse(self.state.pending())

    def test_revoked_owner_lease_still_allows_trusted_cleanup(self):
        self.launch()
        operations = []

        def authorize(principal, operation, binding):
            operations.append(operation)
            return operation == "destroy"

        self.server.authorize = authorize
        self.assertEqual(self.source(), 403)
        self.assertEqual(
            self.request("/v1/instances/isign-0123456789abcdef", method="DELETE")[0], 204
        )
        self.assertIn("destroy", operations)


if __name__ == "__main__":
    unittest.main()
