import contextlib, io, json, unittest
import http_fixtures
from runner_diagnostics import log_failure


class DiagnosticTests(unittest.TestCase):
    def test_redacts_credentials_and_preserves_bounded_causes_without_locals(self):
        secret = "synthetic-private-key-32-bytes-only"
        error = ValueError("Bearer " + secret + " https://user:pass@example.com/file?token=private")
        error.__cause__ = error
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            log_failure("test_failure", error, secrets=(secret,), jobId="j")
        entry = json.loads(output.getvalue())
        self.assertEqual(entry["jobId"], "j")
        self.assertEqual(entry["error"]["cause"]["type"], "TruncatedCause")
        self.assertIn("example.com", output.getvalue())
        for value in (secret, "user:pass", "token=private"):
            self.assertNotIn(value, output.getvalue())

    def test_broken_log_sink_does_not_replace_operation_error(self):
        class BrokenSink:
            def write(self, data):
                raise OSError("closed")

        with contextlib.redirect_stderr(BrokenSink()):
            log_failure("test_failure", ValueError("original"))


class HTTPDiagnosticTests(http_fixtures.HTTPFixtures):
    def test_body_framing_failure_logs_stage_and_path_without_headers(self):
        case = self.broker()
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            host, client, worker = self.connection(case)
            client.sendall(self.request_header(case, "Transfer-Encoding: invalid"))
            self.assertIn(b"400", client.recv(4096))
            host.close()
        entry = next(
            json.loads(line)
            for line in output.getvalue().splitlines()
            if json.loads(line)["event"] == "runner_http_failed"
        )
        self.assertEqual(entry["stage"], "read-body")
        self.assertEqual(entry["error"]["message"], "TRANSFER_ENCODING_REJECTED")
        self.assertTrue(entry["path"].endswith("/source"))
        self.assertNotIn(case.token, output.getvalue())

    def test_rejected_route_does_not_log_query_credentials(self):
        case = self.broker()
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            response = case.server.dispatch(
                "POST", "/v1/instances?token=query-secret", case.headers, [b"{}"], tls=True
            )
        self.assertEqual(response.status, 404)
        self.assertNotIn("query-secret", output.getvalue())
        self.assertNotIn("?token=", output.getvalue())


class GuestDiagnosticTests(unittest.TestCase):
    def test_guest_failure_logs_cause_but_keeps_response_generic(self):
        import hashlib, threading
        from unittest.mock import Mock
        from runner_modules import load

        controller = load("guest_controller")
        app = controller.GuestController.__new__(controller.GuestController)
        token = "synthetic-bearer-token-32-bytes-only"
        key = b"synthetic-proof-key-32-bytes-only!"
        app.token_hash = hashlib.sha256(token.encode()).digest()
        app.key = key
        app.audience = "guest"
        app.identity = {"jobId": "j", "instanceId": "sandbox"}
        app.transport_kind = "stdio"
        app.lock = threading.Lock()
        app.authorize = Mock()
        app.action = Mock(
            side_effect=ValueError("NATIVE_COMMAND_FAILED " + token + " " + key.hex())
        )
        payload = {}
        envelope = {
            "request": {"payloadDigest": hashlib.sha256(controller.canonical(payload)).hexdigest()},
            "payload": payload,
            "attestation": "fixture",
        }
        environment = {
            "wsgi.url_scheme": "isign-stdio",
            "isign.transport": "authenticated-stdio",
            "REQUEST_METHOD": "POST",
            "PATH_INFO": "/v1/guest/execute",
            "CONTENT_TYPE": "application/json",
            "HTTP_AUTHORIZATION": "Bearer " + token,
            "HTTP_X_RUNNER_AUDIENCE": "guest",
            "wsgi.input": io.BytesIO(controller.canonical(envelope)),
        }
        output = io.StringIO()
        statuses = []
        with contextlib.redirect_stderr(output):
            response = b"".join(app(environment, lambda status, headers: statuses.append(status)))
        self.assertEqual(statuses, ["403 Forbidden"])
        self.assertEqual(response, b'{"error":"GUEST_REQUEST_REJECTED"}')
        entry = json.loads(output.getvalue())
        self.assertEqual(entry["event"], "runner_guest_failed")
        self.assertEqual(entry["jobId"], "j")
        self.assertIn("NATIVE_COMMAND_FAILED", entry["error"]["message"])
        self.assertNotIn(token, output.getvalue())
        self.assertNotIn(key.hex(), output.getvalue())

    def test_docker_exec_preserves_diagnostic_stderr_separate_from_protocol(self):
        from unittest.mock import patch
        from runner_modules import load

        backend = load("stdio_backend")
        with patch.object(backend.subprocess, "Popen") as start:
            backend.DockerStdioGuestChannel.start_process(["/usr/bin/docker", "exec", "fixture"])
        self.assertIsNone(start.call_args.kwargs["stderr"])
        self.assertEqual(start.call_args.kwargs["stdout"], backend.subprocess.PIPE)
