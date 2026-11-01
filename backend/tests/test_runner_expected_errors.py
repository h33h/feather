import base64, contextlib, hashlib, hmac, io, json, os, tempfile, threading, time, unittest
from pathlib import Path
from unittest.mock import patch

from runner_modules import load
import test_runner_broker as broker_fixtures
from test_runner_analyzer import archive, macho


class GuestExpectedErrorTests(unittest.TestCase):
    def setUp(self):
        self.guest = load("guest_controller")
        self.stdio = load("stdio_channel")
        self.transport = load("https_transport")
        self.key = b"K" * 32
        self.token = "T" * 32
        self.now = int(time.time() * 1000)
        self.identity = dict(
            ownerId="o", jobId="j", instanceId="isign-0123456789abcdef", expiresAt=self.now + 60000
        )
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        class Runtime:
            root = Path(self.temp.name)
            validate_vm = lambda *args: True
            destroy = lambda *args: None

        with patch.dict(os.environ, ISIGN_ISOLATED_EXECUTOR="1"):
            self.app = self.guest.GuestController(
                Runtime(),
                identity=self.identity,
                evidence={"type": "vm", **{k: True for k in self.guest.native.REQUIRED_ISOLATION}},
                validate_launcher_identity=lambda *args: True,
                token=self.token,
                audience="guest",
                proof_key=self.key,
                transport_kind="stdio",
                clock=lambda: self.now,
            )
        parent = self

        class ResponseStream:
            def read(self, size):
                if not hasattr(self, "data"):
                    parent.process.stdin.seek(0)
                    message = json.loads(parent.stdio.read_frame(parent.process.stdin))
                    body = base64.b64decode(message["body"])
                    env = {
                        "wsgi.url_scheme": "isign-stdio",
                        "isign.transport": "authenticated-stdio",
                        "REQUEST_METHOD": "POST",
                        "PATH_INFO": message["path"],
                        "CONTENT_TYPE": "application/json",
                        "wsgi.input": io.BytesIO(body),
                    }
                    env.update(
                        {
                            "HTTP_" + k.upper().replace("-", "_"): v
                            for k, v in message["headers"].items()
                        }
                    )
                    statuses = []
                    raw = b"".join(parent.app(env, lambda status, headers: statuses.append(status)))
                    framed = io.BytesIO()
                    parent.stdio.write_frame(
                        framed,
                        parent.transport.canonical(
                            {"status": statuses[0], "body": base64.b64encode(raw).decode()}
                        ),
                    )
                    self.data = io.BytesIO(framed.getvalue())
                return self.data.read(size)

        class Process:
            stdin = io.BytesIO()
            stdout = ResponseStream()
            killed = False

            def kill(self):
                self.killed = True

            def wait(self, **kwargs):
                return 0

        self.process = Process()
        http = self.stdio.StdioHTTP(self.process, self.identity, self.key, "guest", self.token)
        self.channel = {**self.identity, "http": http}
        self.delegate = self.transport.HTTPSGuestChannel(
            lambda _: http, self.key, clock=lambda: self.now
        )

    def analyze(self, source):
        path = Path(self.temp.name) / "source.ipa"
        path.write_bytes(source)
        digest = hashlib.sha256(source).hexdigest()
        self.app.source = {"sha256": digest, "size": len(source)}
        grant = broker_fixtures.BrokerTests.grant(type("Fixture", (), {"now": self.now})())
        grant["uploadDigest"] = digest
        return self.delegate.call(self.channel, "analyze", {"grant": grant, "proof": {}})

    def test_actual_analyzer_error_survives_authenticated_guest_stdio_and_broker(self):
        broker = broker_fixtures.BrokerTests()
        broker.setUp()
        self.addCleanup(broker.doCleanups)
        broker.launch()
        broker.source()
        broker.backend.analyze = lambda *args: self.analyze(b"invalid IPA")
        with contextlib.redirect_stderr(io.StringIO()):
            status, body = broker.request(
                "/v1/instances/isign-0123456789abcdef/analyze", {"grant": broker.grant()}
            )
        self.assertEqual((status, body), (422, {"error": "ARCHIVE_INVALID"}))
        self.assertFalse(self.process.killed)

    def test_expected_source_platform_and_drm_errors_remain_distinct(self):
        for source, code in [
            (archive(binary=macho(platform=7)), "PLATFORM_UNSUPPORTED"),
            (archive(binary=macho(encrypted=1)), "DRM_UNSUPPORTED"),
        ]:
            with self.subTest(code=code):
                self.setUp()
                with (
                    contextlib.redirect_stderr(io.StringIO()),
                    self.assertRaisesRegex(ValueError, "^" + code + "$"),
                ):
                    self.analyze(source)
                self.assertFalse(self.process.killed)

    def test_unknown_internal_error_stays_generic_and_kills_unusable_stdio_channel(self):
        with patch.object(
            self.app, "action", side_effect=ValueError("private details /job/materials/key.p12")
        ):
            with (
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaisesRegex(ValueError, "^GUEST_STDIO_RESPONSE_REJECTED$"),
            ):
                self.analyze(b"invalid IPA")
        self.assertTrue(self.process.killed)

    def test_allowlisted_message_before_authorization_stays_generic(self):
        with patch.object(self.app, "authorize", side_effect=ValueError("ARCHIVE_INVALID")):
            with (
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaisesRegex(ValueError, "^GUEST_STDIO_RESPONSE_REJECTED$"),
            ):
                self.analyze(b"invalid IPA")

    def test_failure_requires_exact_current_request_and_valid_attestation(self):
        for mutation in ("signature", "request", "unknown", "extra"):
            parent = self

            class Http:
                audience = "guest"

                def request(self, path, raw, **kwargs):
                    request = json.loads(raw)["request"]
                    if mutation == "request":
                        request["binding"]["jobId"] = "other-job"
                    code = "PRIVATE_INTERNAL_ERROR" if mutation == "unknown" else "ARCHIVE_INVALID"
                    response = {"request": request, "error": code}
                    envelope = {
                        "response": response,
                        "error": code,
                        "attestation": hmac.new(
                            parent.key,
                            b"isign-guest-response-v1\0" + parent.transport.canonical(response),
                            hashlib.sha256,
                        ).hexdigest(),
                    }
                    if mutation == "signature":
                        envelope["attestation"] = "0" * 64
                    if mutation == "extra":
                        envelope["private"] = "internal details"
                    return parent.transport.canonical(envelope)

            channel = {**self.identity, "http": Http()}
            with (
                self.subTest(mutation=mutation),
                self.assertRaisesRegex(ValueError, "^GUEST_RESPONSE_UNTRUSTED$"),
            ):
                self.delegate.call(channel, "analyze", {})

    def test_plain_backend_valueerror_cannot_impersonate_authenticated_guest_failure(self):
        broker = broker_fixtures.BrokerTests()
        broker.setUp()
        self.addCleanup(broker.doCleanups)
        broker.launch()
        broker.source()
        with (
            patch.object(broker.backend, "analyze", side_effect=ValueError("ARCHIVE_INVALID")),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            status, body = broker.request(
                "/v1/instances/isign-0123456789abcdef/analyze", {"grant": broker.grant()}
            )
        self.assertEqual((status, body), (503, {"error": "BROKER_OPERATION_FAILED"}))

    def test_authenticated_execute_failure_still_destroys_the_instance(self):
        broker = broker_fixtures.BrokerTests()
        broker.setUp()
        self.addCleanup(broker.doCleanups)
        broker.launch()
        broker.source()
        grant = broker.grant()
        task = {"fixture": True}
        grant["planDigest"] = hashlib.sha256(self.transport.canonical(task)).hexdigest()
        broker.backend.execute = lambda *args: self.delegate.call(
            self.channel, "execute", {"grant": grant, "task": task, "proof": {}}
        )
        with (
            patch.object(self.app, "action", side_effect=ValueError("ENTITLEMENTS_MISMATCH")),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            status, body = broker.request(
                "/v1/instances/isign-0123456789abcdef/execute", {"grant": grant, "task": task}
            )
        self.assertEqual((status, body), (422, {"error": "ENTITLEMENTS_MISMATCH"}))
        self.assertIn("destroy", broker.calls)

    def test_authenticated_failure_contains_only_the_public_code(self):
        for error in (
            ValueError("ENTITLEMENTS_VALUE_UNSUPPORTED"),
            ValueError("ENTITLEMENTS_INVALID"),
        ):
            with self.subTest(code=str(error)):
                self.setUp()
                with (
                    patch.object(self.app, "action", side_effect=error),
                    contextlib.redirect_stderr(io.StringIO()),
                    self.assertRaisesRegex(ValueError, "^" + str(error) + "$"),
                ):
                    self.analyze(b"invalid IPA")
                frame = json.loads(
                    self.stdio.read_frame(io.BytesIO(self.process.stdout.data.getvalue()))
                )
                envelope = json.loads(base64.b64decode(frame["body"]))
                self.assertEqual(set(envelope), {"response", "error", "attestation"})
                self.assertEqual(set(envelope["response"]), {"request", "error"})
                self.assertEqual(envelope["error"], str(error))
