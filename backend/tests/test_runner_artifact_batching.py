"""Authenticated artifact batching through the real guest and framed channel."""

import base64, contextlib, io, json, os, pathlib, tempfile, time, unittest
from types import SimpleNamespace
from unittest.mock import patch

from runner_modules import load

SLICE = 65536
BATCH = 1 << 20


class ArtifactBatchingTests(unittest.TestCase):
    def setUp(self):
        self.guest = load("guest_controller")
        self.transport = load("https_transport")
        self.stdio = load("stdio_channel")
        self.key = b"K" * 32
        self.now = int(time.time() * 1000)
        self.identity = dict(
            ownerId="owner", jobId="job", instanceId="guest", expiresAt=self.now + 60000
        )
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        runtime = SimpleNamespace(root=self.root)
        with patch.dict(os.environ, ISIGN_ISOLATED_EXECUTOR="1"):
            self.app = self.guest.GuestController(
                runtime,
                identity=self.identity,
                evidence={"type": "vm", **{k: True for k in self.guest.native.REQUIRED_ISOLATION}},
                validate_launcher_identity=lambda *args: True,
                token="T" * 32,
                audience="guest",
                proof_key=self.key,
                transport_kind="stdio",
                clock=lambda: self.now,
            )
        self.requests = []
        self.frames = []
        self.mutate_request = None
        self.mutate_response = None
        parent = self

        class Input(io.BytesIO):
            def flush(self):
                raw = self.getvalue()
                if raw:
                    self.seek(0)
                    self.truncate()
                    parent.respond(raw)

        self.process = SimpleNamespace(
            stdin=Input(), stdout=io.BytesIO(), kill=lambda: None, wait=lambda **kwargs: 0
        )
        http = self.stdio.StdioHTTP(self.process, self.identity, self.key, "guest", "T" * 32)
        self.channel = {**self.identity, "http": http}
        self.delegate = self.transport.HTTPSGuestChannel(
            lambda _: http, self.key, clock=lambda: self.now
        )

    def respond(self, raw):
        message = json.loads(self.stdio.read_frame(io.BytesIO(raw)))
        envelope = json.loads(base64.b64decode(message["body"]))
        self.requests.append(envelope["payload"])
        if self.mutate_request:
            self.mutate_request(envelope)
        headers = message["headers"]
        env = {
            "wsgi.url_scheme": "isign-stdio",
            "isign.transport": "authenticated-stdio",
            "REQUEST_METHOD": "POST",
            "PATH_INFO": message["path"],
            "CONTENT_TYPE": "application/json",
            "wsgi.input": io.BytesIO(self.transport.canonical(envelope)),
        }
        env.update(
            {"HTTP_" + key.upper().replace("-", "_"): value for key, value in headers.items()}
        )
        statuses = []
        body = b"".join(self.app(env, lambda status, headers: statuses.append(status)))
        if self.mutate_response:
            response = json.loads(body)
            self.mutate_response(response)
            body = self.transport.canonical(response)
        frame = self.transport.canonical(
            {"status": statuses[0], "body": base64.b64encode(body).decode()}
        )
        self.frames.append(frame)
        output = io.BytesIO()
        self.stdio.write_frame(output, frame)
        self.process.stdout = io.BytesIO(output.getvalue())

    def source(self, size):
        data = (bytes(range(256)) * ((size + 255) // 256))[:size]
        (self.root / "signed.ipa").write_bytes(data)
        return data

    def test_batches_guest_requests_but_yields_bounded_slices_without_prefetch(self):
        expected = self.source(BATCH + SLICE + 13)
        stream = self.delegate.artifact(self.channel, "signed_ipa")
        chunks = [next(stream)]
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.requests[0], {"ref": "signed_ipa", "offset": 0, "maxBytes": BATCH})
        for _ in range(BATCH // SLICE - 1):
            chunks.append(next(stream))
            self.assertEqual(len(self.requests), 1)
        chunks.append(next(stream))
        self.assertEqual(len(self.requests), 2)
        self.assertEqual(self.requests[1]["offset"], BATCH)
        chunks.extend(stream)
        self.assertEqual(b"".join(chunks), expected)
        self.assertTrue(all(0 < len(chunk) <= SLICE for chunk in chunks))
        self.assertEqual(len(self.requests), 2)

    def test_guest_rejects_request_without_current_batch_limit(self):
        self.source(SLICE + 3)
        with self.assertRaisesRegex(ValueError, "^ARTIFACT_OFFSET_REJECTED$"):
            self.app.action("artifact", {"ref": "signed_ipa", "offset": 0})
        self.assertEqual(self.app.artifact_offset, 0)

    def test_one_mib_batch_fits_existing_nested_base64_stdio_frame_cap(self):
        expected = self.source(BATCH)
        self.assertEqual(b"".join(self.delegate.artifact(self.channel, "signed_ipa")), expected)
        self.assertEqual(len(self.requests), 1)
        self.assertLess(len(self.frames[0]), self.stdio.MAX_FRAME)

    def test_guest_accepts_only_bounded_integer_batch_size_and_exact_fields(self):
        expected = self.source(BATCH + 1)
        for size in (1, SLICE - 1, SLICE, BATCH):
            with self.subTest(size=size):
                self.app.artifact_offset = 0
                value = self.app.action(
                    "artifact", {"ref": "signed_ipa", "offset": 0, "maxBytes": size}
                )
                self.assertEqual(base64.b64decode(value["data"]), expected[:size])
                self.assertEqual(self.app.artifact_offset, size)
        for size in (True, False, 0, -1, BATCH + 1, 1.0, "65536", None):
            with self.subTest(invalid_size=size):
                self.app.artifact_offset = 0
                with self.assertRaisesRegex(ValueError, "^ARTIFACT_OFFSET_REJECTED$"):
                    self.app.action(
                        "artifact", {"ref": "signed_ipa", "offset": 0, "maxBytes": size}
                    )
                self.assertEqual(self.app.artifact_offset, 0)
        for payload in (
            {"ref": "signed_ipa", "offset": 0, "maxBytes": BATCH, "extra": True},
            {"ref": "signed_ipa", "offset": False},
            {"ref": "signed_ipa", "offset": "0"},
            {"ref": "signed_ipa", "offset": 1},
        ):
            self.app.artifact_offset = 0
            with (
                self.subTest(payload=payload),
                self.assertRaisesRegex(ValueError, "^ARTIFACT_OFFSET_REJECTED$"),
            ):
                self.app.action("artifact", payload)

    def test_authenticated_malformed_responses_are_rejected_before_yielding_bytes(self):
        valid = {"data": base64.b64encode(b"x").decode(), "offset": 0, "done": True}
        invalid = [
            None,
            [],
            {},
            {**valid, "extra": True},
            {**valid, "offset": False},
            {**valid, "offset": "0"},
            {**valid, "offset": 1},
            {**valid, "done": 1},
            {**valid, "done": "true"},
            {**valid, "data": 7},
            {**valid, "data": "!invalid!"},
            {**valid, "data": "не base64"},
            {**valid, "data": base64.b64encode(b"x" * (BATCH + 1)).decode()},
            {**valid, "data": "A" * (4 * ((BATCH + 2) // 3) + 4)},
        ]
        for value in invalid:
            with self.subTest(
                value_type=type(value).__name__,
                keys=list(value) if isinstance(value, dict) else None,
            ):
                with patch.object(self.app, "action", return_value=value):
                    with self.assertRaisesRegex(ValueError, "^ARTIFACT_CHUNK_INVALID$"):
                        next(self.delegate.artifact(self.channel, "signed_ipa"))

    def test_empty_batches_are_rejected_including_final_marker(self):
        for done in (False, True):
            with (
                self.subTest(done=done),
                patch.object(
                    self.app, "action", return_value={"data": "", "offset": 0, "done": done}
                ),
                self.assertRaisesRegex(ValueError, "^ARTIFACT_STREAM_INVALID$"),
            ):
                next(self.delegate.artifact(self.channel, "signed_ipa"))

    def test_closing_partial_batch_discards_buffer_without_fetching_another_batch(self):
        expected = self.source(BATCH + 1)
        stream = self.delegate.artifact(self.channel, "signed_ipa")
        self.assertEqual(next(stream), expected[:SLICE])
        stream.close()
        self.assertEqual(len(self.requests), 1)

    def test_revocation_or_expiry_between_slices_stops_buffered_output(self):
        for reason in ("revoked", "expired"):
            with self.subTest(reason=reason):
                self.setUp()
                self.source(BATCH + 1)
                stream = self.delegate.artifact(self.channel, "signed_ipa")
                next(stream)
                if reason == "revoked":
                    self.channel["revoked"] = True
                else:
                    self.now = self.identity["expiresAt"]
                with self.assertRaisesRegex(ValueError, "^GUEST_CHANNEL_(REVOKED|EXPIRED)$"):
                    next(stream)
                self.assertEqual(len(self.requests), 1)

    def test_request_batch_size_is_covered_by_payload_digest_and_authentication(self):
        self.source(BATCH + 1)
        self.mutate_request = lambda envelope: envelope["payload"].update(maxBytes=SLICE)
        with (
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaisesRegex(ValueError, "^GUEST_STDIO_RESPONSE_REJECTED$"),
        ):
            next(self.delegate.artifact(self.channel, "signed_ipa"))
        self.assertEqual(self.app.artifact_offset, 0)

    def test_response_batch_is_authenticated_before_slicing(self):
        self.source(BATCH)
        self.mutate_response = lambda envelope: envelope["value"].update(
            data=base64.b64encode(b"forged").decode()
        )
        with self.assertRaisesRegex(ValueError, "^GUEST_RESPONSE_UNTRUSTED$"):
            next(self.delegate.artifact(self.channel, "signed_ipa"))

    def test_valid_short_nonfinal_batches_use_actual_length_for_next_offset(self):
        expected = self.source(17)
        original = self.app.action

        def action(operation, payload):
            return original(operation, {**payload, "maxBytes": 7})

        with patch.object(self.app, "action", side_effect=action):
            chunks = list(self.delegate.artifact(self.channel, "signed_ipa"))
        self.assertEqual(b"".join(chunks), expected)
        self.assertEqual([request["offset"] for request in self.requests], [0, 7, 14])

    def broker_artifact(self, *, reject_after=None):
        import hashlib
        import test_runner_broker

        expected = self.source(BATCH + SLICE + 13)
        case = test_runner_broker.BrokerTests()
        case.setUp()
        self.addCleanup(case.doCleanups)
        case.launch()
        case.source()
        original_execute = case.backend.execute

        def execute(*args):
            result = original_execute(*args)
            result["artifactRef"] = "signed_ipa"
            result["report"]["artifactSize"] = len(expected)
            result["report"]["artifactDigest"] = hashlib.sha256(expected).hexdigest()
            return result

        case.backend.execute = execute
        case.backend.artifact = lambda handle, ref: self.delegate.artifact(self.channel, ref)
        grant = dict(case.grant(), planDigest=hashlib.sha256(b"{}").hexdigest())
        self.assertEqual(
            case.request(
                "/v1/instances/isign-0123456789abcdef/execute", {"grant": grant, "task": {}}
            )[0],
            200,
        )
        checks = []

        def authorize(principal, operation, binding):
            if operation == "grant":
                checks.append(binding)
                if reject_after is not None and len(checks) > reject_after:
                    return False
            return True

        case.server.authorize = authorize
        resource = next(iter(case.server.instances.values()))
        response = case.server.artifact(resource, "signed_ipa", {})
        self.addCleanup(response.body.close)
        return expected, response.body, checks

    def test_broker_still_authorizes_every_slice_and_verifies_final_size_and_digest(self):
        expected, stream, checks = self.broker_artifact()
        chunks = list(stream)
        self.assertEqual(b"".join(chunks), expected)
        self.assertEqual(len(self.requests), 2)
        self.assertEqual(len(checks), len(chunks) + 1)  # Admission plus each existing 64 KiB slice.

    def test_broker_revocation_stops_a_buffered_batch_at_the_next_slice(self):
        expected, stream, checks = self.broker_artifact(reject_after=2)
        self.assertEqual(next(stream), expected[:SLICE])
        with self.assertRaisesRegex(ValueError, "^BINDING_NOT_CURRENT$"):
            next(stream)
        self.assertEqual(len(checks), 3)
        self.assertEqual(len(self.requests), 1)
