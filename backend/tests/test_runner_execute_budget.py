"""Trusted execute deadlines; synthetic subprocesses and actual TLS sockets only."""

import base64, hashlib, hmac, json, pathlib, socket, subprocess, sys, threading, time, unittest
from http_fixtures import load
import http_fixtures
from protocol.codec import canonical


class StdioBudgetTests(unittest.TestCase):
    def setUp(self):
        self.m = load("stdio_channel")
        self.key = b"K" * 32
        self.identity = {
            "ownerId": "o",
            "jobId": "j",
            "instanceId": "sandbox",
            "expiresAt": int(time.time() * 1000) + 3000,
        }

    def process(self, delay=0.15):
        program = """import sys,struct,json,base64,time
size=struct.unpack('>I',sys.stdin.buffer.read(4))[0]
sys.stdin.buffer.read(size)
time.sleep(float(sys.argv[1]))
reply=json.dumps({'status':'200 OK','body':base64.b64encode(b'ok').decode()}).encode()
sys.stdout.buffer.write(struct.pack('>I',len(reply))+reply);sys.stdout.buffer.flush()
time.sleep(10)
"""
        process = subprocess.Popen(
            [sys.executable, "-u", "-c", program, str(delay)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )

        def cleanup():
            process.kill()
            process.wait(timeout=2)
            process.stdin.close()
            process.stdout.close()

        self.addCleanup(cleanup)
        return process

    def envelope(self, change=None):
        now = int(time.time() * 1000)
        grant = {
            "ownerId": "o",
            "jobId": "j",
            "leaseToken": "l",
            "connectionId": "c",
            "connectionGeneration": 1,
            "deviceId": "d",
            "uploadDigest": "a" * 64,
            "taskNonce": "n",
            "isolationInstanceId": "sandbox",
            "expiresAt": now + 2000,
            "planDigest": hashlib.sha256(b"{}").hexdigest(),
        }
        payload = {"grant": grant, "task": {}, "proof": {}}
        request = {
            "binding": {**self.identity, "nonce": "n" * 24, "expiresAt": now + 1000},
            "operation": "execute",
            "audience": "guest",
            "payloadDigest": hashlib.sha256(canonical(payload)).hexdigest(),
        }
        if change:
            change(request, payload)
        signature = hmac.new(
            self.key, b"isign-guest-request-v1\0" + canonical(request), hashlib.sha256
        ).hexdigest()
        return canonical({"request": request, "attestation": signature, "payload": payload})

    def test_invalid_execute_rejected_without_worker_or_wire_write(self):
        changes = [
            lambda r, p: r.update(audience="foreign"),
            lambda r, p: r.update(operation="analyze"),
            lambda r, p: r["binding"].update(ownerId="foreign"),
            lambda r, p: r["binding"].update(expiresAt=1),
            lambda r, p: p["grant"].update(ownerId="foreign"),
            lambda r, p: p["grant"].update(expiresAt=1),
            lambda r, p: r.update(payloadDigest="0" * 64),
        ]
        for change in changes:
            with self.subTest(change=change):
                process = self.process(0)
                http = self.m.StdioHTTP(
                    process, self.identity, self.key, "guest", "T" * 32, timeout=0.04
                )
                with self.assertRaisesRegex(ValueError, "STDIO_EXECUTE"):
                    http.request("/v1/guest/execute", self.envelope(change))
                self.assertIsNone(process.poll())

    def test_grant_expiry_kills_and_reaps_process(self):
        process = self.process(0.5)
        http = self.m.StdioHTTP(process, self.identity, self.key, "guest", "T" * 32, timeout=0.04)
        raw = json.loads(self.envelope())
        raw["payload"]["grant"]["expiresAt"] = int(time.time() * 1000) + 100
        raw["request"]["payloadDigest"] = hashlib.sha256(canonical(raw["payload"])).hexdigest()
        raw["attestation"] = hmac.new(
            self.key,
            b"isign-guest-request-v1\0" + canonical(raw["request"]),
            hashlib.sha256,
        ).hexdigest()
        with self.assertRaisesRegex(ValueError, "STDIO_REQUEST_TIMEOUT"):
            http.request("/v1/guest/execute", canonical(raw))
        self.assertIsNotNone(process.poll())
        self.assertFalse(any(t.name == "isign-stdio-request" for t in threading.enumerate()))

    def test_recomputed_payload_digest_does_not_authorize_foreign_grant_or_bad_mac(self):
        for field, value in [
            ("ownerId", "foreign"),
            ("jobId", "foreign"),
            ("isolationInstanceId", "foreign"),
            ("expiresAt", 1),
            ("expiresAt", int(time.time() * 1000) + 900000),
            ("connectionGeneration", 0),
            ("planDigest", "0" * 64),
            ("MAC", "0" * 64),
        ]:
            with self.subTest(field=field, value=value):
                process = self.process(0)
                http = self.m.StdioHTTP(
                    process, self.identity, self.key, "guest", "T" * 32, timeout=0.04
                )
                raw = json.loads(self.envelope())
                if field != "MAC":
                    raw["payload"]["grant"][field] = value
                raw["request"]["payloadDigest"] = hashlib.sha256(
                    canonical(raw["payload"])
                ).hexdigest()
                raw["attestation"] = hmac.new(
                    self.key,
                    b"isign-guest-request-v1\0" + canonical(raw["request"]),
                    hashlib.sha256,
                ).hexdigest()
                if field == "MAC":
                    raw["attestation"] = value
                with self.assertRaisesRegex(ValueError, "STDIO_EXECUTE"):
                    http.request("/v1/guest/execute", canonical(raw))
                self.assertIsNone(process.poll())

    def test_abort_cannot_claim_process_cleanup_or_clear_keys_if_wait_fails(self):
        from types import SimpleNamespace

        process = SimpleNamespace(
            kill=lambda: None,
            wait=lambda **kw: (_ for _ in ()).throw(subprocess.TimeoutExpired("synthetic", 5)),
            stdin=None,
            stdout=None,
            stderr=None,
        )
        http = self.m.StdioHTTP(process, self.identity, self.key, "guest", "T" * 32)
        delegate = SimpleNamespace(key=self.key, resolve=lambda _: http)
        channel = {
            "instanceId": "sandbox",
            "process": process,
            "http": http,
            "stdioDelegate": delegate,
        }
        owner = load("stdio_backend").DockerStdioGuestChannel("/configured/docker")
        owner.channels["sandbox"] = channel
        with self.assertRaisesRegex(ValueError, "STDIO_PROCESS_CLEANUP_UNCONFIRMED"):
            owner.abort(channel)
        self.assertEqual(http.key, self.key)
        self.assertEqual(delegate.key, self.key)
        self.assertIn("sandbox", owner.channels)
        self.assertTrue(channel["revoked"])


class HostBudgetTests(unittest.TestCase):
    setUpClass = classmethod(http_fixtures.HTTPFixtures.setUpClass.__func__)
    broker = http_fixtures.HTTPFixtures.broker
    connection = http_fixtures.HTTPFixtures.connection

    def execute_request(self, case, **overrides):
        task = {}
        grant = dict(
            case.grant(), taskNonce="execute", planDigest=hashlib.sha256(b"{}").hexdigest()
        )
        grant.update(overrides)
        body = json.dumps({"grant": grant, "task": task}).encode()
        return (
            "POST /v1/instances/isign-0123456789abcdef/execute HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer "
            + case.token
            + "\r\nX-Runner-Audience: test-audience\r\nContent-Type: application/json\r\nContent-Length: "
            + str(len(body))
            + "\r\n\r\n"
        ).encode() + body

    def read_response(self, client):
        data = b""
        while True:
            chunk = client.recv(65536)
            if not chunk:
                return data
            data += chunk

    def test_disconnect_and_shutdown_physically_cancel_compute(self):
        for failure in ("disconnect", "shutdown"):
            with self.subTest(failure=failure):
                case = self.broker()
                case.source()
                started = threading.Event()
                destroyed = threading.Event()
                original = case.backend.execute

                def execute(*args):
                    started.set()
                    destroyed.wait(2)
                    return original(*args)

                def destroy(handle):
                    case.calls.append("destroy")
                    destroyed.set()
                    return True

                case.backend.execute = execute
                case.backend.destroy = destroy
                host, client, worker = self.connection(case, 0.1)
                client.sendall(self.execute_request(case))
                self.assertTrue(started.wait(1))
                if failure == "disconnect":
                    client.close()
                else:
                    host.close()
                self.assertTrue(destroyed.wait(0.5))
                host.close()
                self.assertFalse(worker.is_alive())
                resource = next(iter(case.server.instances.values()))
                self.assertNotIn("artifact", resource)
                self.assertFalse(case.state.pending())

    def test_budget_only_after_broker_auth_complete_grant_and_plan(self):
        from unittest.mock import patch

        for failure in ("token", "expired", "owner", "plan", "malformed", "replay"):
            with self.subTest(failure=failure):
                case = self.broker()
                case.source()
                request = self.execute_request(case)
                if failure == "token":
                    request = request.replace(case.token.encode(), b"foreign")
                elif failure == "expired":
                    request = self.execute_request(case, expiresAt=1)
                elif failure == "owner":
                    request = self.execute_request(case, ownerId="foreign")
                elif failure == "plan":
                    request = self.execute_request(case, planDigest="0" * 64)
                elif failure == "malformed":
                    request = request.replace(b'"grant":', b'"wrong":')
                elif failure == "replay":
                    case.server.consume("execute", "execute")
                host, client, worker = self.connection(case, 0.3)
                with patch.object(
                    self.module.SocketBody,
                    "authorize_execute",
                    side_effect=AssertionError("invalid request must not authorize compute"),
                ) as authorize:
                    client.sendall(request)
                    raw = self.read_response(client)
                    self.assertNotIn(b"200 Response", raw)
                    authorize.assert_not_called()
                host.close()
                self.assertFalse(worker.is_alive())

    def test_absolute_compute_expiry_cancels_backend(self):
        case = self.broker()
        case.source()
        started = threading.Event()
        destroyed = threading.Event()
        original = case.backend.execute

        def execute(*args):
            started.set()
            destroyed.wait(2)
            return original(*args)

        def destroy(handle):
            case.calls.append("destroy")
            destroyed.set()
            return True

        case.backend.execute = execute
        case.backend.destroy = destroy
        host, client, worker = self.connection(case, 0.08)
        client.sendall(self.execute_request(case, expiresAt=int(time.time() * 1000) + 200))
        self.assertTrue(started.wait(1))
        self.assertTrue(destroyed.wait(0.6))
        self.assertNotIn(b"200 Response", self.read_response(client))
        host.close()
        self.assertFalse(worker.is_alive())
        self.assertFalse(case.state.pending())

    def test_unconfirmed_cleanup_retains_tombstone_busy_and_no_artifact(self):
        case = self.broker()
        case.source()
        started = threading.Event()
        attempted = threading.Event()
        original = case.backend.execute

        def execute(*args):
            started.set()
            attempted.wait(2)
            return original(*args)

        def destroy(handle):
            attempted.set()
            return False

        case.backend.execute = execute
        case.backend.destroy = destroy
        host, client, worker = self.connection(case, 0.1)
        # The helper registers close, but this test intentionally requires failure.
        self._cleanups = [entry for entry in self._cleanups if entry[0] != host.close]
        client.sendall(self.execute_request(case))
        self.assertTrue(started.wait(1))
        client.close()
        self.assertTrue(attempted.wait(0.5))
        worker.join(1)
        with self.assertRaisesRegex(ValueError, "HTTPS_HOST_CLEANUP_UNCONFIRMED"):
            host.close()
        self.assertFalse(worker.is_alive())
        resource = next(iter(case.server.instances.values()))
        self.assertTrue(resource["dead"])
        self.assertTrue(resource["busy"])
        self.assertNotIn("artifact", resource)
        self.assertTrue(case.state.pending())

    def test_nonce_replay_never_destroys_existing_work(self):
        case = self.broker()
        case.source()
        case.server.consume("execute", "execute")
        host, client, worker = self.connection(case, 0.3)
        client.sendall(self.execute_request(case))
        self.assertIn(b"409 Response", self.read_response(client))
        host.close()
        self.assertNotIn("destroy", case.calls)

    def test_completed_compute_failure_replies_only_after_confirmed_destruction(self):
        from protocol.errors import ExpectedGuestFailure

        for error, status, code in (
            (
                ValueError("SIGNATURE_CONTAINER_INVALID private details"),
                503,
                "BROKER_OPERATION_FAILED",
            ),
            (ExpectedGuestFailure("ENTITLEMENTS_INVALID"), 422, "ENTITLEMENTS_INVALID"),
        ):
            with self.subTest(status=status):
                case = self.broker()
                case.source()
                destroyed = threading.Event()
                cleanup_started = threading.Event()
                release_cleanup = threading.Event()
                original_destroy = case.backend.destroy

                def execute(*args):
                    raise error

                def destroy(handle):
                    cleanup_started.set()
                    release_cleanup.wait(2)
                    result = original_destroy(handle)
                    destroyed.set()
                    return result

                case.backend.execute = execute
                case.backend.destroy = destroy
                host, client, worker = self.connection(case)
                client.sendall(self.execute_request(case))
                self.assertTrue(cleanup_started.wait(1))
                client.settimeout(0.04)
                try:
                    with self.assertRaises(socket.timeout):
                        client.recv(1)
                finally:
                    release_cleanup.set()
                    client.settimeout(3)
                raw = self.read_response(client)
                self.assertIn(f"{status} Response".encode(), raw)
                self.assertEqual(json.loads(raw.split(b"\r\n\r\n", 1)[1]), {"error": code})
                self.assertTrue(destroyed.is_set())
                self.assertEqual(case.calls.count("destroy"), 1)
                resource = next(iter(case.server.instances.values()))
                self.assertTrue(resource["dead"])
                self.assertTrue(resource["destroyed"])
                self.assertNotIn("artifact", resource)
                self.assertFalse(case.state.pending())
                host.close()
                self.assertFalse(worker.is_alive())

    def test_completed_failure_keeps_cancellation_monitor_until_http_response(self):
        case = self.broker()
        case.source()
        reply_ready = threading.Event()
        release_reply = threading.Event()
        original_dispatch = case.server.dispatch

        def execute(*args):
            raise ValueError("SIGNATURE_CONTAINER_INVALID")

        def dispatch(*args, **kwargs):
            response = original_dispatch(*args, **kwargs)
            reply_ready.set()
            release_reply.wait(2)
            return response

        case.backend.execute = execute
        case.server.dispatch = dispatch
        host, client, worker = self.connection(case)
        client.sendall(self.execute_request(case))
        self.assertTrue(reply_ready.wait(1))
        self.assertEqual(case.calls.count("destroy"), 1)
        client.sendall(b"GET /private HTTP/1.1\r\n\r\n")
        try:
            self.assertEqual(self.read_response(client), b"")
        finally:
            release_reply.set()
        worker.join(1)
        host.close()
        self.assertEqual(case.calls.count("destroy"), 1)
        self.assertFalse(worker.is_alive())

    def test_failed_compute_cleanup_keeps_deadline_and_disconnect_cancellation(self):
        for failure in ("deadline", "disconnect", "pipelined"):
            with self.subTest(failure=failure):
                case = self.broker()
                case.source()
                cleanup_started = threading.Event()
                release_cleanup = threading.Event()
                original_destroy = case.backend.destroy

                def execute(*args):
                    raise ValueError("SIGNATURE_CONTAINER_INVALID")

                def destroy(handle):
                    cleanup_started.set()
                    release_cleanup.wait(2)
                    return original_destroy(handle)

                case.backend.execute = execute
                case.backend.destroy = destroy
                host, client, worker = self.connection(case)
                grant = (
                    {"expiresAt": int(time.time() * 1000) + 250} if failure == "deadline" else {}
                )
                client.sendall(self.execute_request(case, **grant))
                self.assertTrue(cleanup_started.wait(1))
                if failure == "disconnect":
                    client.close()
                elif failure == "pipelined":
                    client.sendall(b"GET /private HTTP/1.1\r\n\r\n")
                try:
                    if failure != "disconnect":
                        self.assertEqual(self.read_response(client), b"")
                finally:
                    release_cleanup.set()
                worker.join(1)
                host.close()
                resource = next(iter(case.server.instances.values()))
                self.assertTrue(resource["dead"])
                self.assertTrue(resource["destroyed"])
                self.assertNotIn("artifact", resource)
                self.assertFalse(case.state.pending())
                self.assertEqual(case.calls.count("destroy"), 1)
                self.assertFalse(worker.is_alive())

    def test_failed_compute_unconfirmed_destruction_never_sends_an_error_reply(self):
        case = self.broker()
        case.source()

        def execute(*args):
            raise ValueError("SIGNATURE_CONTAINER_INVALID")

        case.backend.execute = execute
        case.backend.destroy = lambda handle: False
        host, client, worker = self.connection(case)
        self._cleanups = [entry for entry in self._cleanups if entry[0] != host.close]
        client.sendall(self.execute_request(case))
        self.assertEqual(self.read_response(client), b"")
        worker.join(1)
        with self.assertRaisesRegex(ValueError, "HTTPS_HOST_CLEANUP_UNCONFIRMED"):
            host.close()
        resource = next(iter(case.server.instances.values()))
        self.assertTrue(resource["dead"])
        self.assertTrue(resource["busy"])
        self.assertNotIn("artifact", resource)
        self.assertTrue(case.state.pending())


class ArtifactBudgetTests(http_fixtures.HTTPFixtures):
    read_response = HostBudgetTests.read_response

    def prepare(self, *, expires_at=None):
        case = self.broker()
        case.source()
        grant = dict(
            case.grant(), taskNonce="execute", planDigest=hashlib.sha256(b"{}").hexdigest()
        )
        if expires_at is not None:
            grant["expiresAt"] = expires_at
        self.assertEqual(
            case.request(
                "/v1/instances/isign-0123456789abcdef/execute", {"grant": grant, "task": {}}
            )[0],
            200,
        )
        return case, next(iter(case.server.instances.values()))

    def artifact_request(self, case, *, ref="artifact-1", body=b"{}"):
        return (
            f"POST /v1/instances/isign-0123456789abcdef/artifacts/{ref} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {case.token}"
            f"\r\nX-Runner-Audience: test-audience\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n"
        ).encode() + body

    def test_valid_artifact_transfer_outlives_admission_timeout_within_same_grant(self):
        case, resource = self.prepare()

        def artifact(*args):
            yield b"SYNTHETIC-"
            time.sleep(0.25)
            yield b"ARTIFACT"

        case.backend.artifact = artifact
        host, client, worker = self.connection(case, 0.1)
        client.sendall(self.artifact_request(case))
        raw = self.read_response(client)
        self.assertIn(b"200 Response", raw)
        self.assertEqual(raw.split(b"\r\n\r\n", 1)[1], b"SYNTHETIC-ARTIFACT")
        self.assertFalse(resource["busy"])
        self.assertTrue(resource["artifact"]["used"])
        self.assertNotIn("destroy", case.calls)
        host.close()
        self.assertFalse(worker.is_alive())

    def test_invalid_artifact_requests_never_extend_the_admission_budget(self):
        from unittest.mock import patch

        for failure in ("token", "ref", "body", "used", "expired", "owner", "instance"):
            with self.subTest(failure=failure):
                case, resource = self.prepare()
                request = self.artifact_request(case)
                if failure == "token":
                    request = request.replace(case.token.encode(), b"foreign")
                elif failure == "ref":
                    request = self.artifact_request(case, ref="wrong")
                elif failure == "body":
                    request = self.artifact_request(case, body=b'{"extra":true}')
                elif failure == "used":
                    resource["artifact"]["used"] = True
                elif failure == "expired":
                    resource["artifact"]["grant"]["expiresAt"] = 1
                elif failure == "owner":
                    resource["artifact"]["grant"]["ownerId"] = "foreign"
                elif failure == "instance":
                    resource["expiresAt"] = resource["artifact"]["grant"]["expiresAt"] - 1
                host, client, worker = self.connection(case)
                with patch.object(
                    self.module.SocketBody,
                    "authorize_execute",
                    side_effect=AssertionError("invalid artifact must not extend budget"),
                ) as authorize:
                    client.sendall(request)
                    raw = self.read_response(client)
                    self.assertNotIn(b"200 Response", raw)
                    authorize.assert_not_called()
                host.close()
                self.assertFalse(worker.is_alive())

    def test_artifact_admission_failure_releases_busy_without_consuming_reference(self):
        from types import SimpleNamespace

        case, resource = self.prepare()

        def authorize(*args):
            raise ValueError("EXECUTE_ADMISSION_EXPIRED")

        with self.assertRaisesRegex(ValueError, "EXECUTE_ADMISSION_EXPIRED"):
            case.server.artifact(
                resource,
                "artifact-1",
                {},
                execution_source=SimpleNamespace(authorize_execute=authorize),
            )
        self.assertFalse(resource["busy"])
        self.assertFalse(resource["artifact"]["used"])

    def test_closing_artifact_response_before_first_chunk_releases_busy(self):
        case, resource = self.prepare()

        def artifact(*args):
            raise AssertionError("guest must not be read before response iteration")

        case.backend.artifact = artifact
        response = case.server.artifact(resource, "artifact-1", {})
        response.body.close()
        self.assertFalse(resource["busy"])

    def test_abandoning_admitted_artifact_retires_resource_before_releasing_busy(self):
        from types import SimpleNamespace

        case, resource = self.prepare()
        cancelled = threading.Event()
        context = SimpleNamespace(check=lambda: None, cancel=cancelled.set)
        source = SimpleNamespace(authorize_execute=lambda *args: context)
        response = case.server.artifact(resource, "artifact-1", {}, execution_source=source)
        response.body.close()
        self.assertTrue(cancelled.is_set())
        self.assertTrue(resource["dead"])
        self.assertTrue(resource["busy"])
        self.assertNotIn("artifact", resource)

    def test_stale_authorized_artifact_request_cannot_reuse_a_consumed_reference(self):
        from types import SimpleNamespace

        case, resource = self.prepare()
        authorized = threading.Event()
        resume = threading.Event()
        extended = threading.Event()
        original_allowed = case.server.allowed
        outcome = {}

        def allowed(operation, binding):
            if operation == "grant" and threading.current_thread().name == "stale-artifact":
                authorized.set()
                resume.wait(2)
            return original_allowed(operation, binding)

        def authorize(*args):
            extended.set()
            return SimpleNamespace(check=lambda: None, cancel=lambda: None)

        def stale_request():
            try:
                response = case.server.artifact(
                    resource,
                    "artifact-1",
                    {},
                    execution_source=SimpleNamespace(authorize_execute=authorize),
                )
                outcome["body"] = b"".join(response.body)
            except case.m.BrokerError as error:
                outcome["error"] = (error.code, error.status)

        case.server.allowed = allowed
        stale = threading.Thread(target=stale_request, name="stale-artifact")
        stale.start()
        self.assertTrue(authorized.wait(1))
        try:
            current = case.server.artifact(resource, "artifact-1", {})
            self.assertEqual(b"".join(current.body), b"SYNTHETIC-ARTIFACT")
        finally:
            resume.set()
        stale.join(1)
        self.assertFalse(stale.is_alive())
        self.assertEqual(outcome.get("error"), ("ARTIFACT_UNAVAILABLE", 404))
        self.assertFalse(extended.is_set())

    def test_artifact_response_budget_uses_grant_expiry_and_existing_fifteen_minute_cap(self):
        from types import SimpleNamespace

        for remaining in (300, 1800000):
            with self.subTest(remaining=remaining):
                case, resource = self.prepare()
                resource["expiresAt"] = case.now + remaining + 1
                resource["artifact"]["grant"]["expiresAt"] = case.now + remaining
                admitted = []

                def authorize(expires_at, cancel):
                    admitted.append(expires_at)
                    return SimpleNamespace(check=lambda: None, cancel=cancel)

                response = case.server.artifact(
                    resource,
                    "artifact-1",
                    {},
                    execution_source=SimpleNamespace(authorize_execute=authorize),
                )
                response.body.close()
                self.assertEqual(admitted, [case.now + min(remaining, 900000)])
                self.assertFalse(resource["busy"])

    def test_artifact_body_admission_keeps_the_original_request_timeout(self):
        from unittest.mock import patch

        case, resource = self.prepare()
        host, client, worker = self.connection(case, 0.1)
        request = self.artifact_request(case)
        with patch.object(
            self.module.SocketBody,
            "authorize_execute",
            side_effect=AssertionError("partial body must not extend budget"),
        ) as authorize:
            client.sendall(request[:-1])
            self.assertEqual(self.read_response(client), b"")
            authorize.assert_not_called()
        host.close()
        self.assertFalse(resource["busy"])
        self.assertFalse(resource["artifact"]["used"])
        self.assertFalse(worker.is_alive())

    def test_artifact_deadline_disconnect_and_pipelining_physically_cancel_transfer(self):
        for failure in ("deadline", "disconnect", "pipelined", "shutdown"):
            with self.subTest(failure=failure):
                expiry = int(time.time() * 1000) + 300 if failure == "deadline" else None
                case, resource = self.prepare(expires_at=expiry)
                destroyed = threading.Event()
                streaming = threading.Event()
                original_destroy = case.backend.destroy

                def artifact(*args):
                    yield b"SYNTHETIC-"
                    streaming.set()
                    destroyed.wait(2)
                    yield b"ARTIFACT"

                def destroy(handle):
                    result = original_destroy(handle)
                    destroyed.set()
                    return result

                case.backend.artifact = artifact
                case.backend.destroy = destroy
                host, client, worker = self.connection(case)
                client.sendall(self.artifact_request(case))
                first = b""
                while not first.endswith(b"SYNTHETIC-"):
                    chunk = client.recv(65536)
                    self.assertTrue(chunk, "transfer closed before the first artifact chunk")
                    first += chunk
                self.assertTrue(streaming.wait(1))
                if failure == "disconnect":
                    client.close()
                elif failure == "pipelined":
                    client.sendall(b"GET /private HTTP/1.1\r\n\r\n")
                elif failure == "shutdown":
                    host.close()
                self.assertTrue(destroyed.wait(0.7))
                if failure != "disconnect":
                    self.assertEqual(self.read_response(client), b"")
                host.close()
                self.assertTrue(resource["dead"])
                self.assertTrue(resource["destroyed"])
                self.assertNotIn("artifact", resource)
                self.assertFalse(case.state.pending())
                self.assertEqual(case.calls.count("destroy"), 1)
                self.assertFalse(worker.is_alive())
