from runner_modules import module_path
import hashlib, hmac, importlib.util, io, json, os, pathlib, tempfile, time, unittest
from unittest.mock import patch
import http.server, threading, socket
from concurrent.futures import ThreadPoolExecutor
import http_fixtures

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load(name):
    s = importlib.util.spec_from_file_location(name, module_path(name))
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


class TransportTests(unittest.TestCase):
    def test_authorizer_exact_response_binding_and_hmac(self):
        m = load("https_transport")
        key = b"K" * 32

        class Http:
            audience = "backend"

            def request(self, path, body, **kw):
                self.request_body = json.loads(body)
                req = self.request_body
                now = int(time.time() * 1000)
                report = {
                    "version": 1,
                    "operation": "authorize-binding",
                    "requestOperation": req["operation"],
                    "binding": req["binding"],
                    "nonce": req["nonce"],
                    "audience": req["audience"],
                    "authorized": True,
                    "checkedAt": now,
                    "expiresAt": now + 15000,
                }
                return m.canonical(
                    {
                        "report": report,
                        "attestation": hmac.new(
                            key, m.canonical(report), hashlib.sha256
                        ).hexdigest(),
                    }
                )

        http = Http()
        authorize = m.HttpBindingAuthorizer(http, key)
        self.assertTrue(authorize("principal", "grant", {"ownerId": "o"}))
        self.assertEqual(http.request_body["binding"], {"ownerId": "o"})
        http.request = lambda *a, **kw: b'{"report":{"authorized":true},"attestation":"forged"}'
        with self.assertRaises(ValueError):
            authorize("principal", "grant", {"ownerId": "o"})


class KeepaliveTests(http_fixtures.HTTPFixtures):
    def transport(self, *, persistent=True, pin=None, loopback=False):
        parent = self
        self.connections = 0
        self.requests = []
        self.close_next = False
        self.fail_next = False

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def setup(self):
                super().setup()
                parent.connections += 1

            def do_POST(self):
                body = self.rfile.read(int(self.headers["content-length"]))
                parent.requests.append(body)
                if parent.fail_next:
                    parent.fail_next = False
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.close_connection = True
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                if parent.close_next:
                    self.send_header("Connection", "close")
                    parent.close_next = False
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.socket = self.context.wrap_socket(server.socket, server_side=True)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()

        def cleanup():
            server.shutdown()
            server.server_close()
            worker.join(2)

        self.addCleanup(cleanup)
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        certificate = x509.load_pem_x509_certificate(
            (pathlib.Path(self.temp.name) / "cert.pem").read_bytes()
        )
        expected_pin = hashlib.sha256(
            certificate.public_bytes(serialization.Encoding.DER)
        ).hexdigest()
        m = load("https_transport")
        kwargs = {}
        if loopback:
            deployment = load("personal_deployment")

            def connection(host, port, **kw):
                result = deployment.LoopbackHTTPSConnection(host, port, **kw)
                result.private_address = "127.0.0.1"
                return result

            kwargs["connection_factory"] = connection
        transport = m.PinnedHTTPS(
            "https://localhost:" + str(server.server_port),
            token="T" * 32,
            audience="test",
            certificate_sha256=pin or expected_pin,
            ssl_context=self.client_context,
            reuse_connections=persistent,
            **kwargs,
        )
        self.addCleanup(transport.close)
        return transport

    def test_reuses_tls_but_sends_every_authorization_request(self):
        transport = self.transport()
        for body in (b"first", b"second", b"third"):
            self.assertEqual(transport.request("/api/internal/runner/authorize", body), body)
        self.assertEqual(self.requests, [b"first", b"second", b"third"])
        self.assertEqual(self.connections, 1)

    def test_peer_close_reconnects_and_rechecks_certificate_pin(self):
        transport = self.transport()
        self.close_next = True
        transport.request("/api/internal/runner/authorize", b"first")
        transport.pin = "0" * 64
        with self.assertRaisesRegex(ValueError, "TLS_PEER_PIN_MISMATCH"):
            transport.request("/api/internal/runner/authorize", b"second")
        self.assertEqual(self.requests, [b"first"])

    def test_default_transport_closes_each_connection(self):
        transport = self.transport(persistent=False)
        transport.request("/api/internal/runner/authorize", b"first")
        transport.request("/api/internal/runner/authorize", b"second")
        self.assertEqual(self.connections, 2)

    def test_idle_authorizer_connection_is_replaced_before_next_request(self):
        transport = self.transport()
        transport.request("/api/internal/runner/authorize", b"first")
        transport._connection_used_at = time.monotonic() - 31
        transport.request("/api/internal/runner/authorize", b"second")
        self.assertEqual(self.requests, [b"first", b"second"])
        self.assertEqual(self.connections, 2)

    def test_loopback_tls_disables_nagle_for_small_authorization_requests(self):
        transport = self.transport(loopback=True)
        transport.request("/api/internal/runner/authorize", b"first")
        self.assertNotEqual(
            transport._connection.sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY), 0
        )

    def test_concurrent_authorizations_keep_responses_bound_to_their_requests(self):
        transport = self.transport()
        bodies = [str(index).encode() for index in range(8)]
        with ThreadPoolExecutor(max_workers=4) as workers:
            results = list(
                workers.map(
                    lambda body: transport.request("/api/internal/runner/authorize", body), bodies
                )
            )
        self.assertEqual(results, bodies)
        self.assertCountEqual(self.requests, bodies)
        self.assertEqual(self.connections, 1)

    def test_failed_request_is_not_replayed_and_next_request_uses_fresh_tls(self):
        transport = self.transport()
        self.fail_next = True
        with self.assertRaises(http.client.RemoteDisconnected):
            transport.request("/api/internal/runner/authorize", b"first")
        self.assertEqual(self.requests, [b"first"])
        self.assertEqual(transport.request("/api/internal/runner/authorize", b"second"), b"second")
        self.assertEqual(self.requests, [b"first", b"second"])
        self.assertEqual(self.connections, 2)


if __name__ == "__main__":
    unittest.main()
