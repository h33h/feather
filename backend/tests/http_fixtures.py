from runner_modules import module_path
import datetime, hashlib, importlib.util, pathlib, socket, ssl, subprocess, sys, tempfile, threading, time, unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, module_path(name))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class HTTPFixtures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        root = pathlib.Path(cls.temp.name)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
            .sign(key, hashes.SHA256())
        )
        (root / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (root / "key.pem").write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        cls.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.context.load_cert_chain(root / "cert.pem", root / "key.pem")
        cls.client_context = ssl.create_default_context(cafile=str(root / "cert.pem"))
        cls.module = load("http_host")

    def broker(self):
        import test_runner_broker

        case = test_runner_broker.BrokerTests("test_source_analysis_signed_response_and_destroy")
        case.setUp()
        self.addCleanup(case.doCleanups)
        case.launch()
        root = pathlib.Path(case.temp.name)
        case.partial = root / "partial-source"
        case.started = threading.Event()
        case.received = 0
        original_destroy = case.backend.destroy

        def destroy(handle):
            case.partial.unlink(missing_ok=True)
            return original_destroy(handle)

        def upload(handle, chunks, digest):
            hash_ = hashlib.sha256()
            size = 0
            case.started.set()
            with case.partial.open("xb") as target:
                for block in chunks:
                    target.write(block)
                    size += len(block)
                    hash_.update(block)
                    case.received += len(block)
            return {"sha256": hash_.hexdigest(), "size": size}

        case.backend.destroy = destroy
        case.backend.upload_source = upload
        return case

    def connection(self, case, timeout=0.3):
        host = self.module.HTTPSBrokerHost(
            case.server, self.context, workers=1, request_timeout=timeout
        )
        server, client = socket.socketpair()
        host.pending.put(server)
        worker = threading.Thread(target=host._worker, name="test-concrete-https")
        host.threads = [worker]
        worker.start()
        self.addCleanup(host.close)
        client = self.client_context.wrap_socket(client, server_hostname="localhost")
        client.settimeout(3)
        self.addCleanup(client.close)
        return host, client, worker

    def request_header(self, case, framing):
        return (
            "POST /v1/instances/isign-0123456789abcdef/source HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer "
            + case.token
            + "\r\nX-Runner-Audience: test-audience\r\nContent-Type: application/octet-stream\r\nX-Source-Digest: "
            + case.grant()["uploadDigest"]
            + "\r\n"
            + framing
            + "\r\n\r\n"
        ).encode()
