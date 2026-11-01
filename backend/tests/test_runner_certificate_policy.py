from runner_modules import module_path

"""Synthetic certificate policy regressions, no account keys or profiles."""
import datetime, hashlib, importlib.util, pathlib, unittest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, ObjectIdentifier

s = importlib.util.spec_from_file_location("policy", module_path("linux_certificate_policy"))
p = importlib.util.module_from_spec(s)
s.loader.exec_module(p)


class CertificatePolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rootkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.leafkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.root = cls.cert(True, [], cls.rootkey)

    @classmethod
    def cert(cls, ca, extensions, key):
        now = datetime.datetime.now(datetime.timezone.utc)
        name = x509.Name(
            [
                x509.NameAttribute(
                    NameOID.COMMON_NAME, "Synthetic CA" if ca else "Synthetic Distribution"
                ),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "TEAM"),
            ]
        )
        b = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name if ca else cls.root.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=1 if ca else None), True)
            .add_extension(
                x509.KeyUsage(True, False, False, False, False, ca, ca, False, False), True
            )
        )
        if not ca:
            b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), True)
        for oid, value in extensions:
            b = b.add_extension(x509.UnrecognizedExtension(ObjectIdentifier(oid), value), True)
        return b.sign(cls.rootkey, hashes.SHA256())

    def check(self, extensions):
        c = self.cert(False, extensions, self.leafkey)
        raw = c.public_bytes(serialization.Encoding.DER)
        return p.LinuxCertificatePolicy([self.root.public_bytes(serialization.Encoding.DER)])(
            raw, {"teamId": "TEAM", "fingerprint": hashlib.sha256(raw).hexdigest().upper()}
        )

    def test_companion_requires_iphone_marker(self):
        self.assertTrue(
            self.check(
                [
                    ("1.2.840.113635.100.6.1.4", b"\x05\x00"),
                    ("1.2.840.113635.100.6.1.7", b"\x05\x00"),
                ]
            )
        )
        with self.assertRaisesRegex(ValueError, "DISTRIBUTION_CERTIFICATE_MARKER_REQUIRED"):
            self.check([("1.2.840.113635.100.6.1.7", b"\x05\x00")])

    def test_unknown_critical_and_wrong_marker_value_rejected(self):
        for oid, val in [
            ("1.2.840.113635.100.6.1.99", b"\x05\x00"),
            ("1.2.840.113635.100.6.1.7", b"\x05\x01\x00"),
        ]:
            with self.assertRaisesRegex(ValueError, "UNKNOWN_CRITICAL"):
                self.check([("1.2.840.113635.100.6.1.4", b"\x05\x00"), (oid, val)])

    def test_tampered_leaf_rejected(self):
        c = self.cert(False, [("1.2.840.113635.100.6.1.4", b"\x05\x00")], self.leafkey)
        raw = bytearray(c.public_bytes(serialization.Encoding.DER))
        raw[-1] ^= 1
        with self.assertRaises(Exception):
            p.LinuxCertificatePolicy([self.root.public_bytes(serialization.Encoding.DER)])(
                bytes(raw),
                {"teamId": "TEAM", "fingerprint": hashlib.sha256(raw).hexdigest().upper()},
            )

    def test_sha1_leaf_and_nonpinned_anchor_rejected(self):
        c = self.cert(False, [("1.2.840.113635.100.6.1.4", b"\x05\x00")], self.leafkey)
        # Change both DER algorithm identifiers without manufacturing a weak private signature.
        for weak_leaf in (True, False):
            leaf = c.public_bytes(serialization.Encoding.DER)
            root = self.root.public_bytes(serialization.Encoding.DER)
            if weak_leaf:
                leaf = leaf.replace(
                    bytes.fromhex("2a864886f70d01010b"), bytes.fromhex("2a864886f70d010105")
                )
            else:
                root = root.replace(
                    bytes.fromhex("2a864886f70d01010b"), bytes.fromhex("2a864886f70d010105")
                )
            with self.assertRaisesRegex(ValueError, "ALGORITHM_REJECTED"):
                p.LinuxCertificatePolicy([root])(
                    leaf,
                    {"teamId": "TEAM", "fingerprint": hashlib.sha256(leaf).hexdigest().upper()},
                )
