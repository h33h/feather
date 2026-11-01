"""Exact pinned chain code-signing policy, without OpenSSL ignore-critical."""

import datetime, hashlib
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID, NameOID

SUPPORTED_DISTRIBUTION_MARKERS = {"1.2.840.113635.100.6.1.4"}
# Exact DER anchor: SHA1 is allowed only for its self-signature, never chain links.
APPLE_LEGACY_ROOT_SHA256 = "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024"
# Apple Distribution companion marker; iPhone Distribution marker remains mandatory.
APPLE_DISTRIBUTION_COMPANION = "1.2.840.113635.100.6.1.7"
SUPPORTED_WWDR_MARKERS = {"1.2.840.113635.100.6.2.1", "1.2.840.113635.100.6.2.15"}


class LinuxCertificatePolicy:
    def __init__(
        self,
        chain_der,
        *,
        distribution_markers=SUPPORTED_DISTRIBUTION_MARKERS,
        clock=lambda: datetime.datetime.now(datetime.timezone.utc),
    ):
        if (
            not 1 <= len(chain_der) <= 5
            or not distribution_markers
            or not set(distribution_markers) <= SUPPORTED_DISTRIBUTION_MARKERS
        ):
            raise ValueError("PINNED_DISTRIBUTION_CHAIN_REQUIRED")
        self.chain = [x509.load_der_x509_certificate(c) for c in chain_der]
        self.markers = set(distribution_markers)
        self.clock = clock

    def __call__(self, leaf_der, identity):
        leaf = x509.load_der_x509_certificate(leaf_der)
        chain = [leaf, *self.chain]
        now = self.clock()
        if (
            hashlib.sha1(leaf_der).hexdigest().upper() != identity["fingerprint"]
            and hashlib.sha256(leaf_der).hexdigest().upper() != identity["fingerprint"]
        ):
            raise ValueError("CERTIFICATE_PIN_MISMATCH")
        if leaf.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME) != [
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, identity["teamId"])
        ]:
            raise ValueError("CERTIFICATE_TEAM_MISMATCH")
        markers = []
        for index, cert in enumerate(chain):
            if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc or not (
                cert.signature_hash_algorithm.name in ("sha256", "sha384", "sha512")
                or (
                    index == len(chain) - 1
                    and cert.subject == cert.issuer
                    and cert.signature_hash_algorithm.name == "sha1"
                    and hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
                    == APPLE_LEGACY_ROOT_SHA256
                )
            ):
                raise ValueError("CERTIFICATE_VALIDITY_OR_ALGORITHM_REJECTED")
            basic = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
            usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
            if index == 0:
                eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
                if (
                    basic.ca
                    or not usage.digital_signature
                    or usage.key_cert_sign
                    or list(eku) != [ExtendedKeyUsageOID.CODE_SIGNING]
                ):
                    raise ValueError("CERTIFICATE_LEAF_USAGE_REJECTED")
            elif (
                not basic.ca
                or not usage.key_cert_sign
                or (basic.path_length is not None and basic.path_length < index - 1)
            ):
                raise ValueError("CERTIFICATE_CA_USAGE_REJECTED")
            for extension in cert.extensions:
                if isinstance(extension.value, x509.UnrecognizedExtension):
                    oid = extension.oid.dotted_string
                    if index == 0 and oid in self.markers and extension.value.value == b"\x05\x00":
                        markers.append(oid)
                    elif (
                        index == 0
                        and oid == APPLE_DISTRIBUTION_COMPANION
                        and extension.value.value == b"\x05\x00"
                    ):
                        pass
                    elif (
                        0 < index < len(chain) - 1
                        and oid in SUPPORTED_WWDR_MARKERS
                        and extension.value.value == b"\x05\x00"
                    ):
                        pass
                    elif extension.critical:
                        raise ValueError("UNKNOWN_CRITICAL_CERTIFICATE_EXTENSION")
                elif extension.critical and extension.oid not in (
                    ExtensionOID.BASIC_CONSTRAINTS,
                    ExtensionOID.KEY_USAGE,
                    ExtensionOID.EXTENDED_KEY_USAGE,
                ):
                    raise ValueError("UNSUPPORTED_CRITICAL_CERTIFICATE_POLICY")
            issuer = chain[index + 1] if index + 1 < len(chain) else cert
            if cert.issuer != issuer.subject:
                raise ValueError("CERTIFICATE_ISSUER_MISMATCH")
            key = issuer.public_key()
            if isinstance(key, rsa.RSAPublicKey):
                if key.key_size < 2048:
                    raise ValueError("CERTIFICATE_RSA_SIZE_REJECTED")
                key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm,
                )
            elif isinstance(key, ec.EllipticCurvePublicKey):
                if key.curve.name not in ("secp256r1", "secp384r1"):
                    raise ValueError("CERTIFICATE_CURVE_REJECTED")
                key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    ec.ECDSA(cert.signature_hash_algorithm),
                )
            else:
                raise ValueError("CERTIFICATE_KEY_TYPE_REJECTED")
        if len(markers) != 1:
            raise ValueError("DISTRIBUTION_CERTIFICATE_MARKER_REQUIRED")
        return True
