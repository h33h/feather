from runner_modules import module_path
import importlib.util, pathlib, time, os, json, hmac, hashlib, base64, unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load():
    s = importlib.util.spec_from_file_location(
        "bootstrap_sealing", module_path("bootstrap_sealing")
    )
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


class BootstrapSealingTests(unittest.TestCase):
    def setUp(self):
        self.m = load()
        self.key = b"synthetic-proof-key-at-least-32-bytes"
        self.now = int(time.time() * 1000)
        self.lease = dict(
            ownerId="o",
            connectionId="c",
            generation=1,
            nonce="lease-nonce",
            expiresAt=self.now + 60000,
        )
        self.runner = dict(
            ownerId="o",
            connectionId="c",
            connectionGeneration=1,
            isolationInstanceId="isign-0123456789abcdef",
            expiresAt=self.now + 60000,
        )
        self.grant = dict(
            version=1,
            operation="bootstrap-seal",
            lease=self.lease,
            secretId="secret",
            grantNonce="nonce",
            audience="aud",
            instanceId=self.runner["isolationInstanceId"],
            purpose="distribution-key",
            materialFormat="encrypted-pem-with-password-v1",
            expiresAt=self.now + 30000,
            wrappedKey="synthetic-wrapped-key",
            aad='{"owner":"o","connection":"c","purpose":"distribution-key","secret":"secret"}',
        )
        self.grant["signature"] = hmac.new(
            self.key, self.m.GRANT_DOMAIN + self.m.canonical(self.grant), hashlib.sha256
        ).hexdigest()
        self.captured = []
        gate = patch.dict(os.environ, {"ISIGN_ISOLATED_EXECUTOR": "1"})
        gate.start()
        self.addCleanup(gate.stop)

    def execute(self, **override):
        parent = self

        class SyntheticAESGCM:
            def __init__(self, key):
                parent.assertEqual(len(key), 32)

            def encrypt(self, nonce, plaintext, aad):
                parent.captured.append((nonce, plaintext, aad))
                return b"SYNTHETIC-CIPHERTEXT" + b"T" * 16

        options = dict(
            grant=self.grant,
            data_key=b"K" * 32,
            material=b"SYNTHETIC-ENCRYPTED-PEM",
            secret_password="synthetic-passphrase",
            csr="-----BEGIN CERTIFICATE REQUEST-----\nSYNTHETIC\n-----END CERTIFICATE REQUEST-----\n",
            spki_der=b"SYNTHETIC-SPKI",
            proof_key=self.key,
            audience="aud",
            runner_grant=self.runner,
            vm_proof="synthetic",
            validate_vm=lambda *a: True,
            nonce_provider=lambda size: b"N" * size,
            aesgcm_factory=SyntheticAESGCM,
        )
        options.update(override)
        return self.m.seal_bootstrap_material(**options)

    def test_exact_aad_plaintext_format_ciphertext_only_report_and_domain_signature(self):
        result = self.execute()
        nonce, plain, aad = self.captured[0]
        self.assertEqual(aad, self.grant["aad"].encode())
        self.assertEqual(json.loads(plain)["format"], "encrypted-pem-with-password-v1")
        self.assertEqual(json.loads(plain)["password"], "synthetic-passphrase")
        self.assertNotIn("synthetic-passphrase", str(result))
        self.assertNotIn("SYNTHETIC-ENCRYPTED-PEM", str(result))
        self.assertEqual(base64.b64decode(result["report"]["envelope"]["tag"]), b"T" * 16)
        self.assertEqual(
            result["attestation"],
            hmac.new(
                self.key, self.m.RECEIPT_DOMAIN + self.m.canonical(result["report"]), hashlib.sha256
            ).hexdigest(),
        )

    def test_tampered_grant_foreign_vm_and_bad_key_rejected_before_aead(self):
        for override in (
            {"grant": dict(self.grant, audience="foreign")},
            {"runner_grant": dict(self.runner, isolationInstanceId="foreign")},
            {"data_key": b"short"},
            {"validate_vm": lambda *a: False},
        ):
            with self.subTest(override=tuple(override)), self.assertRaises(ValueError):
                self.execute(**override)
            self.assertEqual(self.captured, [])


if __name__ == "__main__":
    unittest.main()
