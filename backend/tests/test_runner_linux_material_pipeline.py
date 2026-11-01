"""Actual sealed-material to strict-signature pipeline with synthetic credentials."""

import base64, hashlib, importlib.util, json, os, pathlib, secrets, shutil, tempfile, unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
s = importlib.util.spec_from_file_location("linux_fixture", ROOT / "tests/test_runner_linux.py")
fixtures = importlib.util.module_from_spec(s)
s.loader.exec_module(fixtures)


class LinuxMaterialPipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.LinuxSigningTests.setUpClass()

    @classmethod
    def tearDownClass(cls):
        fixtures.LinuxSigningTests.tearDownClass()

    def test_sealed_material_exports_pinned_issuer_chain_and_signs(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        f = fixtures.LinuxSigningTests()
        with (
            tempfile.TemporaryDirectory() as td,
            patch.dict(os.environ, {"ISIGN_ISOLATED_EXECUTOR": "1"}),
        ):
            root, task, grant, run, verifier = f.fixture(td)
            shutil.rmtree(root / "materials")
            key = secrets.token_bytes(32)
            nonce = secrets.token_bytes(12)
            aad = json.dumps(
                {
                    "owner": "o",
                    "connection": "c",
                    "purpose": "distribution-key",
                    "secret": "synthetic",
                },
                separators=(",", ":"),
            )
            package = {
                "format": "encrypted-pem-with-password-v1",
                "material": base64.b64encode(
                    f.key.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8,
                        serialization.BestAvailableEncryption(b"synthetic-password"),
                    )
                ).decode(),
                "password": "synthetic-password",
            }
            cipher = AESGCM(key).encrypt(nonce, json.dumps(package).encode(), aad.encode())
            b = lambda raw: base64.b64encode(raw).decode()
            payload = {
                "sealedKey": {
                    "dataKey": b(key),
                    "envelope": {
                        "owner": "o",
                        "connection": "c",
                        "purpose": "distribution-key",
                        "secret": "synthetic",
                        "aad": aad,
                        "wrappedKey": "synthetic-only",
                        "nonce": b(nonce),
                        "ciphertext": b(cipher[:-16]),
                        "tag": b(cipher[-16:]),
                        "generation": 1,
                    },
                },
                "certificatePem": f.pem(f.cert).decode(),
                "profiles": [
                    {
                        "bundleId": bundle,
                        "cmsBase64": b(cms),
                        "cmsSha256": hashlib.sha256(cms).hexdigest(),
                        "resourceId": "synthetic",
                    }
                    for bundle, (ent, cms) in f.profiles.items()
                ],
                "expected": {
                    "ownerId": "o",
                    "teamId": "TEAM",
                    "certificateSha256": hashlib.sha256(f.der(f.cert)).hexdigest(),
                    "fingerprint": hashlib.sha1(f.der(f.cert)).hexdigest().upper(),
                    "udid": "TEST-UDID",
                    "deviceOs": "17.0",
                },
            }
            store = fixtures.load("material_prepare").GuestMaterialStore(
                root, run, verifier, openssl_path=f.openssl, validate_vm=lambda *a: True
            )
            try:
                prepared = store.prepare(grant, payload, {})
                task = {**task, "identity": prepared["identity"], "profiles": prepared["profiles"]}
                grant["planDigest"] = fixtures.load("executor").canonical_digest(task)
                report = fixtures.load("linux_executor").execute_linux_task(
                    grant=grant,
                    task=task,
                    workspace=root,
                    vm_proof={},
                    validate_vm=lambda *a: True,
                    command_runner=run,
                    verifier=verifier,
                    zsign_path=f.zsign,
                    zsign_digest=hashlib.sha256(f.zsign.read_bytes()).hexdigest(),
                    material_password_provider=store.password_provider,
                )
                self.assertTrue(all(report["checks"].values()))
                self.assertTrue(report["verification"]["archiveVerified"])
                self.assertFalse((root / "materials/key.p12").exists())
                self.assertFalse(list(root.glob("prepare-key-*")))
            finally:
                store.clear()
