from runner_modules import module_path
import importlib.util, pathlib, tempfile, unittest, time, os
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load():
    s = importlib.util.spec_from_file_location("bootstrap", module_path("bootstrap"))
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.module = load()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name).resolve()
        self.calls = []
        self.grant = {
            "ownerId": "o",
            "jobId": "bootstrap:n",
            "leaseToken": "l",
            "connectionId": "c",
            "connectionGeneration": 1,
            "deviceId": "d",
            "uploadDigest": "a" * 64,
            "taskNonce": "n",
            "isolationInstanceId": "vm",
            "expiresAt": int(time.time() * 1000) + 3600000,
            "teamId": "TEAM",
            "operation": "bootstrap-request",
        }
        gate = patch.dict(os.environ, {"ISIGN_ISOLATED_EXECUTOR": "1"})
        gate.start()
        self.addCleanup(gate.stop)

    def runner(self, args, **kwargs):
        self.calls.append(args)
        if args[1] == "genpkey":
            pathlib.Path(args[args.index("-out") + 1]).write_bytes(b"SYNTHETIC-ENCRYPTED-KEY")
            return {"stdout": b"", "stderr": b""}
        if args[1] == "req":
            return {
                "stdout": b"-----BEGIN CERTIFICATE REQUEST-----\nSYNTHETIC\n-----END CERTIFICATE REQUEST-----\n",
                "stderr": b"",
            }
        if args[1] == "pkey":
            return {"stdout": b"SYNTHETIC-SPKI", "stderr": b""}
        raise AssertionError(args)

    def seal(self, material, *, kind, grant, secret_password):
        self.assertEqual(material, b"SYNTHETIC-ENCRYPTED-KEY")
        return {
            "storageRef": "kms:synthetic-only",
            "ciphertextDigest": "b" * 64,
            "persisted": True,
            "passwordSealed": True,
            "ownerId": "o",
            "connectionId": "c",
            "connectionGeneration": 1,
            "taskNonce": "n",
            "materialKind": kind,
        }

    def execute(self, **overrides):
        options = dict(
            workspace=self.root,
            grant=self.grant,
            vm_proof="synthetic-proof",
            validate_vm=lambda *a: True,
            command_runner=self.runner,
            openssl_path="/configured/openssl",
            password_provider=lambda *a: "synthetic-passphrase",
            seal_material=self.seal,
        )
        options.update(overrides)
        return self.module.generate_distribution_request(**options)

    def test_generated_key_persisted_before_public_csr_return_and_cleanup(self):
        result = self.execute()
        self.assertEqual(result["encryptedKeyRef"], "kms:synthetic-only")
        self.assertIn("BEGIN CERTIFICATE REQUEST", result["csr"])
        self.assertNotIn("SYNTHETIC-ENCRYPTED-KEY", str(result))
        self.assertEqual(list(self.root.iterdir()), [])

    def test_missing_persist_receipt_and_password_fail_closed(self):
        with self.assertRaises(ValueError):
            self.execute(seal_material=lambda *a, **k: {"persisted": False})
        self.assertEqual(list(self.root.iterdir()), [])
        self.calls = []
        with self.assertRaises(ValueError):
            self.execute(password_provider=lambda *a: "")
        self.assertEqual(self.calls, [])

    def test_pkcs12_only_sealed_ciphertext_reference_and_cleanup(self):
        import hashlib

        self.grant["operation"] = "bootstrap-pkcs12"
        key = self.root / "encrypted-key.pem"
        key.write_bytes(b"SYNTHETIC")
        der = b"SYNTHETIC-CERT"
        identity = {
            "ownerId": "o",
            "teamId": "TEAM",
            "fingerprint": "A" * 40,
            "expiresAt": self.grant["expiresAt"],
        }

        class Verifier:
            def certificate(self, pem, expected):
                return der

        def run(args, **kwargs):
            self.calls.append(args)
            if args[1] == "pkey":
                if kwargs.get("input_bytes") == b"SYNTHETIC-PUBLIC-CERT" and "-pubin" not in args:
                    raise ValueError("PUBLIC_KEY_MODE_REQUIRED")
                out = b"SYNTHETIC-SPKI"
            elif args[1] == "x509":
                out = b"SYNTHETIC-PUBLIC-CERT"
            elif args[1] == "pkcs12":
                pathlib.Path(args[args.index("-out") + 1]).write_bytes(b"SYNTHETIC-P12")
                out = b""
            else:
                raise AssertionError(args)
            return {"stdout": out, "stderr": b""}

        def seal(material, *, kind, grant, secret_password):
            self.assertEqual(material, b"SYNTHETIC-P12")
            return {
                "storageRef": "kms:synthetic-p12",
                "ciphertextDigest": "b" * 64,
                "persisted": True,
                "passwordSealed": True,
                "ownerId": "o",
                "connectionId": "c",
                "connectionGeneration": 1,
                "taskNonce": "n",
                "materialKind": kind,
            }

        result = self.module.seal_distribution_pkcs12(
            workspace=self.root,
            grant=self.grant,
            vm_proof="synthetic",
            validate_vm=lambda *args: True,
            command_runner=run,
            openssl_path="/configured/openssl",
            password_provider=lambda *args: "synthetic-passphrase",
            seal_material=seal,
            encrypted_key_path="encrypted-key.pem",
            certificate_der=der,
            expected_spki_digest=hashlib.sha256(b"SYNTHETIC-SPKI").hexdigest(),
            identity=identity,
            verifier=Verifier(),
        )
        self.assertEqual(result["encryptedPkcs12Ref"], "kms:synthetic-p12")
        self.assertNotIn("synthetic-passphrase", str(result))
        self.assertFalse(key.exists())
        self.assertEqual(list(self.root.iterdir()), [])

    def test_csr_before_team_discovery_has_no_fabricated_team(self):
        self.grant.pop("teamId")
        result = self.execute()
        self.assertNotIn("teamId", result)
        csr_commands = [args for args in self.calls if args[1] == "req" and "-new" in args]
        self.assertEqual(
            csr_commands[0][csr_commands[0].index("-subj") + 1], "/CN=iSign Distribution"
        )


if __name__ == "__main__":
    unittest.main()
