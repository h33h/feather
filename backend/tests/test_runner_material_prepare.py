from runner_modules import module_path
import importlib.util, pathlib, time, os, json, hashlib, base64, tempfile, unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load():
    s = importlib.util.spec_from_file_location("material_prepare", module_path("material_prepare"))
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


class MaterialTests(unittest.TestCase):
    def setUp(self):
        self.m = load()
        self.grant = {
            "connectionOwnerId": "o",
            "ownerId": "o",
            "connectionId": "c",
            "connectionGeneration": 1,
        }

    def sealed(self):
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            self.skipTest("Pinned crypto venv required for actual AEAD tests")
        aad = '{"owner":"o","connection":"c","purpose":"distribution-key","secret":"secret"}'
        plain = json.dumps(
            {
                "format": "encrypted-pem-with-password-v1",
                "material": base64.b64encode(b"SYNTHETIC-ENCRYPTED-PEM").decode(),
                "password": "synthetic-password",
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        key = b"K" * 32
        nonce = b"N" * 12
        encrypted = AESGCM(key).encrypt(nonce, plain, aad.encode())
        return {
            "dataKey": base64.b64encode(key).decode(),
            "envelope": {
                "owner": "o",
                "connection": "c",
                "purpose": "distribution-key",
                "secret": "secret",
                "aad": aad,
                "wrappedKey": "synthetic-wrapped",
                "nonce": base64.b64encode(nonce).decode(),
                "ciphertext": base64.b64encode(encrypted[:-16]).decode(),
                "tag": base64.b64encode(encrypted[-16:]).decode(),
                "generation": 1,
            },
        }

    def test_actual_aead_restore_and_generation_aad_tag_rejection(self):
        sealed = self.sealed()
        self.assertEqual(
            self.m.decode_job_key(sealed, self.grant),
            (b"SYNTHETIC-ENCRYPTED-PEM", "synthetic-password"),
        )
        for field, value in [
            ("generation", 2),
            ("owner", "foreign"),
            ("aad", "foreign"),
            ("tag", base64.b64encode(b"T" * 16).decode()),
        ]:
            bad = {
                "dataKey": sealed["dataKey"],
                "envelope": dict(sealed["envelope"], **{field: value}),
            }
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.m.decode_job_key(bad, self.grant)

    def test_password_provider_exact_scope_and_clear(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td).resolve()
            store = self.m.GuestMaterialStore(
                root, None, None, openssl_path="/configured/openssl", validate_vm=lambda *a: False
            )
            grant = {**self.grant, "jobId": "j", "isolationInstanceId": "vm"}
            store.passwords["materials/key.p12"] = {"password": "synthetic", "binding": grant}
            self.assertEqual(
                store.password_provider(root / "materials/key.p12", grant), "synthetic"
            )
            with self.assertRaises(ValueError):
                store.password_provider(root / "materials/key.p12", dict(grant, jobId="foreign"))
            store.clear()
            self.assertEqual(store.passwords, {})

    def test_prepare_records_key_match_export_and_profile_ceiling(self):
        import datetime
        from unittest.mock import patch

        sealed = self.sealed()
        der = b"SYNTHETIC-CERT"
        pem = "-----BEGIN CERTIFICATE-----\nQQ==\n-----END CERTIFICATE-----\n"
        expiry = (int(time.time()) + 3600) * 1000
        cms = b"SYNTHETIC-CMS"
        calls = []
        state = {"wrong_key": False}
        grant = {
            **self.grant,
            "jobId": "j",
            "leaseToken": "l",
            "deviceId": "d",
            "uploadDigest": "a" * 64,
            "taskNonce": "n",
            "isolationInstanceId": "vm",
            "expiresAt": expiry,
        }
        profile = {
            "ExpirationDate": datetime.datetime.fromtimestamp(
                expiry / 1000, datetime.timezone.utc
            ).replace(tzinfo=None),
            "TeamIdentifier": ["TEAM"],
            "ApplicationIdentifierPrefix": ["PREFIX"],
            "ProvisionedDevices": ["TEST-UDID"],
            "DeveloperCertificates": [der],
            "Entitlements": {
                "application-identifier": "PREFIX.*",
                "com.apple.developer.team-identifier": "TEAM",
                "get-task-allow": False,
                "keychain-access-groups": ["PREFIX.*", "com.apple.token"],
            },
        }

        class Verifier:
            clock = lambda self: int(time.time() * 1000)

            def certificate(self, *args):
                return der

            def decode_profile(self, path):
                return profile

        def run(args, **kwargs):
            calls.append((args, kwargs.get("input_bytes")))
            if args[1] == "x509":
                if "-startdate" in args:
                    out = (
                        "notBefore=Jan  1 00:00:00 2020 GMT\nnotAfter="
                        + datetime.datetime.fromtimestamp(
                            expiry / 1000, datetime.timezone.utc
                        ).strftime("%b %d %H:%M:%S %Y GMT")
                        + "\n"
                    ).encode()
                elif "-pubkey" in args:
                    out = b"SYNTHETIC-PUBLIC"
                else:
                    out = der
            elif args[1] == "pkey":
                if kwargs.get("input_bytes") == b"SYNTHETIC-PUBLIC":
                    self.assertIn("-pubin", args)
                out = b"WRONG" if state["wrong_key"] and "-in" in args else b"SYNTHETIC-SPKI"
            elif args[1] == "pkcs12":
                self.assertEqual(args[args.index("-passin") + 1], "stdin")
                self.assertEqual(args[args.index("-passout") + 1], "stdin")
                self.assertEqual(len(kwargs["input_bytes"].splitlines()), 2)
                pathlib.Path(args[args.index("-out") + 1]).write_bytes(b"SYNTHETIC-PKCS12")
                out = b""
            else:
                raise AssertionError(args)
            return {"stdout": out}

        payload = {
            "sealedKey": sealed,
            "certificatePem": pem,
            "profiles": [
                {
                    "bundleId": "org.synthetic.app",
                    "cmsBase64": base64.b64encode(cms).decode(),
                    "cmsSha256": hashlib.sha256(cms).hexdigest(),
                    "resourceId": "public-profile-id",
                }
            ],
            "expected": {
                "ownerId": "o",
                "teamId": "TEAM",
                "certificateSha256": hashlib.sha256(der).hexdigest(),
                "fingerprint": hashlib.sha1(der).hexdigest().upper(),
                "udid": "TEST-UDID",
                "deviceOs": "18.0",
            },
        }
        with (
            tempfile.TemporaryDirectory() as td,
            patch.dict(os.environ, {"ISIGN_ISOLATED_EXECUTOR": "1"}),
        ):
            store = self.m.GuestMaterialStore(
                td, run, Verifier(), openssl_path="/configured/openssl", validate_vm=lambda *a: True
            )
            value = store.prepare(grant, payload, {})
            self.assertEqual(value["identity"]["materialPath"], "materials/key.p12")
            descriptor = value["profiles"]["org.synthetic.app"]
            self.assertEqual(
                descriptor["entitlements"]["keychain-access-groups"],
                ["PREFIX.*", "com.apple.token"],
            )
            self.assertEqual(descriptor["bundleId"], "org.synthetic.app")
            self.assertEqual(descriptor["entitlements"]["application-identifier"], "PREFIX.*")
            self.assertEqual(descriptor["cmsSha256"], hashlib.sha256(cms).hexdigest())
            self.assertTrue(
                store.password_provider(pathlib.Path(td).resolve() / "materials/key.p12", grant)
            )
            store.clear()
            state["wrong_key"] = True
            with self.assertRaisesRegex(ValueError, "CERTIFICATE_KEY_MISMATCH"):
                store.prepare(grant, payload, {})
            self.assertFalse((pathlib.Path(td) / "materials").exists())


class SharedMaterialTests(MaterialTests):
    def test_actual_shared_aead_keeps_owner_aad_and_rejects_wrong_connection_owner(self):
        sealed = self.sealed()
        shared = {
            "ownerId": "recipient",
            "connectionOwnerId": "o",
            "accessGrantId": "synthetic-grant",
            "accessGrantGeneration": 1,
            "connectionId": "c",
            "connectionGeneration": 1,
        }
        self.assertEqual(
            self.m.decode_job_key(sealed, shared),
            (b"SYNTHETIC-ENCRYPTED-PEM", "synthetic-password"),
        )
        self.assertEqual(json.loads(sealed["envelope"]["aad"])["owner"], "o")
        for bad in [
            dict(shared, connectionOwnerId="other"),
            dict(shared, connectionGeneration=2),
            {k: v for k, v in shared.items() if k != "connectionOwnerId"},
        ]:
            with self.assertRaises(ValueError):
                self.m.decode_job_key(sealed, bad)

    def test_guest_report_carries_authenticated_access_revision(self):
        analyzer = self.m.native.analyzer
        grant = {
            "ownerId": "recipient",
            "connectionOwnerId": "o",
            "accessGrantId": "synthetic-grant",
            "accessGrantGeneration": 2,
            "connectionId": "c",
            "connectionGeneration": 1,
            "jobId": "job",
            "leaseToken": "lease",
            "deviceId": "device",
            "uploadDigest": "a" * 64,
            "taskNonce": "nonce",
            "isolationInstanceId": "vm",
            "expiresAt": int(time.time() * 1000) + 60000,
        }
        report = analyzer.make_report(grant, {"sha256": "a" * 64})
        self.assertEqual(report["connectionOwnerId"], "o")
        self.assertEqual(report["accessGrantGeneration"], 2)
        for bad in [
            dict(grant, accessGrantGeneration=0),
            dict(grant, connectionOwnerId="recipient"),
            {k: v for k, v in grant.items() if k != "accessGrantId"},
        ]:
            with self.assertRaises(ValueError):
                analyzer.validate_grant(bad)


if __name__ == "__main__":
    unittest.main()
