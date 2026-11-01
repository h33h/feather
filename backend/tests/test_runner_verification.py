from runner_modules import module_path
import importlib.util, pathlib, unittest, datetime, tempfile, time, plistlib, hashlib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load():
    s = importlib.util.spec_from_file_location("verification", module_path("verification"))
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


class VerificationTests(unittest.TestCase):
    def test_material_source_tree_key_match_and_leaf_failure(self):
        import io, zipfile

        fixture_spec = importlib.util.spec_from_file_location(
            "runner_fixtures", ROOT / "tests/test_runner_analyzer.py"
        )
        fixture = importlib.util.module_from_spec(fixture_spec)
        fixture_spec.loader.exec_module(fixture)
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td).resolve()
            raw = fixture.archive()
            (root / "source.ipa").write_bytes(raw)
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                for entry in archive.infolist():
                    path = root / entry.filename
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(archive.read(entry))
            ca = root / "ca.pem"
            ca.write_bytes(b"SYNTHETIC")
            inter = root / "inter.pem"
            inter.write_bytes(b"SYNTHETIC")
            (root / "identity.p12").write_bytes(b"SYNTHETIC")
            (root / "app.profile").write_bytes(b"SYNTHETIC")
            expiry = (int(time.time()) + 3600) * 1000
            der = b"SYNTHETIC-CERT"
            pem = b"-----BEGIN CERTIFICATE-----\nQQ==\n-----END CERTIFICATE-----\n"
            ent = {
                "application-identifier": "TEAM.org.example.app",
                "com.apple.developer.team-identifier": "TEAM",
                "get-task-allow": False,
            }
            identity = dict(
                ownerId="o",
                teamId="TEAM",
                prefix="TEAM",
                fingerprint=hashlib.sha256(der).hexdigest().upper(),
                expiresAt=expiry,
                materialPath="identity.p12",
            )
            expected = {
                **identity,
                "bundleId": "org.example.app",
                "udids": ["TEST-UDID"],
                "entitlements": ent,
                "materialPath": "app.profile",
            }
            profile = {
                "ExpirationDate": datetime.datetime.fromtimestamp(
                    expiry / 1000, datetime.timezone.utc
                ).replace(tzinfo=None),
                "TeamIdentifier": ["TEAM"],
                "ApplicationIdentifierPrefix": ["TEAM"],
                "ProvisionedDevices": ["TEST-UDID"],
                "DeveloperCertificates": [der],
                "Entitlements": ent,
            }
            component = dict(
                path="Payload/App.app",
                kind="app",
                bundleId="org.example.app",
                platform="ios",
                architectures=["arm64"],
                encrypted=False,
                minOs="16.0",
                entitlements=ent,
                profileRequired=True,
            )
            task = {
                "identity": identity,
                "udid": "TEST-UDID",
                "profiles": {"org.example.app": expected},
                "components": [component],
            }
            grant = {
                "ownerId": "o",
                "jobId": "j",
                "leaseToken": "l",
                "connectionId": "c",
                "connectionGeneration": 1,
                "deviceId": "d",
                "uploadDigest": hashlib.sha256(raw).hexdigest(),
                "taskNonce": "n",
                "isolationInstanceId": "vm",
                "expiresAt": expiry,
            }
            state = {"wrong_key": False, "wrong_entitlements": False}
            calls = []

            def run(args, **kwargs):
                calls.append(args)
                command = args[1]
                if command == "cms":
                    pathlib.Path(args[args.index("-signer") + 1]).write_bytes(pem)
                    result = plistlib.dumps(profile)
                elif command == "pkcs12":
                    result = (
                        pem
                        if "-nokeys" in args
                        else b"-----BEGIN PRIVATE KEY-----\nSYNTHETIC\n-----END PRIVATE KEY-----"
                    )
                elif command == "pkey":
                    if (
                        kwargs.get("input_bytes") == b"SYNTHETIC-PUBLIC-PEM"
                        and "-pubin" not in args
                    ):
                        raise ValueError("PUBLIC_KEY_MODE_REQUIRED")
                    result = (
                        b"OTHER"
                        if state["wrong_key"] and b"PRIVATE KEY" in kwargs.get("input_bytes", b"")
                        else b"SYNTHETIC-SPKI"
                    )
                elif command == "verify":
                    result = b"OK"
                elif command == "x509":
                    if "-startdate" in args:
                        result = (
                            "notBefore=Jan  1 00:00:00 2020 GMT\nnotAfter="
                            + datetime.datetime.fromtimestamp(
                                expiry / 1000, datetime.timezone.utc
                            ).strftime("%b %d %H:%M:%S %Y GMT")
                            + "\n"
                        ).encode()
                    elif "-subject" in args:
                        result = b"subject=CN=Synthetic,OU=TEAM\n"
                    elif "-pubkey" in args:
                        result = b"SYNTHETIC-PUBLIC-PEM"
                    elif "-outform" in args and args[args.index("-outform") + 1] == "PEM":
                        result = pem
                    else:
                        result = der
                else:
                    raise AssertionError(args)
                return {"stdout": result, "stderr": b""}

            verifier = self.module.GuestVerifier(
                root,
                run,
                openssl_path="/configured/openssl",
                ca_file=ca,
                intermediate_file=inter,
                cms_signer_fingerprints={hashlib.sha256(der).hexdigest()},
            )
            checks = verifier.verify_materials(
                task, root, grant, pkcs12_password="synthetic-password"
            )
            self.assertTrue(checks["inputDigestExact"])
            state["wrong_key"] = True
            with self.assertRaisesRegex(ValueError, "CERTIFICATE_KEY_MISMATCH"):
                verifier.verify_materials(task, root, grant, pkcs12_password="synthetic-password")

    def setUp(self):
        self.module = load()

    def profile(self):
        expiry = (int(time.time()) + 3600) * 1000
        der = b"SYNTHETIC-CERT"
        ent = {
            "application-identifier": "TEAM.org.example.app",
            "com.apple.developer.team-identifier": "TEAM",
            "get-task-allow": False,
        }
        expected = {
            "bundleId": "org.example.app",
            "teamId": "TEAM",
            "prefix": "TEAM",
            "fingerprint": hashlib.sha256(der).hexdigest().upper(),
            "expiresAt": expiry,
            "entitlements": ent,
            "udids": ["TEST-UDID"],
        }
        profile = {
            "ExpirationDate": datetime.datetime.fromtimestamp(
                expiry / 1000, datetime.timezone.utc
            ).replace(tzinfo=None),
            "TeamIdentifier": ["TEAM"],
            "ApplicationIdentifierPrefix": ["TEAM"],
            "ProvisionedDevices": ["TEST-UDID"],
            "DeveloperCertificates": [der],
            "Entitlements": ent,
            "ProvisionsAllDevices": False,
        }
        return profile, expected, der

    def test_decoded_profile_exact_certificate_device_entitlements_expiry(self):
        p, e, der = self.profile()
        self.module.validate_profile(p, e, "TEST-UDID", der, now=int(time.time() * 1000))
        for field, value in [
            ("TeamIdentifier", ["FOREIGN"]),
            ("ProvisionedDevices", ["OTHER"]),
            ("DeveloperCertificates", [b"OTHER"]),
            ("Entitlements", {"aps-environment": "production"}),
            ("ProvisionsAllDevices", True),
        ]:
            bad = dict(p)
            bad[field] = value
            with self.assertRaises(ValueError):
                self.module.validate_profile(bad, e, "TEST-UDID", der, now=int(time.time() * 1000))

    def test_cms_uses_verified_chain_and_pinned_signer(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td).resolve()
            profile = root / "app.profile"
            profile.write_bytes(b"SYNTHETIC")
            ca = root / "ca.pem"
            ca.write_bytes(b"SYNTHETIC")
            inter = root / "inter.pem"
            inter.write_bytes(b"SYNTHETIC")
            calls = []
            p, expected, der = self.profile()

            def run(argv, **kwargs):
                calls.append(argv)
                if argv[1] == "cms":
                    pathlib.Path(argv[argv.index("-signer") + 1]).write_bytes(
                        b"-----BEGIN CERTIFICATE-----\nQQ==\n-----END CERTIFICATE-----\n"
                    )
                    return {"stdout": plistlib.dumps(p), "stderr": b""}
                if argv[1] == "x509":
                    return {"stdout": der, "stderr": b""}
                raise AssertionError(argv)

            verifier = self.module.GuestVerifier(
                root,
                run,
                openssl_path="/trusted/openssl",
                ca_file=ca,
                intermediate_file=inter,
                cms_signer_fingerprints={hashlib.sha256(der).hexdigest()},
            )
            self.assertEqual(verifier.decode_profile(profile), p)
            self.assertIn("-verify", calls[0])
            self.assertIn("-verify_retcode", calls[0])
            self.assertNotIn("-noverify", calls[0])
            verifier.cms_signers = {"b" * 64}
            with self.assertRaises(ValueError):
                verifier.decode_profile(profile)


if __name__ == "__main__":
    unittest.main()


class ProfileCeilingTests(unittest.TestCase):
    def test_apple_ceiling_preserves_signed_keychain_scope(self):
        spec = importlib.util.spec_from_file_location("verification", module_path("verification"))
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        ent = {
            "application-identifier": "PREFIX.com.synthetic.app",
            "com.apple.developer.team-identifier": "TEAM",
            "get-task-allow": False,
            "keychain-access-groups": ["PREFIX.*", "com.apple.token"],
        }
        emitted = m.profile_entitlement_ceiling(ent, "PREFIX", "com.synthetic.app", "TEAM")
        self.assertEqual(emitted["keychain-access-groups"], ["PREFIX.*", "com.apple.token"])
        self.assertEqual(ent["keychain-access-groups"], ["PREFIX.*", "com.apple.token"])
        with self.assertRaises(ValueError):
            m.profile_entitlement_ceiling(
                dict(ent, **{"keychain-access-groups": ["PREFIX.shared"]}),
                "PREFIX",
                "com.synthetic.app",
                "TEAM",
            )


class WildcardProfileTests(unittest.TestCase):
    def test_profile_permissions_remain_authoritative_wildcard_ceilings(self):
        m = load()
        for permission in ("TEAM.*", "TEAM.org.example.*", "TEAM.org.example.app"):
            with self.subTest(permission=permission):
                raw = {
                    "application-identifier": permission,
                    "com.apple.developer.team-identifier": "TEAM",
                    "get-task-allow": False,
                    "keychain-access-groups": [permission],
                }
                emitted = m.profile_entitlement_ceiling(raw, "TEAM", "org.example.app", "TEAM")
                self.assertEqual(emitted["application-identifier"], permission)
                self.assertEqual(emitted["keychain-access-groups"], [permission])
                self.assertEqual(raw["application-identifier"], permission)

    def test_invalid_permission_patterns_rejected(self):
        m = load()
        for permission in (
            "TEAMX.*",
            "TEAM.org.other.*",
            "TEAM.org.*.app",
            "TEAM.org.**",
            "TEAM.org.example.app.*",
            "OTHER.org.example.app",
        ):
            with self.subTest(permission=permission), self.assertRaises(ValueError):
                m.profile_entitlement_ceiling(
                    {
                        "application-identifier": permission,
                        "com.apple.developer.team-identifier": "TEAM",
                        "get-task-allow": False,
                    },
                    "TEAM",
                    "org.example.app",
                    "TEAM",
                )
