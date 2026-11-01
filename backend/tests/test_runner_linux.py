from runner_modules import module_path

"""Fresh synthetic certificate/profile/arm64 fixtures; no personal key inputs."""
import base64, datetime, hashlib, importlib.util, io, json, os, pathlib, plistlib, shutil, struct, subprocess, sys, tempfile, time, unittest, zipfile
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load(name):
    s = importlib.util.spec_from_file_location(name, module_path(name))
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


def unsigned_macho(kind="app"):
    text = struct.pack(
        "<II16sQQQQIIII", 0x19, 152, b"__TEXT", 0x100000000, 4096, 0, 4096, 7, 5, 1, 0
    )
    section = struct.pack(
        "<16s16sQQIIIIIIII", b"__text", b"__TEXT", 0x100000200, 4, 512, 2, 0, 0, 0x80000400, 0, 0, 0
    )
    link = struct.pack(
        "<II16sQQQQIIII", 0x19, 72, b"__LINKEDIT", 0x100001000, 4096, 4096, 0, 7, 1, 0, 0
    )
    build = struct.pack("<IIIIII", 0x32, 24, 2, 15 << 16, 15 << 16, 0)
    main = struct.pack("<IIQQ", 0x80000028, 24, 512, 0)
    commands = text + section + link + build + main
    raw = bytearray(
        struct.pack(
            "<IIIIIIII",
            0xFEEDFACF,
            0x100000C,
            0,
            6 if kind == "framework" else 2,
            4,
            len(commands),
            0,
            0,
        )
        + commands
    )
    raw.extend(b"\0" * (4096 - len(raw)))
    struct.pack_into("<I", raw, 512, 0xD65F03C0)
    return bytes(raw)


class LinuxSourceFormatTests(unittest.TestCase):
    def test_standalone_dylib_is_a_file_without_info_plist(self):
        runtime = load("linux_runtime").LinuxGuestRuntime
        stream = io.BytesIO()
        path = "Payload/App.app/Frameworks/r3yt.dylib"
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr(path, unsigned_macho("framework"))
        try:
            runtime.validate_source_format(
                None, stream.getvalue(), {"components": [{"path": path, "kind": "dylib"}]}
            )
        except (KeyError, ValueError) as error:
            self.fail("Thin standalone library must be accepted without Info.plist: " + str(error))

    def test_standalone_malformed_fat_dylib_is_rejected(self):
        runtime = load("linux_runtime").LinuxGuestRuntime
        stream = io.BytesIO()
        path = "Payload/App.app/Frameworks/r3yt.dylib"
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr(path, b"\xca\xfe\xba\xbe" + b"\0" * 32)
        with self.assertRaisesRegex(ValueError, "FAT_BOUNDS"):
            runtime.validate_source_format(
                None, stream.getvalue(), {"components": [{"path": path, "kind": "dylib"}]}
            )


class LinuxSigningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.zsign = pathlib.Path(
            os.environ.get("ISIGN_TEST_ZSIGN_BINARY", "/nonexistent/explicit-zsign")
        )
        cls.openssl = os.environ.get(
            "ISIGN_TEST_OPENSSL", shutil.which("openssl") or "/nonexistent/openssl"
        )
        if not cls.zsign.is_file():
            raise unittest.SkipTest("Explicit approved scratch signer/fixture unavailable")
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives.serialization import pkcs12
            from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, ObjectIdentifier
        except ImportError:
            raise unittest.SkipTest("Pinned crypto venv required")
        cls.temp = tempfile.TemporaryDirectory(prefix="isign-linux-synthetic-")
        cls.root = pathlib.Path(cls.temp.name).resolve()
        now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
        cls.expiry = int((now + datetime.timedelta(days=1)).timestamp() * 1000)

        def cert(cn, key, issuer=None, issuerkey=None, ca=False, marker=None, unknown=False):
            name = x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, cn),
                    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "TEAM"),
                ]
            )
            builder = (
                x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(issuer.subject if issuer else name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=1))
                .not_valid_after(now + datetime.timedelta(days=1))
                .add_extension(
                    x509.BasicConstraints(ca=ca, path_length=1 if ca else None), critical=True
                )
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        content_commitment=False,
                        key_encipherment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=ca,
                        crl_sign=ca,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )
            )
            if not ca:
                builder = builder.add_extension(
                    x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), critical=True
                )
            if marker:
                builder = builder.add_extension(
                    x509.UnrecognizedExtension(ObjectIdentifier(marker), b"\x05\x00"), critical=True
                )
            if unknown:
                builder = builder.add_extension(
                    x509.UnrecognizedExtension(ObjectIdentifier("1.2.3.4.5.99"), b"\x05\x00"),
                    critical=True,
                )
            return builder.sign(issuerkey or key, hashes.SHA256())

        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rootkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cakey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.rootcert = cert("Synthetic Root", rootkey, ca=True)
        cls.ca = cert(
            "Synthetic WWDR", cakey, cls.rootcert, rootkey, True, "1.2.840.113635.100.6.2.1"
        )
        cls.badca = cert(
            "Synthetic WWDR", cakey, cls.rootcert, rootkey, True, "1.2.840.113635.100.6.2.1", True
        )
        cls.cert = cert(
            "Synthetic Distribution", cls.key, cls.ca, cakey, False, "1.2.840.113635.100.6.1.4"
        )
        cls.badcert = cert(
            "Synthetic Distribution",
            cls.key,
            cls.ca,
            cakey,
            False,
            "1.2.840.113635.100.6.1.4",
            True,
        )
        cls.der = staticmethod(lambda c: c.public_bytes(serialization.Encoding.DER))
        cls.pem = staticmethod(lambda c: c.public_bytes(serialization.Encoding.PEM))
        cls.pkcs12 = pkcs12.serialize_key_and_certificates(
            b"synthetic",
            cls.key,
            cls.cert,
            [cls.ca, cls.rootcert],
            serialization.BestAvailableEncryption(b"synthetic-p12-password"),
        )
        (cls.root / "ca.pem").write_bytes(cls.pem(cls.rootcert))
        (cls.root / "intermediate.pem").write_bytes(cls.pem(cls.ca))
        (cls.root / "cms.pem").write_bytes(cls.pem(cls.rootcert))
        (cls.root / "cms.key").write_bytes(
            rootkey.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        cls.profiles = {}
        for bundle in ("org.synthetic.app", "org.synthetic.app.extension"):
            ent = {
                "application-identifier": "TEAM." + bundle,
                "com.apple.developer.team-identifier": "TEAM",
                "get-task-allow": False,
                "keychain-access-groups": ["TEAM." + bundle],
            }
            profile = {
                "ExpirationDate": (now + datetime.timedelta(days=1)).replace(tzinfo=None),
                "TeamIdentifier": ["TEAM"],
                "ApplicationIdentifierPrefix": ["TEAM"],
                "ProvisionedDevices": ["TEST-UDID"],
                "DeveloperCertificates": [cls.der(cls.cert)],
                "Entitlements": ent,
                "UUID": bundle,
                "Name": "Synthetic",
                "CreationDate": now.replace(tzinfo=None),
            }
            content = plistlib.dumps(profile)
            process = subprocess.run(
                [
                    cls.openssl,
                    "cms",
                    "-sign",
                    "-binary",
                    "-nodetach",
                    "-outform",
                    "DER",
                    "-signer",
                    str(cls.root / "cms.pem"),
                    "-inkey",
                    str(cls.root / "cms.key"),
                ],
                input=content,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
                timeout=30,
            )
            cls.profiles[bundle] = (ent, process.stdout)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "temp"):
            cls.temp.cleanup()

    def fixture(self, directory, *, include_dylib=False):
        m = load("linux_verification")
        policy = load("linux_certificate_policy")
        root = pathlib.Path(directory).resolve()
        components = []
        for relative, kind, bundle in [
            ("Payload/App.app", "app", "org.synthetic.app"),
            ("Payload/App.app/PlugIns/Extension.appex", "appex", "org.synthetic.app.extension"),
            ("Payload/App.app/Frameworks/Library.framework", "framework", "org.synthetic.library"),
        ]:
            folder = root / relative
            folder.mkdir(parents=True)
            fixture = json.loads((ROOT / "tests/fixtures/linux-unsigned-macho.json").read_text())[
                "fixtures"
            ]["FixtureFramework" if kind == "framework" else "Fixture"]
            binary = bytearray(base64.b64decode(fixture["base64"], validate=True))
            self.assertEqual(hashlib.sha256(binary).hexdigest(), fixture["sha256"])
            (folder / "Fixture").write_bytes(binary)
            (folder / "Info.plist").write_bytes(
                plistlib.dumps(
                    {
                        "CFBundleIdentifier": bundle,
                        "CFBundleExecutable": "Fixture",
                        "CFBundleShortVersionString": "1.0",
                        "CFBundleVersion": "1",
                        "CFBundleName": "Synthetic",
                        "MinimumOSVersion": "15.0",
                        "CFBundleSupportedPlatforms": ["iPhoneOS"],
                    }
                )
            )
            (folder / "resource.txt").write_text("synthetic resource")
            components.append(
                {
                    "path": relative,
                    "kind": kind,
                    "bundleId": bundle,
                    "platform": "ios",
                    "architectures": ["arm64"],
                    "encrypted": False,
                    "minOs": "15.0",
                    "entitlements": {} if kind == "framework" else self.profiles[bundle][0],
                    "profileRequired": kind != "framework",
                }
            )
        if include_dylib:
            relative = "Payload/App.app/Frameworks/r3yt.dylib"
            fixture = json.loads((ROOT / "tests/fixtures/linux-unsigned-macho.json").read_text())[
                "fixtures"
            ]["FixtureFramework"]
            binary = base64.b64decode(fixture["base64"], validate=True)
            self.assertEqual(hashlib.sha256(binary).hexdigest(), fixture["sha256"])
            (root / relative).write_bytes(binary)
            components.append(
                {
                    "path": relative,
                    "kind": "dylib",
                    "bundleId": "isign.dylib."
                    + hashlib.sha256(relative.encode("utf8")).hexdigest(),
                    "platform": "ios",
                    "architectures": ["arm64"],
                    "encrypted": False,
                    "minOs": "15.0.0",
                    "entitlements": {},
                    "profileRequired": False,
                }
            )
        resources = root / "Payload/App.app/Assets.bundle"
        resources.mkdir()
        (resources / "Info.plist").write_bytes(plistlib.dumps({"CFBundlePackageType": "BNDL"}))
        (resources / "strings.txt").write_text("synthetic bundled resource")
        tweak_resources = root / "Payload/App.app/Tweak.bundle"
        tweak_resources.mkdir()
        (tweak_resources / "Info.plist").write_text(
            '{ "CFBundleIdentifier" = "org.synthetic.resources"; "CFBundlePackageType" = "BNDL"; }'
        )
        (tweak_resources / "strings.txt").write_text("synthetic tweak resource")
        (root / "materials").mkdir()
        (root / "materials/key.p12").write_bytes(self.pkcs12)
        identity = {
            "ownerId": "o",
            "teamId": "TEAM",
            "prefix": "TEAM",
            "fingerprint": hashlib.sha1(self.der(self.cert)).hexdigest().upper(),
            "expiresAt": self.expiry,
            "materialPath": "materials/key.p12",
        }
        profiles = {}
        for index, (bundle, (ent, cms)) in enumerate(self.profiles.items()):
            path = f"materials/profile_{index}.mobileprovision"
            (root / path).write_bytes(cms)
            profiles[bundle] = {
                **identity,
                "bundleId": bundle,
                "udids": ["TEST-UDID"],
                "entitlements": ent,
                "materialPath": path,
                "cmsSha256": hashlib.sha256(cms).hexdigest(),
            }
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            for path in (root / "Payload").rglob("*"):
                if path.is_file():
                    archive.writestr(str(path.relative_to(root)), path.read_bytes())
        raw = stream.getvalue()
        (root / "source.ipa").write_bytes(raw)
        task = {
            "identity": identity,
            "profiles": profiles,
            "components": components,
            "udid": "TEST-UDID",
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
            "isolationInstanceId": "sandbox",
            "expiresAt": int(time.time() * 1000) + 60000,
            "planDigest": m.v.executor.canonical_digest(task),
        }

        def run(args, **kwargs):
            result = subprocess.run(
                args,
                cwd=kwargs["cwd"],
                input=kwargs.get("input_bytes"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
                timeout=kwargs["timeout"],
            )
            return {"stdout": result.stdout, "stderr": result.stderr}

        verifier = m.LinuxVerifier(
            root,
            run,
            openssl_path=self.openssl,
            ca_file=self.root / "ca.pem",
            intermediate_file=self.root / "intermediate.pem",
            cms_signer_fingerprints={hashlib.sha256(self.der(self.rootcert)).hexdigest()},
            apple_certificate_policy=policy.LinuxCertificatePolicy(
                [self.der(self.ca), self.der(self.rootcert)]
            ),
        )
        return root, task, grant, run, verifier

    def wildcard_fixture(self, directory, *, permission="TEAM.*", profile_changes=None):
        root, task, grant, run, verifier = self.fixture(directory, include_dylib=True)
        original = self.profiles["org.synthetic.app"][1]
        content = subprocess.run(
            [
                self.openssl,
                "cms",
                "-verify",
                "-inform",
                "DER",
                "-binary",
                "-CAfile",
                str(self.root / "ca.pem"),
            ],
            input=original,
            capture_output=True,
            check=True,
        ).stdout
        profile = plistlib.loads(content)
        profile["Entitlements"]["application-identifier"] = permission
        profile["Entitlements"]["keychain-access-groups"] = ["TEAM.*"]
        profile.update(profile_changes or {})
        cms = subprocess.run(
            [
                self.openssl,
                "cms",
                "-sign",
                "-binary",
                "-nodetach",
                "-outform",
                "DER",
                "-signer",
                str(self.root / "cms.pem"),
                "-inkey",
                str(self.root / "cms.key"),
            ],
            input=plistlib.dumps(profile),
            capture_output=True,
            check=True,
        ).stdout
        for descriptor in task["profiles"].values():
            descriptor["entitlements"] = dict(profile["Entitlements"])
            (root / descriptor["materialPath"]).write_bytes(cms)
            descriptor["cmsSha256"] = hashlib.sha256(cms).hexdigest()
        grant["planDigest"] = load("executor").canonical_digest(task)
        return root, task, grant, run, verifier

    def test_real_resign_clears_previous_larger_signature_tail(self):
        driver = load("linux_executor")
        signatures = load("linux_verification")
        with (
            tempfile.TemporaryDirectory(prefix="synthetic-resign-") as td,
            patch.dict(os.environ, {"ISIGN_ISOLATED_EXECUTOR": "1"}),
        ):
            root, task, grant, run, verifier = self.fixture(td)
            verifier.verify_materials(task, root, grant, pkcs12_password="synthetic-p12-password")
            main = task["components"][0]
            main_root = root / main["path"]
            binary = main_root / "Fixture"
            old_entitlements = {
                **main["entitlements"],
                "com.synthetic.previous-signature": "old-source-claim-" * 512,
            }
            old_plan = {}
            for index, component in enumerate(task["components"]):
                folder = root / component["path"]
                relative = "/" if folder == main_root else str(folder.relative_to(main_root))
                profile = task["profiles"][
                    (main if component["kind"] == "framework" else component)["bundleId"]
                ]
                entitlements = old_entitlements if component is main else component["entitlements"]
                entpath = root / ("old-entitlements-" + str(index) + ".plist")
                entpath.write_bytes(plistlib.dumps(entitlements))
                old_plan[relative] = {
                    "bundleId": component["bundleId"],
                    "kind": component["kind"],
                    "applicationId": profile["entitlements"]["application-identifier"],
                    "profileDigest": profile["cmsSha256"],
                    "entitlementsPath": str(entpath),
                }
            plan_path = root / "old-signature-plan.json"
            plan_path.write_text(json.dumps(old_plan))
            args = [
                str(self.zsign),
                "--isign-plan",
                str(plan_path),
                "-f",
                "-2",
                "-q",
                "-k",
                str(root / task["identity"]["materialPath"]),
                "--isign-password-stdin",
            ]
            for profile in task["profiles"].values():
                args += ["-m", str(root / profile["materialPath"])]
            run(
                args + [str(main_root)],
                cwd=str(root),
                timeout=120,
                input_bytes=b"synthetic-p12-password\n",
            )
            original = binary.read_bytes()
            old_offset, _, _ = signatures.macho_signature(original)
            old_total = struct.unpack_from(">I", original, old_offset + 4)[0]
            # The old source has a real CMS signature. Its extra claim is input,
            # never authority for the smaller, profile-authorized output plan.
            self.assertTrue(
                all(
                    verifier.verify_component(
                        main_root, {**main, "entitlements": old_entitlements}, task, grant
                    ).values()
                )
            )
            for component in task["components"]:
                component["sourceEntitlements"] = (
                    old_entitlements if component is main else component["entitlements"]
                )
            with zipfile.ZipFile(root / "source.ipa", "w") as archive:
                for path in (root / "Payload").rglob("*"):
                    if path.is_file():
                        archive.write(path, str(path.relative_to(root)))
            grant["uploadDigest"] = hashlib.sha256((root / "source.ipa").read_bytes()).hexdigest()
            grant["planDigest"] = load("executor").canonical_digest(task)
            report = driver.execute_linux_task(
                grant=grant,
                task=task,
                workspace=root,
                vm_proof={},
                validate_vm=lambda *a: True,
                command_runner=run,
                verifier=verifier,
                zsign_path=self.zsign,
                zsign_digest=hashlib.sha256(self.zsign.read_bytes()).hexdigest(),
                material_password_provider=lambda *a: "synthetic-p12-password",
            )
            rewritten = binary.read_bytes()
            new_offset, _, _ = signatures.macho_signature(rewritten)
            new_total = struct.unpack_from(">I", rewritten, new_offset + 4)[0]
            self.assertEqual(new_offset, old_offset)
            self.assertEqual(len(rewritten), len(original))
            self.assertLess(new_total, old_total)
            self.assertFalse(any(rewritten[new_offset + new_total :]))
            self.assertTrue(report["verification"]["archiveVerified"])

    def test_real_sign_normalizes_universal_main_extension_framework_and_dylib(self):
        from test_runner_macho_compatibility import universal

        driver = load("linux_executor")
        with (
            tempfile.TemporaryDirectory(prefix="synthetic-universal-") as td,
            patch.dict(os.environ, {"ISIGN_ISOLATED_EXECUTOR": "1"}),
        ):
            root, task, grant, run, verifier = self.fixture(td, include_dylib=True)
            for index, component in enumerate(task["components"]):
                binary = root / component["path"]
                if component["kind"] != "dylib":
                    info = plistlib.loads((binary / "Info.plist").read_bytes())
                    binary /= info["CFBundleExecutable"]
                raw = binary.read_bytes()
                binary.write_bytes(
                    universal(
                        [(12, 9, b"legacy" * 8), (0x100000C, 0, raw)],
                        wide=bool(index % 2),
                        endian="<" if index % 2 else ">",
                    )
                )
            with zipfile.ZipFile(root / "source.ipa", "w") as archive:
                for path in (root / "Payload").rglob("*"):
                    if path.is_file():
                        archive.write(path, str(path.relative_to(root)))
            grant["uploadDigest"] = hashlib.sha256((root / "source.ipa").read_bytes()).hexdigest()
            report = driver.execute_linux_task(
                grant=grant,
                task=task,
                workspace=root,
                vm_proof="proof",
                validate_vm=lambda *a: True,
                command_runner=run,
                verifier=verifier,
                zsign_path=str(self.zsign),
                zsign_digest=hashlib.sha256(self.zsign.read_bytes()).hexdigest(),
                material_password_provider=lambda *a: "synthetic-p12-password",
            )
            self.assertTrue(report["checks"]["signatures"])
            self.assertTrue(report["verification"]["archiveVerified"])
            self.assertEqual(len(report["verification"]["components"]), 4)

    def test_real_sign_maps_app_and_extension_with_a_dotless_framework_identifier(self):
        driver = load("linux_executor")
        with (
            tempfile.TemporaryDirectory(prefix="synthetic-framework-id-") as td,
            patch.dict(os.environ, {"ISIGN_ISOLATED_EXECUTOR": "1"}),
        ):
            root, task, grant, run, verifier = self.fixture(td)
            for component in task["components"]:
                path = root / component["path"] / "Info.plist"
                info = plistlib.loads(path.read_bytes())
                if component["kind"] == "framework":
                    component["bundleId"] = "ExampleSDK"
                    info["CFBundleName"] = "ExampleSDK"
                    info["CFBundleIdentifier"] = "ExampleSDK"
                else:
                    source_id = "org.original.app" + (
                        ".share" if component["kind"] == "appex" else ""
                    )
                    component["sourceBundleId"] = source_id
                    info["CFBundleIdentifier"] = source_id
                path.write_bytes(plistlib.dumps(info))
            with zipfile.ZipFile(root / "source.ipa", "w") as archive:
                for path in (root / "Payload").rglob("*"):
                    if path.is_file():
                        archive.write(path, str(path.relative_to(root)))
            grant["uploadDigest"] = hashlib.sha256((root / "source.ipa").read_bytes()).hexdigest()
            grant["planDigest"] = load("executor").canonical_digest(task)
            report = driver.execute_linux_task(
                grant=grant,
                task=task,
                workspace=root,
                vm_proof={},
                validate_vm=lambda *a: True,
                command_runner=run,
                verifier=verifier,
                zsign_path=self.zsign,
                zsign_digest=hashlib.sha256(self.zsign.read_bytes()).hexdigest(),
                material_password_provider=lambda *a: "synthetic-p12-password",
            )
            self.assertTrue(report["verification"]["archiveVerified"])

    def test_real_shared_wildcard_profile_signs_concrete_app_extension_and_dylib(self):
        driver = load("linux_executor")
        with (
            tempfile.TemporaryDirectory() as td,
            patch.dict(os.environ, {"ISIGN_ISOLATED_EXECUTOR": "1"}),
        ):
            root, task, grant, run, verifier = self.wildcard_fixture(td)

            def inspect(args, **kwargs):
                plan = json.loads(pathlib.Path(args[2]).read_text())
                digest = next(iter(task["profiles"].values()))["cmsSha256"]
                self.assertTrue(all(node["profileDigest"] == digest for node in plan.values()))
                self.assertTrue(all("*" not in node["applicationId"] for node in plan.values()))
                return run(args, **kwargs)

            report = driver.execute_linux_task(
                grant=grant,
                task=task,
                workspace=root,
                vm_proof={},
                validate_vm=lambda *a: True,
                command_runner=inspect,
                verifier=verifier,
                zsign_path=self.zsign,
                zsign_digest=hashlib.sha256(self.zsign.read_bytes()).hexdigest(),
                material_password_provider=lambda *a: "synthetic-p12-password",
            )
            self.assertTrue(report["verification"]["archiveVerified"])
            for component in task["components"]:
                self.assertNotIn("*", component["entitlements"].get("application-identifier", ""))

    def test_final_archive_seals_pkginfo_and_localization_with_apple_compatible_exclusions(self):
        with (
            tempfile.TemporaryDirectory() as td,
            patch.dict(os.environ, {"ISIGN_ISOLATED_EXECUTOR": "1"}),
        ):
            root, task, grant, run, verifier = self.fixture(td, include_dylib=True)
            for component in task["components"]:
                if component["kind"] == "dylib":
                    continue
                folder = root / component["path"]
                (folder / "PkgInfo").write_bytes(b"APPL????")
                (folder / "en.lproj").mkdir()
                (folder / "en.lproj/locversion.plist").write_bytes(
                    plistlib.dumps({"LprojCompatibleVersion": 123})
                )
                for name in (".DS_Store", "copy.DS_Store", "en.lproj/.DS_Store"):
                    (folder / name).write_bytes(b"synthetic Finder metadata")
            with zipfile.ZipFile(root / "source.ipa", "w") as archive:
                for path in (root / "Payload").rglob("*"):
                    if path.is_file():
                        archive.write(path, str(path.relative_to(root)))
            grant["uploadDigest"] = hashlib.sha256((root / "source.ipa").read_bytes()).hexdigest()
            report = load("linux_executor").execute_linux_task(
                grant=grant,
                task=task,
                workspace=root,
                vm_proof={},
                validate_vm=lambda *a: True,
                command_runner=run,
                verifier=verifier,
                zsign_path=self.zsign,
                zsign_digest=hashlib.sha256(self.zsign.read_bytes()).hexdigest(),
                material_password_provider=lambda *a: "synthetic-p12-password",
            )
            self.assertTrue(report["verification"]["archiveVerified"])
            with zipfile.ZipFile(root / "signed.ipa") as archive:
                self.assertFalse(any(name.endswith(".DS_Store") for name in archive.namelist()))
                extracted = root / "final-archive"
                archive.extractall(extracted)  # Only this trusted synthetic fixture.
            for component in task["components"]:
                if component["kind"] == "dylib":
                    continue
                folder = extracted / component["path"]
                resources = plistlib.loads((folder / "_CodeSignature/CodeResources").read_bytes())
                self.assertNotIn("PkgInfo", resources["files2"])
                self.assertEqual(resources["files"]["PkgInfo"], hashlib.sha1(b"APPL????").digest())
                self.assertIn("en.lproj/locversion.plist", resources["files2"])
                if sys.platform == "darwin":
                    check = subprocess.run(
                        ["/usr/bin/codesign", "--verify", "--strict", "--verbose=4", str(folder)],
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
                    # Synthetic credentials deliberately fail Apple's trust requirement;
                    # its independent resource validation must nevertheless pass.
                    self.assertIn("valid on disk", check.stderr, check.stderr)
                    self.assertNotIn("sealed resource", check.stderr, check.stderr)
            tampered = root / "tampered.ipa"
            with (
                zipfile.ZipFile(root / "signed.ipa") as original,
                zipfile.ZipFile(tampered, "w") as changed,
            ):
                for entry in original.infolist():
                    raw = original.read(entry)
                    if entry.filename == "Payload/App.app/en.lproj/locversion.plist":
                        raw = b"tampered"
                    changed.writestr(entry, raw)
            with self.assertRaises(ValueError):
                verifier.verify_archive(tampered, task, grant)

    def test_actual_wildcard_cms_rejects_bad_permission_device_certificate_and_expiry(self):
        cases = [
            ("permission", value)
            for value in ("TEAMX.*", "TEAM.org.other.*", "TEAM.org.*.app", "TEAM.**")
        ]
        cases += [
            ("ProvisionedDevices", ["OTHER-UDID"]),
            ("DeveloperCertificates", [self.der(self.badcert)]),
            ("ExpirationDate", datetime.datetime(2020, 1, 1)),
        ]
        for field, value in cases:
            with self.subTest(field=field, value=value), tempfile.TemporaryDirectory() as td:
                options = (
                    {"permission": value}
                    if field == "permission"
                    else {"profile_changes": {field: value}}
                )
                root, task, grant, run, verifier = self.wildcard_fixture(td, **options)
                with self.assertRaises(ValueError):
                    verifier.verify_materials(
                        task, root, grant, pkcs12_password="synthetic-p12-password"
                    )

    def test_strict_signer_rejects_wrong_digest_even_with_matching_permission(self):
        driver = load("linux_executor")
        for relative in ("/", "PlugIns/Extension.appex", "Frameworks/r3yt.dylib"):
            with (
                self.subTest(relative=relative),
                tempfile.TemporaryDirectory() as td,
                patch.dict(os.environ, {"ISIGN_ISOLATED_EXECUTOR": "1"}),
            ):
                root, task, grant, run, verifier = self.fixture(td, include_dylib=True)

                def mutate(args, **kwargs):
                    path = pathlib.Path(args[2])
                    plan = json.loads(path.read_text())
                    plan[relative]["profileDigest"] = "f" * 64
                    path.write_text(json.dumps(plan))
                    return run(args, **kwargs)

                with self.assertRaises(subprocess.CalledProcessError):
                    driver.execute_linux_task(
                        grant=grant,
                        task=task,
                        workspace=root,
                        vm_proof={},
                        validate_vm=lambda *a: True,
                        command_runner=mutate,
                        verifier=verifier,
                        zsign_path=self.zsign,
                        zsign_digest=hashlib.sha256(self.zsign.read_bytes()).hexdigest(),
                        material_password_provider=lambda *a: "synthetic-p12-password",
                    )

    def test_real_sign_standalone_library_and_reject_tampering(self):
        driver = load("linux_executor")
        module = load("linux_verification")
        with (
            tempfile.TemporaryDirectory() as td,
            patch.dict(os.environ, {"ISIGN_ISOLATED_EXECUTOR": "1"}),
        ):
            root, task, grant, run, verifier = self.fixture(td, include_dylib=True)
            report = driver.execute_linux_task(
                grant=grant,
                task=task,
                workspace=root,
                vm_proof={},
                validate_vm=lambda *a: True,
                command_runner=run,
                verifier=verifier,
                zsign_path=self.zsign,
                zsign_digest=hashlib.sha256(self.zsign.read_bytes()).hexdigest(),
                material_password_provider=lambda *a: "synthetic-p12-password",
            )
            component = task["components"][-1]
            library = root / component["path"]
            self.assertEqual(len(report["verification"]["components"]), 4)
            self.assertTrue(report["verification"]["archiveVerified"])
            original = library.read_bytes()
            offset, filetype, entries = module.macho_signature(original)
            self.assertEqual(filetype, 6)
            self.assertNotIn(7, entries)
            self.assertEqual(plistlib.loads(entries[5][8:]), {})
            self.assertTrue(
                all(verifier.verify_component(library, component, task, grant).values())
            )
            for field, value in [
                ("bundleId", "isign.dylib.wrong"),
                ("entitlements", {"get-task-allow": False}),
            ]:
                with self.subTest(field=field), self.assertRaises(ValueError):
                    verifier.verify_component(library, {**component, field: value}, task, grant)
            for position in [4096, offset + len(entries[0])]:
                with self.subTest(position=position):
                    tampered = bytearray(original)
                    tampered[position] ^= 1
                    library.write_bytes(tampered)
                    with self.assertRaises(ValueError):
                        verifier.verify_component(library, component, task, grant)
                    library.write_bytes(original)
            library.write_bytes(original[:-1])
            with self.assertRaises(ValueError):
                verifier.verify_component(library, component, task, grant)

    def test_strict_signer_rejects_unplanned_or_mismatched_loose_code(self):
        driver = load("linux_executor")
        for mutation in ("omit", "extra", "identifier", "kind", "executable", "unplanned"):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as td,
                patch.dict(os.environ, {"ISIGN_ISOLATED_EXECUTOR": "1"}),
            ):
                root, task, grant, run, verifier = self.fixture(td, include_dylib=True)

                def altered_run(args, **kwargs):
                    if args[0] == str(self.zsign):
                        plan_path = pathlib.Path(args[2])
                        plan = json.loads(plan_path.read_text())
                        relative = "Frameworks/r3yt.dylib"
                        if mutation == "omit":
                            plan.pop(relative)
                        elif mutation == "extra":
                            plan["Frameworks/missing.dylib"] = dict(plan[relative])
                        elif mutation == "identifier":
                            plan[relative]["bundleId"] = "isign.dylib.wrong"
                        elif mutation == "kind":
                            plan[relative]["kind"] = "framework"
                        elif mutation == "executable":
                            library = root / "Payload/App.app" / relative
                            raw = bytearray(library.read_bytes())
                            struct.pack_into("<I", raw, 12, 2)
                            library.write_bytes(raw)
                        else:
                            (root / "Payload/App.app/Frameworks/unplanned.dylib").write_bytes(
                                (root / "Payload/App.app" / relative).read_bytes()
                            )
                        plan_path.write_text(json.dumps(plan))
                    return run(args, **kwargs)

                with self.assertRaises(subprocess.CalledProcessError):
                    driver.execute_linux_task(
                        grant=grant,
                        task=task,
                        workspace=root,
                        vm_proof={},
                        validate_vm=lambda *a: True,
                        command_runner=altered_run,
                        verifier=verifier,
                        zsign_path=self.zsign,
                        zsign_digest=hashlib.sha256(self.zsign.read_bytes()).hexdigest(),
                        material_password_provider=lambda *a: "synthetic-p12-password",
                    )
                self.assertFalse((root / "signed.ipa").exists())

    def test_real_sign_main_extension_framework_and_independent_tampering_rejection(self):
        driver = load("linux_executor")
        with (
            tempfile.TemporaryDirectory() as td,
            patch.dict(os.environ, {"ISIGN_ISOLATED_EXECUTOR": "1"}),
        ):
            root, task, grant, run, verifier = self.fixture(td)
            report = driver.execute_linux_task(
                grant=grant,
                task=task,
                workspace=root,
                vm_proof={},
                validate_vm=lambda *a: True,
                command_runner=run,
                verifier=verifier,
                zsign_path=self.zsign,
                zsign_digest=hashlib.sha256(self.zsign.read_bytes()).hexdigest(),
                material_password_provider=lambda *a: "synthetic-p12-password",
            )
            self.assertTrue(all(report["checks"].values()))
            self.assertFalse(report["executionAuthorized"])
            self.assertTrue((root / "signed.ipa").exists())
            self.assertFalse((root / "materials/key.p12").exists())
            main = task["components"][0]
            folder = root / main["path"]
            resource = folder / "resource.txt"
            resource.write_text("TAMPERED")
            with self.assertRaises(ValueError):
                verifier.verify_component(folder, main, task, grant)
            resource.write_text("synthetic resource")
            binary = folder / "Fixture"
            original = binary.read_bytes()
            changed = bytearray(original)
            changed[4096] ^= 1
            binary.write_bytes(changed)
            with self.assertRaises(ValueError):
                verifier.verify_component(folder, main, task, grant)
            binary.write_bytes(original)
            info = folder / "Info.plist"
            original_info = info.read_bytes()
            info.write_bytes(original_info + b" ")
            with self.assertRaises(ValueError):
                verifier.verify_component(folder, main, task, grant)

    def test_real_sign_preserves_only_profile_authorized_source_capabilities(self):
        with (
            tempfile.TemporaryDirectory() as td,
            patch.dict(os.environ, {"ISIGN_ISOLATED_EXECUTOR": "1"}),
        ):
            root, task, grant, run, verifier = self.fixture(td)
            component = task["components"][0]
            source = {
                "application-identifier": "OLD.org.synthetic.app",
                "keychain-access-groups": [
                    "OLD.org.synthetic.app",
                    "group.shared",
                    "foreign.shared",
                ],
                "aps-environment": "production",
                "com.apple.security.application-groups": ["group.shared"],
                "com.apple.developer.icloud-container-identifiers": [
                    "iCloud.org.synthetic.documents"
                ],
                "com.example.structured": {
                    "enabled": True,
                    "version": 2,
                    "modes": ["one"],
                    "numbers": [
                        0,
                        1,
                        2,
                        127,
                        128,
                        255,
                        256,
                        -1,
                        -128,
                        -129,
                        9007199254740991,
                        -9007199254740991,
                    ],
                },
                "com.example.unavailable": True,
            }
            capabilities = {
                "aps-environment": "production",
                "com.apple.security.application-groups": ["group.shared"],
                "com.apple.developer.icloud-container-identifiers": [
                    "iCloud.org.synthetic.documents"
                ],
                "com.example.structured": {
                    "enabled": True,
                    "version": 2,
                    "modes": ["one"],
                    "numbers": [
                        0,
                        1,
                        2,
                        127,
                        128,
                        255,
                        256,
                        -1,
                        -128,
                        -129,
                        9007199254740991,
                        -9007199254740991,
                    ],
                },
            }
            profile = task["profiles"][component["bundleId"]]
            ceiling = {
                **profile["entitlements"],
                **capabilities,
                "keychain-access-groups": ["TEAM.org.synthetic.app", "group.shared"],
                "com.apple.developer.icloud-container-identifiers": ["iCloud.org.synthetic.*"],
                "com.example.profile-only": True,
            }
            component["sourceEntitlements"] = source
            component["entitlements"] = {
                **component["entitlements"],
                **capabilities,
                "keychain-access-groups": ["TEAM.org.synthetic.app", "group.shared"],
            }
            decoded = verifier.decode_profile(root / profile["materialPath"])
            decoded["Entitlements"] = ceiling
            cms = subprocess.run(
                [
                    self.openssl,
                    "cms",
                    "-sign",
                    "-binary",
                    "-nodetach",
                    "-outform",
                    "DER",
                    "-signer",
                    str(self.root / "cms.pem"),
                    "-inkey",
                    str(self.root / "cms.key"),
                ],
                input=plistlib.dumps(decoded),
                capture_output=True,
                check=True,
            ).stdout
            (root / profile["materialPath"]).write_bytes(cms)
            profile["entitlements"] = ceiling
            profile["cmsSha256"] = hashlib.sha256(cms).hexdigest()
            # Source signatures supply claims, not authority. A source XML blob
            # need not contain an authorized CodeDirectory to be normalized.
            binary = root / component["path"] / "Fixture"
            raw = bytearray(binary.read_bytes())
            xml = plistlib.dumps(source)
            claim = struct.pack(">II", 0xFADE7171, len(xml) + 8) + xml
            signature = struct.pack(">IIIII", 0xFADE0CC0, 20 + len(claim), 1, 5, 20) + claim
            count, size = struct.unpack_from("<II", raw, 16)
            self.assertEqual(raw[32 + size : 48 + size], b"\0" * 16)
            struct.pack_into("<II", raw, 16, count + 1, size + 16)
            struct.pack_into("<IIII", raw, 32 + size, 0x1D, 16, len(raw), len(signature))
            cursor = 32
            for _ in range(count):
                command, length = struct.unpack_from("<II", raw, cursor)
                if command == 0x19 and raw[cursor + 8 : cursor + 24].rstrip(b"\0") == b"__LINKEDIT":
                    fileoff = struct.unpack_from("<Q", raw, cursor + 40)[0]
                    struct.pack_into("<Q", raw, cursor + 48, len(raw) + len(signature) - fileoff)
                cursor += length
            raw.extend(signature)
            binary.write_bytes(raw)
            with zipfile.ZipFile(root / "source.ipa", "w") as archive:
                for path in (root / "Payload").rglob("*"):
                    if path.is_file():
                        archive.write(path, str(path.relative_to(root)))
            grant["uploadDigest"] = hashlib.sha256((root / "source.ipa").read_bytes()).hexdigest()
            grant["planDigest"] = load("executor").canonical_digest(task)
            report = load("linux_executor").execute_linux_task(
                grant=grant,
                task=task,
                workspace=root,
                vm_proof={},
                validate_vm=lambda *a: True,
                command_runner=run,
                verifier=verifier,
                zsign_path=self.zsign,
                zsign_digest=hashlib.sha256(self.zsign.read_bytes()).hexdigest(),
                material_password_provider=lambda *a: "synthetic-p12-password",
            )
            self.assertTrue(report["verification"]["archiveVerified"])
            actual = load("analyzer").analyze_file(root / "signed.ipa", allow_verified_der=True)
            ent = next(c["entitlements"] for c in actual["components"] if c["kind"] == "app")
            for key, value in capabilities.items():
                self.assertEqual(ent[key], value)
            self.assertEqual(
                ent["keychain-access-groups"], ["TEAM.org.synthetic.app", "group.shared"]
            )
            self.assertNotIn("com.example.unavailable", ent)
            self.assertNotIn("com.example.profile-only", ent)

    def test_safe_executable_name_with_spaces_and_plus_verifies_after_signing(self):
        with (
            tempfile.TemporaryDirectory() as td,
            patch.dict(os.environ, {"ISIGN_ISOLATED_EXECUTOR": "1"}),
        ):
            root, task, grant, run, verifier = self.fixture(td)
            folder = root / task["components"][0]["path"]
            name = "Synthetic App+Binary"
            (folder / "Fixture").rename(folder / name)
            info = plistlib.loads((folder / "Info.plist").read_bytes())
            info["CFBundleExecutable"] = name
            (folder / "Info.plist").write_bytes(plistlib.dumps(info))
            with zipfile.ZipFile(root / "source.ipa", "w") as archive:
                for path in (root / "Payload").rglob("*"):
                    if path.is_file():
                        archive.write(path, str(path.relative_to(root)))
            grant["uploadDigest"] = hashlib.sha256((root / "source.ipa").read_bytes()).hexdigest()
            report = load("linux_executor").execute_linux_task(
                grant=grant,
                task=task,
                workspace=root,
                vm_proof={},
                validate_vm=lambda *a: True,
                command_runner=run,
                verifier=verifier,
                zsign_path=self.zsign,
                zsign_digest=hashlib.sha256(self.zsign.read_bytes()).hexdigest(),
                material_password_provider=lambda *a: "synthetic-p12-password",
            )
            self.assertTrue(report["verification"]["archiveVerified"])
            self.assertTrue((folder / name).is_file())

    def test_der_missing_semantic_mismatch_cms_tamper_and_alternate_slots(self):
        driver = load("linux_executor")
        module = load("linux_verification")
        with (
            tempfile.TemporaryDirectory() as td,
            patch.dict(os.environ, {"ISIGN_ISOLATED_EXECUTOR": "1"}),
        ):
            root, task, grant, run, verifier = self.fixture(td)
            driver.execute_linux_task(
                grant=grant,
                task=task,
                workspace=root,
                vm_proof={},
                validate_vm=lambda *a: True,
                command_runner=run,
                verifier=verifier,
                zsign_path=self.zsign,
                zsign_digest=hashlib.sha256(self.zsign.read_bytes()).hexdigest(),
                material_password_provider=lambda *a: "synthetic-p12-password",
            )
            component = task["components"][0]
            folder = root / component["path"]
            binary = folder / "Fixture"
            raw = binary.read_bytes()
            offset, _, entries = module.macho_signature(raw)
            args = [
                raw,
                offset,
                entries,
                component,
                (folder / "Info.plist").read_bytes(),
                (folder / "_CodeSignature/CodeResources").read_bytes(),
                "TEAM",
                "Synthetic Distribution",
            ]
            args[2] = {
                **entries,
                5: module.blob(
                    0xFADE7171,
                    plistlib.dumps(dict(component["entitlements"], **{"get-task-allow": 0})),
                ),
            }
            with self.assertRaisesRegex(ValueError, "SIGNED_ENTITLEMENTS_MISMATCH"):
                module.verify_directory(*args)
            args[2] = {k: value for k, value in entries.items() if k != 7}
            with self.assertRaisesRegex(ValueError, "SIGNED_DER_ENTITLEMENTS_REQUIRED"):
                module.verify_directory(*args)
            args[2] = {
                **entries,
                7: module.blob(
                    0xFADE7172,
                    module.der(
                        112,
                        b"\x02\x01\x01"
                        + module.entitlement_der(
                            dict(component["entitlements"], **{"get-task-allow": True})
                        ),
                    ),
                ),
            }
            with self.assertRaisesRegex(ValueError, "SIGNED_DER_ENTITLEMENTS_MISMATCH"):
                module.verify_directory(*args)
            count = struct.unpack_from(">I", raw, offset + 8)[0]
            for index in range(count):
                slot, position = struct.unpack_from(">II", raw, offset + 12 + 8 * index)
                if slot == 0x10000:
                    bad_magic = bytearray(raw)
                    struct.pack_into(">I", bad_magic, offset + position, 0xFADE0C01)
                    with self.assertRaisesRegex(ValueError, "SIGNATURE_SLOT_MAGIC_INVALID"):
                        module.macho_signature(bad_magic)
                    changed = bytearray(raw)
                    changed[offset + position + 8 + 64] ^= 1
                    binary.write_bytes(changed)
                    with self.assertRaises(Exception):
                        verifier.verify_component(folder, component, task, grant)
                if slot == 7:
                    changed = bytearray(raw)
                    struct.pack_into(">I", changed, offset + 12 + 8 * index, 0x1000)
                    with self.assertRaisesRegex(ValueError, "SIGNATURE_SLOT_INVALID"):
                        module.macho_signature(changed)
            binary.write_bytes(raw)

    def test_linux_preflight_rejects_fat_and_capacity_before_provisioning(self):
        runtime = load("linux_runtime")
        guest = runtime.LinuxGuestRuntime.__new__(runtime.LinuxGuestRuntime)

        def archive(binary):
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w") as z:
                z.writestr(
                    "Payload/F.app/Info.plist", plistlib.dumps({"CFBundleExecutable": "Fixture"})
                )
                z.writestr("Payload/F.app/Fixture", binary)
            return stream.getvalue()

        analysis = {"components": [{"path": "Payload/F.app"}]}
        guest.validate_source_format(archive(unsigned_macho()), analysis)
        with self.assertRaisesRegex(ValueError, "FAT_BOUNDS"):
            guest.validate_source_format(archive(b"\xca\xfe\xba\xbe" + unsigned_macho()), analysis)
        with patch.object(
            runtime.zipfile.ZipFile,
            "infolist",
            return_value=[type("Entry", (), {"file_size": (4 << 30) + 1})()],
        ):
            with self.assertRaisesRegex(ValueError, "LINUX_SOURCE_CAPACITY_UNSUPPORTED"):
                guest.validate_source_format(archive(unsigned_macho()), analysis)

    def test_signed_cms_agility_hash_must_match_actual_primary_directory(self):
        module = load("linux_verification")
        driver = load("linux_executor")
        with (
            tempfile.TemporaryDirectory(prefix="synthetic-agility-") as td,
            patch.dict(os.environ, {"ISIGN_ISOLATED_EXECUTOR": "1"}),
        ):
            root, task, grant, run, verifier = self.fixture(td)
            driver.execute_linux_task(
                grant=grant,
                task=task,
                workspace=root,
                vm_proof={},
                validate_vm=lambda *a: True,
                command_runner=run,
                verifier=verifier,
                zsign_path=self.zsign,
                zsign_digest=hashlib.sha256(self.zsign.read_bytes()).hexdigest(),
                material_password_provider=lambda *a: "synthetic-p12-password",
            )
            folder = root / task["components"][0]["path"]
            raw = (folder / "Fixture").read_bytes()
            offset, _, entries = module.macho_signature(raw)
            directory = entries[0]
            cms = entries[0x10000][8:]
            module.cms_directory_attributes(cms, directory)
            digest = hashlib.sha256(directory).digest()
            needle = module.der(4, digest)
            self.assertIn(needle, cms)
            with self.assertRaisesRegex(ValueError, "CMS_DIRECTORY_AGILITY_MISMATCH"):
                module.cms_directory_attributes(
                    cms.replace(needle, module.der(4, b"x" * 32)), directory
                )

    def test_expired_and_wrong_plan_fail_before_signer_and_cleanup_rejected_plan(self):
        driver = load("linux_executor")
        with (
            tempfile.TemporaryDirectory() as td,
            patch.dict(os.environ, {"ISIGN_ISOLATED_EXECUTOR": "1"}),
        ):
            root, task, grant, run, verifier = self.fixture(td)
            calls = []
            options = dict(
                task=task,
                workspace=root,
                vm_proof={},
                validate_vm=lambda *a: True,
                command_runner=lambda *a, **kw: calls.append(a),
                verifier=verifier,
                zsign_path=self.zsign,
                zsign_digest=hashlib.sha256(self.zsign.read_bytes()).hexdigest(),
                material_password_provider=lambda *a: "synthetic-p12-password",
            )
            for bad in (dict(grant, planDigest="f" * 64), dict(grant, expiresAt=1)):
                with self.assertRaises(ValueError):
                    driver.execute_linux_task(grant=bad, **options)
            self.assertEqual(calls, [])
            self.assertFalse((root / "signed.ipa").exists())

    def test_duplicate_exact_profile_and_suffix_profile_selection_rejected(self):
        driver = load("linux_executor")
        for attack in ("duplicate", "suffix"):
            with (
                self.subTest(attack=attack),
                tempfile.TemporaryDirectory() as td,
                patch.dict(os.environ, {"ISIGN_ISOLATED_EXECUTOR": "1"}),
            ):
                root, task, grant, run, verifier = self.fixture(td)

                def mutate(args, **kwargs):
                    args = list(args)
                    if attack == "duplicate":
                        args[-1:-1] = ["-m", str(root / "materials/profile_0.mobileprovision")]
                    else:
                        plan_path = pathlib.Path(args[2])
                        plan = json.loads(plan_path.read_text())
                        plan["/"]["applicationId"] = "TEAM.prefix.org.synthetic.app"
                        plan_path.write_text(json.dumps(plan))
                    return run(args, **kwargs)

                with self.assertRaises(subprocess.CalledProcessError):
                    driver.execute_linux_task(
                        grant=grant,
                        task=task,
                        workspace=root,
                        vm_proof={},
                        validate_vm=lambda *a: True,
                        command_runner=mutate,
                        verifier=verifier,
                        zsign_path=self.zsign,
                        zsign_digest=hashlib.sha256(self.zsign.read_bytes()).hexdigest(),
                        material_password_provider=lambda *a: "synthetic-p12-password",
                    )
                self.assertFalse((root / "signed.ipa").exists())
                self.assertFalse((root / "materials/key.p12").exists())

    def test_successful_signer_exit_without_valid_signature_cannot_report_ready(self):
        driver = load("linux_executor")
        with (
            tempfile.TemporaryDirectory() as td,
            patch.dict(os.environ, {"ISIGN_ISOLATED_EXECUTOR": "1"}),
        ):
            root, task, grant, run, verifier = self.fixture(td)
            with self.assertRaisesRegex(ValueError, "SIGNATURE_REQUIRED"):
                driver.execute_linux_task(
                    grant=grant,
                    task=task,
                    workspace=root,
                    vm_proof={},
                    validate_vm=lambda *a: True,
                    command_runner=lambda *a, **kw: {"stdout": b"", "stderr": b""},
                    verifier=verifier,
                    zsign_path=self.zsign,
                    zsign_digest=hashlib.sha256(self.zsign.read_bytes()).hexdigest(),
                    material_password_provider=lambda *a: "synthetic-p12-password",
                )
            self.assertFalse((root / "signed.ipa").exists())
            self.assertFalse((root / "materials/key.p12").exists())

    def test_cancellation_after_actual_signer_removes_material_and_artifact(self):
        driver = load("linux_executor")
        with (
            tempfile.TemporaryDirectory() as td,
            patch.dict(os.environ, {"ISIGN_ISOLATED_EXECUTOR": "1"}),
        ):
            root, task, grant, run, verifier = self.fixture(td)
            active = [True]

            def cancel(args, **kwargs):
                result = run(args, **kwargs)
                active[0] = False
                return result

            with self.assertRaisesRegex(ValueError, "LINUX_EXECUTION_CANCELLED"):
                driver.execute_linux_task(
                    grant=grant,
                    task=task,
                    workspace=root,
                    vm_proof={},
                    validate_vm=lambda *a: active[0],
                    command_runner=cancel,
                    verifier=verifier,
                    zsign_path=self.zsign,
                    zsign_digest=hashlib.sha256(self.zsign.read_bytes()).hexdigest(),
                    material_password_provider=lambda *a: "synthetic-p12-password",
                )
            self.assertFalse((root / "signed.ipa").exists())
            self.assertFalse((root / "materials/key.p12").exists())

    def test_real_sign_verifies_each_component_once_from_finished_archive(self):
        driver = load("linux_executor")
        with (
            tempfile.TemporaryDirectory() as td,
            patch.dict(os.environ, {"ISIGN_ISOLATED_EXECUTOR": "1"}),
        ):
            root, task, grant, run, verifier = self.fixture(td, include_dylib=True)
            checked = []
            original = verifier.verify_component

            def verify(path, component, task, grant):
                checked.append((pathlib.Path(path).relative_to(root), component["path"]))
                return original(path, component, task, grant)

            verifier.verify_component = verify
            report = driver.execute_linux_task(
                grant=grant,
                task=task,
                workspace=root,
                vm_proof={},
                validate_vm=lambda *a: True,
                command_runner=run,
                verifier=verifier,
                zsign_path=self.zsign,
                zsign_digest=hashlib.sha256(self.zsign.read_bytes()).hexdigest(),
                material_password_provider=lambda *a: "synthetic-p12-password",
            )
            self.assertEqual(len(checked), len(task["components"]))
            self.assertEqual(
                {component for _, component in checked}, {c["path"] for c in task["components"]}
            )
            self.assertTrue(all(path.parts[0].startswith("verify-archive-") for path, _ in checked))
            self.assertTrue(report["verification"]["archiveVerified"])
            self.assertEqual(len(report["verification"]["components"]), len(task["components"]))

    def test_real_sign_canonicalizes_major_only_metadata_in_the_verified_archive(self):
        with (
            tempfile.TemporaryDirectory() as td,
            patch.dict(os.environ, {"ISIGN_ISOLATED_EXECUTOR": "1"}),
        ):
            root, task, grant, run, verifier = self.fixture(td)
            for component in task["components"]:
                info_path = root / component["path"] / "Info.plist"
                info = plistlib.loads(info_path.read_bytes())
                info["MinimumOSVersion"] = "15"
                info_path.write_bytes(plistlib.dumps(info))
            with zipfile.ZipFile(root / "source.ipa", "w") as archive:
                for path in (root / "Payload").rglob("*"):
                    if path.is_file():
                        archive.write(path, str(path.relative_to(root)))
            grant["uploadDigest"] = hashlib.sha256((root / "source.ipa").read_bytes()).hexdigest()
            report = load("linux_executor").execute_linux_task(
                grant=grant,
                task=task,
                workspace=root,
                vm_proof={},
                validate_vm=lambda *a: True,
                command_runner=run,
                verifier=verifier,
                zsign_path=self.zsign,
                zsign_digest=hashlib.sha256(self.zsign.read_bytes()).hexdigest(),
                material_password_provider=lambda *a: "synthetic-p12-password",
            )
            self.assertTrue(report["verification"]["archiveVerified"])
            with zipfile.ZipFile(root / "signed.ipa") as archive:
                for component in task["components"]:
                    info = plistlib.loads(archive.read(component["path"] + "/Info.plist"))
                    self.assertEqual(info["MinimumOSVersion"], "15.0")

    def test_real_sign_removes_only_encrypted_notification_and_preserves_other_components(self):
        from types import SimpleNamespace

        with (
            tempfile.TemporaryDirectory() as td,
            patch.dict(os.environ, {"ISIGN_ISOLATED_EXECUTOR": "1"}),
        ):
            root, task, grant, run, verifier = self.fixture(td)
            removed = "Payload/App.app/PlugIns/Notification.appex"
            folder = root / removed
            folder.mkdir()
            info = {
                "CFBundleIdentifier": "org.synthetic.app.notification",
                "CFBundleExecutable": "Protected",
                "MinimumOSVersion": "15.0",
                "NSExtension": {
                    "NSExtensionPointIdentifier": "com.apple.usernotifications.service"
                },
            }
            (folder / "Info.plist").write_bytes(plistlib.dumps(info))
            binary = bytearray(unsigned_macho())
            count, size = struct.unpack_from("<II", binary, 16)
            struct.pack_into("<II", binary, 16, count + 1, size + 24)
            struct.pack_into("<6I", binary, 32 + size, 0x2C, 24, 512, 4, 1, 0)
            (folder / "Protected").write_bytes(binary)
            main_info = root / "Payload/App.app/Info.plist"
            info = plistlib.loads(main_info.read_bytes())
            info["MinimumOSVersion"] = "14.0"
            main_info.write_bytes(plistlib.dumps(info))
            next(c for c in task["components"] if c["kind"] == "app")["minOs"] = "15.0.0"
            with zipfile.ZipFile(root / "source.ipa", "w") as archive:
                for path in (root / "Payload").rglob("*"):
                    if path.is_file():
                        archive.write(path, str(path.relative_to(root)))
            raw = (root / "source.ipa").read_bytes()
            grant["uploadDigest"] = hashlib.sha256(raw).hexdigest()
            task["removedExtensions"] = [
                {
                    "path": removed,
                    "bundleId": "org.synthetic.app.notification",
                    "extensionPoint": "com.apple.usernotifications.service",
                }
            ]
            grant["planDigest"] = load("executor").canonical_digest(task)
            shutil.rmtree(root / "Payload")
            app = load("guest_controller").GuestController.__new__(
                load("guest_controller").GuestController
            )
            app.root, app.source, app.grant = (
                root,
                {"sha256": grant["uploadDigest"], "size": len(raw)},
                lambda *a: None,
            )
            app.runtime = SimpleNamespace(
                verifier=verifier,
                execute=lambda grant, task, proof: load("linux_executor").execute_linux_task(
                    grant=grant,
                    task=task,
                    workspace=root,
                    vm_proof=proof,
                    validate_vm=lambda *a: True,
                    command_runner=run,
                    verifier=verifier,
                    zsign_path=self.zsign,
                    zsign_digest=hashlib.sha256(self.zsign.read_bytes()).hexdigest(),
                    material_password_provider=lambda *a: "synthetic-p12-password",
                ),
            )
            report = app.action("execute", {"grant": grant, "task": task, "proof": {}})
            self.assertTrue(report["verification"]["archiveVerified"])
            self.assertEqual(len(report["verification"]["components"]), 3)
            with zipfile.ZipFile(root / "signed.ipa") as archive:
                self.assertFalse(any(name.startswith(removed + "/") for name in archive.namelist()))
                self.assertEqual(
                    archive.read("Payload/App.app/PlugIns/Extension.appex/resource.txt"),
                    b"synthetic resource",
                )
                self.assertEqual(
                    archive.read("Payload/App.app/Frameworks/Library.framework/resource.txt"),
                    b"synthetic resource",
                )
                self.assertEqual(
                    plistlib.loads(archive.read("Payload/App.app/Info.plist"))["MinimumOSVersion"],
                    "15.0.0",
                )

    def test_real_sign_still_rejects_finished_archive_corruption(self):
        driver = load("linux_executor")
        with (
            tempfile.TemporaryDirectory() as td,
            patch.dict(os.environ, {"ISIGN_ISOLATED_EXECUTOR": "1"}),
        ):
            root, task, grant, run, verifier = self.fixture(td)
            original = verifier.verify_archive

            def corrupted(path, task, grant):
                main = next(c for c in task["components"] if c["kind"] == "app")
                with zipfile.ZipFile(path) as archive:
                    info = plistlib.loads(archive.read(main["path"] + "/Info.plist"))
                    binary = main["path"] + "/" + info["CFBundleExecutable"]
                    entries = [(entry, archive.read(entry)) for entry in archive.infolist()]
                changed = path.with_suffix(".changed.ipa")
                with zipfile.ZipFile(changed, "x") as archive:
                    for entry, raw in entries:
                        if entry.filename == binary:
                            raw = bytearray(raw)
                            raw[512] ^= 1
                        archive.writestr(entry, raw)
                changed.replace(path)
                return original(path, task, grant)

            verifier.verify_archive = corrupted
            with self.assertRaisesRegex(ValueError, "EXECUTABLE_PAGE_HASH_MISMATCH"):
                driver.execute_linux_task(
                    grant=grant,
                    task=task,
                    workspace=root,
                    vm_proof={},
                    validate_vm=lambda *a: True,
                    command_runner=run,
                    verifier=verifier,
                    zsign_path=self.zsign,
                    zsign_digest=hashlib.sha256(self.zsign.read_bytes()).hexdigest(),
                    material_password_provider=lambda *a: "synthetic-p12-password",
                )
            self.assertFalse((root / "signed.ipa").exists())
            self.assertFalse((root / "materials/key.p12").exists())

    def test_unknown_critical_extension_rejected(self):
        policy = load("linux_certificate_policy").LinuxCertificatePolicy(
            [self.der(self.ca), self.der(self.rootcert)]
        )
        identity = {
            "teamId": "TEAM",
            "fingerprint": hashlib.sha1(self.der(self.cert)).hexdigest().upper(),
        }
        self.assertTrue(policy(self.der(self.cert), identity))
        identity["fingerprint"] = hashlib.sha1(self.der(self.badcert)).hexdigest().upper()
        with self.assertRaisesRegex(ValueError, "UNKNOWN_CRITICAL"):
            policy(self.der(self.badcert), identity)
        badchain = load("linux_certificate_policy").LinuxCertificatePolicy(
            [self.der(self.badca), self.der(self.rootcert)]
        )
        identity["fingerprint"] = hashlib.sha1(self.der(self.cert)).hexdigest().upper()
        with self.assertRaisesRegex(ValueError, "UNKNOWN_CRITICAL"):
            badchain(self.der(self.cert), identity)
