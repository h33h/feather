from runner_modules import module_path
import importlib.util, pathlib, unittest, io, zipfile, plistlib, struct, os, warnings, sys, time

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load():
    spec = importlib.util.spec_from_file_location("runner", module_path("analyzer"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def macho(platform=2, encrypted=0, cpu=0x100000C, filetype=2):
    cmds = struct.pack("<IIIIII", 0x32, 24, platform, 0x100000, 0, 0) + struct.pack(
        "<IIIIII", 0x2C, 24, 0, 0, encrypted, 0
    )
    return struct.pack("<IIIIIIII", 0xFEEDFACF, cpu, 0, filetype, 2, len(cmds), 0, 0) + cmds


def archive(extra=(), binary=None):
    out = io.BytesIO()
    info = {
        "CFBundleIdentifier": "org.example.app",
        "CFBundleExecutable": "App",
        "CFBundleShortVersionString": "1.2",
        "CFBundleVersion": "7",
        "MinimumOSVersion": "16.0",
        "CFBundleSupportedPlatforms": ["iPhoneOS"],
    }
    with warnings.catch_warnings(), zipfile.ZipFile(out, "w") as z:
        warnings.simplefilter("ignore", UserWarning)
        z.writestr("Payload/App.app/Info.plist", plistlib.dumps(info))
        z.writestr("Payload/App.app/App", macho() if binary is None else binary)
        for name, data in extra:
            z.writestr(name, data)
    return out.getvalue()


class AnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.runner = load()

    def test_synthetic_graph(self):
        r = self.runner.analyze_bytes(archive())
        self.assertEqual(r["bundleId"], "org.example.app")
        self.assertEqual(r["build"], "7")
        self.assertEqual(r["components"][0]["architectures"], ["arm64"])

    def test_resource_bundles_are_data_but_declared_executables_are_rejected_early(self):
        resource = "Payload/App.app/Assets.bundle/Info.plist"
        report = self.runner.analyze_bytes(
            archive(
                [
                    (resource, plistlib.dumps({"CFBundlePackageType": "BNDL"})),
                    ("Payload/App.app/Assets.bundle/strings.txt", b"resource"),
                ]
            )
        )
        self.assertEqual(len(report["components"]), 1)
        self.runner.analyze_bytes(archive([(resource, b'{"CFBundlePackageType":"BNDL"}')]))
        self.runner.analyze_bytes(
            archive(
                [
                    (
                        resource,
                        b'{ "CFBundleIdentifier" = "org.example.resources"; "CFBundlePackageType" = "BNDL"; }',
                    )
                ]
            )
        )
        self.runner.analyze_bytes(archive([(resource, b"opaque resource data")]))
        self.runner.analyze_bytes(
            archive([(resource, b'{ "Name" = "{ CFBundleExecutable = example"; }')])
        )
        for extras in [
            [(resource, plistlib.dumps({"CFBundleExecutable": "Binary"}))],
            [(resource, b'{"CFBundleExecutable":"Binary"}')],
            [
                (resource, b'{ "CFBundleExecutable" = "Binary"; }'),
                ("Payload/App.app/Assets.bundle/Binary", macho()),
            ],
            [("Payload/App.app/Assets.bundle/hidden.dat", macho())],
            [("Payload/App.app/Assets.bundle/hidden.dat", b"\xbe\xba\xfe\xca" + b"\0" * 32)],
            [("Payload/App.app/Assets.bundle/hidden.dat", b"\xbf\xba\xfe\xca" + b"\0" * 32)],
            [("Payload/App.app/Service.xpc/data", b"resource")],
        ]:
            with (
                self.subTest(extras=extras),
                self.assertRaisesRegex(ValueError, "UNMODELED_EXECUTABLE"),
            ):
                self.runner.analyze_bytes(archive(extras))

    def test_models_standalone_dylib_without_bundle_metadata(self):
        path = "Payload/App.app/Frameworks/libFixture.dylib"
        report = self.runner.analyze_bytes(archive([(path, macho(filetype=6))]))
        component = next(c for c in report["components"] if c["path"] == path)
        self.assertEqual(component["kind"], "dylib")
        self.assertEqual(component["minOs"], "16.0.0")
        self.assertEqual(component["entitlements"], {})
        self.assertEqual(
            component["bundleId"],
            "isign.dylib.7e9532e15d683c755f5c4dbc7b6f5651fe1e0d8cc2d8c0180fb48f012d777107",
        )
        self.assertEqual(component["architectures"], ["arm64"])

    def test_standalone_code_is_not_accepted_by_filename_alone(self):
        for path, binary in [
            ("Payload/App.app/Frameworks/libFixture.dylib", macho(filetype=2)),
            ("Payload/App.app/Frameworks/libFixture.so", macho(filetype=6)),
            ("SwiftSupport/libFixture.dylib", macho(filetype=6)),
        ]:
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.runner.analyze_bytes(archive([(path, binary)]))

    def test_traversal_casefold_duplicate_symlink(self):
        for name in [
            "../escape",
            "Payload/App.app/../escape",
            "payload/app.app/info.PLIST",
            "Payload/App.app/App",
            "/absolute",
            "a\\b",
        ]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.runner.analyze_bytes(archive([(name, b"x")]))
        link = zipfile.ZipInfo("Payload/App.app/link")
        link.external_attr = 0o120777 << 16
        with self.assertRaises(ValueError):
            self.runner.analyze_bytes(archive([(link, b"target")]))

    def test_platform_drm_truncation(self):
        for b in [macho(7), macho(encrypted=1), macho(cpu=7), macho()[:-1], b"not macho"]:
            with self.subTest(binary=b), self.assertRaises(ValueError):
                self.runner.analyze_bytes(archive(binary=b))

    def test_crc_and_container_truncation(self):
        raw = bytearray(archive())
        offset = raw.index(b"org.example.app")
        raw[offset] = ord("x")
        for data in (bytes(raw), archive()[:-30]):
            with self.assertRaises(ValueError):
                self.runner.analyze_bytes(data)

    def test_fat_bounds_and_valid_slice(self):
        thin = macho()
        fat = (
            struct.pack(">IIIIIII", 0xCAFEBABE, 1, 0x100000C, 0, 32, len(thin), 3)
            + b"\0" * 4
            + thin
        )
        self.assertEqual(
            self.runner.analyze_bytes(archive(binary=fat))["components"][0]["architectures"],
            ["arm64"],
        )
        with self.assertRaises(ValueError):
            self.runner.analyze_bytes(archive(binary=fat[:-1]))

    def test_entitlements_report_capabilities_for_normalization(self):
        for ent in (
            {"aps-environment": "development"},
            {"application-identifier": "A.org.example.app", "keychain-access-groups": ["shared"]},
        ):
            payload = plistlib.dumps(ent)
            blob = struct.pack(">II", 0xFADE7171, 8 + len(payload)) + payload
            signature = struct.pack(">IIIII", 0xFADE0CC0, 20 + len(blob), 1, 5, 20) + blob
            binary = macho()
            binary = bytearray(binary)
            struct.pack_into("<II", binary, 16, 3, 64)
            binary = bytes(binary) + struct.pack("<IIII", 0x1D, 16, 96, len(signature)) + signature
            self.assertEqual(
                self.runner.analyze_bytes(archive(binary=binary))["components"][0]["entitlements"],
                ent,
            )

    def test_framework_and_simple_extension_graph(self):
        extras = []
        for folder, bid in [
            ("Frameworks/Kit.framework", "org.example.kit"),
            ("PlugIns/Share.appex", "org.example.app.share"),
        ]:
            base = "Payload/App.app/" + folder
            info = {
                "CFBundleIdentifier": bid,
                "CFBundleExecutable": "Binary",
                "MinimumOSVersion": "16.0",
                "CFBundleSupportedPlatforms": ["iPhoneOS"],
            }
            extras.extend(
                [(base + "/Info.plist", plistlib.dumps(info)), (base + "/Binary", macho())]
            )
        graph = self.runner.analyze_bytes(archive(extras))["components"]
        self.assertEqual({c["kind"] for c in graph}, {"app", "framework", "appex"})

    def test_segment_file_bounds(self):
        binary = bytearray(macho())
        struct.pack_into("<II", binary, 16, 3, 120)
        segment = struct.pack("<II16sQQQQIIII", 0x19, 72, b"__TEXT", 0, 0, 9999, 5, 0, 0, 0, 0)
        with self.assertRaises(ValueError):
            self.runner.analyze_bytes(archive(binary=bytes(binary) + segment))

    def test_path_file_directory_conflict(self):
        with self.assertRaises(ValueError):
            self.runner.analyze_bytes(archive([("a", b"x"), ("a/b", b"y")]))

    def test_metadata_and_binary_memory_limits(self):
        self.runner.MAX_METADATA = 1
        with self.assertRaisesRegex(ValueError, "METADATA_LIMIT"):
            self.runner.analyze_bytes(archive())
        self.runner.MAX_METADATA = 4 << 20
        self.runner.MAX_BINARY = 1
        with self.assertRaisesRegex(ValueError, "BINARY_LIMIT"):
            self.runner.analyze_bytes(archive())

    def test_limit_enforcement(self):
        self.runner.MAX_ENTRIES = 1
        with self.assertRaises(ValueError):
            self.runner.analyze_bytes(archive())
        self.runner.MAX_ENTRIES = 20000
        self.runner.MAX_UNPACKED = 1
        with self.assertRaises(ValueError):
            self.runner.analyze_bytes(archive())
        self.runner.MAX_INPUT = 1
        with self.assertRaises(ValueError):
            self.runner.analyze_bytes(archive())

    def test_grant_binding(self):
        g = dict(
            connectionOwnerId="o",
            ownerId="o",
            jobId="j",
            leaseToken="l",
            connectionId="c",
            deviceId="d",
            connectionGeneration=1,
            uploadDigest="a" * 64,
            taskNonce="n",
            isolationInstanceId="vm-1",
            expiresAt=int(time.time() * 1000) + 3600000,
        )
        self.runner.validate_grant(g, now=100)
        with self.assertRaises(ValueError):
            self.runner.validate_grant(g, now=g["expiresAt"] + 1)
        report = self.runner.make_report(g, {"sha256": "a" * 64})
        self.assertEqual(report["taskNonce"], "n")
        with self.assertRaises(ValueError):
            self.runner.make_report(g, {"sha256": "b" * 64})


if __name__ == "__main__":
    unittest.main()
