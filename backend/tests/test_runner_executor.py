from runner_modules import module_path
import importlib.util, pathlib, tempfile, unittest, time, os, plistlib, json, hashlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("executor", module_path("executor"))
executor = importlib.util.module_from_spec(spec)


class ExecutorTests(unittest.TestCase):
    def setUp(self):
        from unittest.mock import patch

        gate = patch.dict(os.environ, {"ISIGN_ISOLATED_EXECUTOR": "1"})
        gate.start()
        self.addCleanup(gate.stop)
        spec.loader.exec_module(executor)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name).resolve()
        self.commands = []
        self.grant = dict(
            connectionOwnerId="o",
            ownerId="o",
            jobId="j",
            leaseToken="l",
            connectionId="c",
            connectionGeneration=1,
            deviceId="d",
            uploadDigest="a" * 64,
            taskNonce="n",
            isolationInstanceId="vm",
            expiresAt=int(time.time() * 1000) + 3600000,
        )
        self.components = []
        for path, kind, bid in [
            ("Payload/App.app", "app", "org.example.app"),
            ("Payload/App.app/Frameworks/Kit.framework", "framework", "org.example.kit"),
            ("Payload/App.app/PlugIns/Share.appex", "appex", "org.example.app.share"),
        ]:
            folder = self.root / path
            folder.mkdir(parents=True)
            (folder / "Info.plist").write_bytes(
                plistlib.dumps(
                    {
                        "CFBundleIdentifier": bid,
                        "CFBundleExecutable": "Binary",
                        "CFBundleShortVersionString": "1.2",
                        "CFBundleDisplayName": "Синтетика",
                    }
                )
            )
            (folder / "Binary").write_bytes(b"synthetic test only")
            self.components.append(
                dict(
                    path=path,
                    kind=kind,
                    bundleId=bid,
                    platform="ios",
                    architectures=["arm64"],
                    encrypted=False,
                    minOs="16.0",
                    entitlements={}
                    if kind == "framework"
                    else {
                        "application-identifier": "TEAM." + bid,
                        "com.apple.developer.team-identifier": "TEAM",
                        "get-task-allow": False,
                    },
                    profileRequired=kind != "framework",
                )
            )
        (self.root / "identity.p12").write_bytes(b"SYNTHETIC")
        (self.root / "app.profile").write_bytes(b"SYNTHETIC")
        (self.root / "appex.profile").write_bytes(b"SYNTHETIC")
        self.task = dict(
            components=self.components,
            identity=dict(
                ownerId="o",
                teamId="TEAM",
                prefix="TEAM",
                fingerprint="A" * 40,
                expiresAt=int(time.time() * 1000) + 3600000,
                materialPath="identity.p12",
            ),
            udid="TEST-UDID",
            profiles={},
        )
        for c in self.components:
            c["sourceBundleId"] = c["bundleId"]
            c["sourceEntitlements"] = dict(c["entitlements"])
            if c["profileRequired"]:
                self.task["profiles"][c["bundleId"]] = {
                    **self.task["identity"],
                    "bundleId": c["bundleId"],
                    "udids": ["TEST-UDID"],
                    "entitlements": c["entitlements"],
                    "materialPath": "app.profile" if c["kind"] == "app" else "appex.profile",
                }

    def command(self, args, **kwargs):
        self.commands.append(args)
        if args[0] == "/usr/bin/ditto":
            pathlib.Path(args[-1]).write_bytes(b"SYNTHETIC-SIGNED-ARCHIVE")

    def verify(self, *args, **kwargs):
        return {k: True for k in (*executor.REQUIRED_VERIFICATION, *executor.MATERIAL_VERIFICATION)}

    def run_task(self):
        return executor.validate_plan(self.task, self.grant, self.root, int(time.time() * 1000))

    def test_current_task_requires_explicit_source_identity(self):
        for component in self.components:
            component["sourceBundleId"] = component["bundleId"]
            component["sourceEntitlements"] = dict(component["entitlements"])
        self.components[0].pop("sourceBundleId")
        with self.assertRaisesRegex(ValueError, "SOURCE_IDENTITY_REQUIRED"):
            self.run_task()

    def add_library(self):
        import struct

        path = "Payload/App.app/Frameworks/libFixture.dylib"
        command = struct.pack("<IIIIII", 0x32, 24, 2, 16 << 16, 0, 0)
        binary = struct.pack("<8I", 0xFEEDFACF, 0x100000C, 0, 6, 1, 24, 0, 0) + command
        (self.root / path).write_bytes(binary)
        component = dict(
            path=path,
            kind="dylib",
            bundleId="isign.dylib." + hashlib.sha256(path.encode()).hexdigest(),
            platform="ios",
            architectures=["arm64"],
            encrypted=False,
            minOs="16.0",
            entitlements={},
            profileRequired=False,
        )
        component["sourceBundleId"] = component["bundleId"]
        component["sourceEntitlements"] = {}
        self.components.append(component)
        return component

    def test_library_inventory_type_identity_and_profile_rejected(self):
        import copy, struct

        library = self.add_library()
        baseline = copy.deepcopy(self.task)
        path = self.root / library["path"]
        original = path.read_bytes()
        for case in (
            "omitted",
            "extra",
            "type",
            "identifier",
            "profile",
            "entitlements",
            "directory",
        ):
            with self.subTest(case=case):
                self.task = copy.deepcopy(baseline)
                library = self.task["components"][-1]
                if case == "omitted":
                    self.task["components"].pop()
                if case == "extra":
                    (path.parent / "extra.dylib").write_bytes(original)
                if case == "type":
                    raw = bytearray(original)
                    struct.pack_into("<I", raw, 12, 2)
                    path.write_bytes(raw)
                if case == "identifier":
                    library["bundleId"] = "org.example.wrong"
                if case == "profile":
                    library["profileRequired"] = True
                if case == "entitlements":
                    library["entitlements"] = {"get-task-allow": False}
                if case == "directory":
                    path.unlink()
                    path.mkdir()
                with self.assertRaises(ValueError):
                    executor.validate_plan(self.task, self.grant, self.root, time.time() * 1000)
                if path.is_dir():
                    path.rmdir()
                path.write_bytes(original)
                (path.parent / "extra.dylib").unlink(missing_ok=True)

    def test_unknown_entitlement_expiry_and_mismatched_profile_rejected(self):
        import copy

        baseline = copy.deepcopy((self.components, self.task))
        for mutate in [
            lambda: self.components[0]["entitlements"].update({"aps-environment": "production"}),
            lambda: self.task["identity"].update(expiresAt=0),
            lambda: self.task["profiles"]["org.example.app"].update(udids=["OTHER"]),
        ]:
            with self.subTest(mutation=mutate):
                self.components, self.task = copy.deepcopy(baseline)
                mutate()
                with self.assertRaises(ValueError):
                    self.run_task()
                self.assertEqual(self.commands, [])

    def test_preserves_profile_authorized_source_claims_and_refuses_profile_only_injection(self):
        import copy

        component = self.components[0]
        profile = self.task["profiles"][component["bundleId"]]
        profile["entitlements"] = {
            **profile["entitlements"],
            "aps-environment": "production",
            "com.example.structured": {"enabled": True, "modes": ["one", "two"]},
            "com.example.profile-only": True,
        }
        component["sourceEntitlements"] = {
            "aps-environment": "production",
            "com.example.structured": {"enabled": True, "modes": ["one"]},
            "com.example.unavailable": True,
        }
        component["entitlements"].update(
            {
                "aps-environment": "production",
                "com.example.structured": {"enabled": True, "modes": ["one"]},
            }
        )
        self.run_task()
        baseline = copy.deepcopy(component["entitlements"])
        for key, value in (
            ("com.example.profile-only", True),
            ("com.example.unavailable", True),
            ("com.example.structured", {"enabled": 1, "modes": ["one"]}),
        ):
            with self.subTest(key=key):
                component["entitlements"] = {**baseline, key: value}
                with self.assertRaises(ValueError):
                    self.run_task()

    def mapping_task(self):
        for c in self.components:
            if c["kind"] == "framework":
                continue
            original = c["bundleId"]
            c["sourceBundleId"] = original
            c["bundleId"] = original.replace("org.example.app", "net.copy.app")
            c["entitlements"]["application-identifier"] = "TEAM." + c["bundleId"]
            p = self.task["profiles"].pop(original)
            p["bundleId"] = c["bundleId"]
            self.task["profiles"][c["bundleId"]] = p

    def test_dotless_framework_id_and_unchanged_metadata_survive_app_mapping(self):
        framework = next(c for c in self.components if c["kind"] == "framework")
        framework["bundleId"] = "FixtureKit"
        framework["sourceBundleId"] = "FixtureKit"
        path = self.root / framework["path"] / "Info.plist"
        info = plistlib.loads(path.read_bytes())
        info.update(
            CFBundleIdentifier="FixtureKit",
            CFBundleName="FixtureKit",
            CFBundleExecutable="FixtureKit",
        )
        path.write_bytes(plistlib.dumps(info))
        self.mapping_task()
        self.run_task()
        info["OriginalAppReference"] = "org.example.app"
        path.write_bytes(plistlib.dumps(info))
        with self.assertRaisesRegex(ValueError, "UNSUPPORTED_IDENTIFIER_REFERENCE"):
            self.run_task()

    def test_dotless_app_and_extension_and_unsafe_framework_ids_are_rejected(self):
        import copy

        baseline = copy.deepcopy(self.components)
        for index, bid in [
            (0, "FixtureApp"),
            (2, "FixtureExtension"),
            (1, ""),
            (1, ".FixtureKit"),
            (1, "FixtureKit."),
            (1, "Fixture..Kit"),
            (1, "Fixture_Kit"),
            (1, "../FixtureKit"),
        ]:
            with self.subTest(index=index, bid=bid):
                self.components[:] = copy.deepcopy(baseline)
                self.components[index]["bundleId"] = bid
                with self.assertRaises(ValueError):
                    self.run_task()

    def test_mapping_unknown_identifier_reference_rejected(self):
        self.mapping_task()
        path = self.root / "Payload/App.app/Info.plist"
        info = plistlib.loads(path.read_bytes())
        info["WKCompanionAppBundleIdentifier"] = "org.example.app"
        path.write_bytes(plistlib.dumps(info))
        with self.assertRaisesRegex(ValueError, "UNSUPPORTED_IDENTIFIER_REFERENCE"):
            self.run_task()
        self.assertEqual(self.commands, [])

    def test_unknown_nested_bundle_rejected(self):
        (self.root / "Payload/App.app/Unknown.app").mkdir()
        with self.assertRaisesRegex(ValueError, "COMPONENT_GRAPH_REJECTED"):
            self.run_task()
        self.assertEqual(self.commands, [])

    def test_resource_bundle_without_code_is_not_an_executable_component(self):
        folder = self.root / "Payload/App.app/Assets.bundle"
        folder.mkdir()
        (folder / "Info.plist").write_bytes(
            plistlib.dumps(
                {"CFBundleIdentifier": "org.example.resources", "CFBundlePackageType": "BNDL"}
            )
        )
        (folder / "en.lproj").mkdir()
        (folder / "en.lproj/strings.txt").write_text("synthetic resource")
        ordered, _ = executor.validate_plan(
            self.task, self.grant, self.root, int(time.time() * 1000)
        )
        self.assertEqual(len(ordered), 3)
        (folder / "Info.plist").write_bytes(b'{"CFBundlePackageType":"BNDL"}')
        executor.validate_plan(self.task, self.grant, self.root, int(time.time() * 1000))

    def test_executable_bundles_and_xpc_services_remain_rejected(self):
        cases = [
            ("Declared.bundle", "Info.plist", plistlib.dumps({"CFBundleExecutable": "Binary"})),
            ("Hidden.bundle", "image.dat", b"\xcf\xfa\xed\xfe" + b"\0" * 32),
            ("Service.xpc", "resource.txt", b"resource"),
        ]
        for directory, name, raw in cases:
            with self.subTest(directory=directory):
                folder = self.root / "Payload/App.app" / directory
                folder.mkdir()
                (folder / name).write_bytes(raw)
                with self.assertRaisesRegex(ValueError, "UNMODELED_EXECUTABLE"):
                    executor.validate_plan(
                        self.task, self.grant, self.root, int(time.time() * 1000)
                    )
                import shutil

                shutil.rmtree(folder)


if __name__ == "__main__":
    unittest.main()
