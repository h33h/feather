import io
import plistlib
import struct
import unittest
import zipfile
from runner_modules import load
from test_runner_analyzer import archive, macho


def source_with_metadata(**changes):
    stream = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(archive())) as original, zipfile.ZipFile(stream, "w") as output:
        info = plistlib.loads(original.read("Payload/App.app/Info.plist"))
        info.update(changes)
        info = {key: value for key, value in info.items() if value is not None}
        for entry in original.infolist():
            if entry.filename.endswith("/Info.plist"):
                output.writestr(entry.filename, plistlib.dumps(info))
            else:
                output.writestr(
                    "Payload/App.app/" + info["CFBundleExecutable"], original.read(entry)
                )
    return stream.getvalue()


class SourceMetadataTests(unittest.TestCase):
    def test_numeric_major_only_minimum_is_canonicalized_without_changing_dotted_versions(self):
        analyzer = load("analyzer")
        for value, expected in (("16", "16.0"), ("16.0", "16.0"), ("16.0.0", "16.0.0")):
            with self.subTest(value=value):
                report = analyzer.analyze_bytes(source_with_metadata(MinimumOSVersion=value))
                self.assertEqual(report["components"][0]["minOs"], expected)

    def test_framework_major_only_minimum_matches_the_binary_requirement(self):
        analyzer = load("analyzer")
        info = {
            "CFBundleIdentifier": "com.mintegral.MTGSDK",
            "CFBundleExecutable": "MTGSDK",
            "MinimumOSVersion": "12",
            "CFBundleSupportedPlatforms": ["iPhoneOS"],
        }
        binary = bytearray(macho(filetype=6))
        struct.pack_into("<I", binary, 44, 12 << 16)
        prefix = "Payload/App.app/Frameworks/MTGSDK.framework/"
        report = analyzer.analyze_bytes(
            archive(
                [(prefix + "Info.plist", plistlib.dumps(info)), (prefix + "MTGSDK", bytes(binary))]
            )
        )
        component = next(c for c in report["components"] if c["kind"] == "framework")
        self.assertEqual(component["minOs"], "12.0")
        info["MinimumOSVersion"] = "11"
        corrected = analyzer.analyze_bytes(
            archive(
                [
                    (prefix + "Info.plist", plistlib.dumps(info)),
                    (prefix + "MTGSDK", bytes(binary)),
                ]
            )
        )
        self.assertEqual(
            next(c for c in corrected["components"] if c["kind"] == "framework")["minOs"], "12.0.0"
        )
        self.assertEqual(corrected["warnings"][0]["code"], "MIN_OS_CORRECTED")

    def test_minimum_version_format_does_not_hide_invalid_values_or_lower_binary_requirements(self):
        analyzer = load("analyzer")
        for value in (
            True,
            False,
            16,
            16.0,
            [],
            {},
            "",
            " ",
            "16 ",
            " 16",
            "16\n",
            "v16",
            "16a",
            "+16",
            "16..0",
            "16.0.0.0",
        ):
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(ValueError, "^METADATA_INVALID$"),
            ):
                analyzer.analyze_bytes(source_with_metadata(MinimumOSVersion=value))
        report = analyzer.analyze_bytes(source_with_metadata(MinimumOSVersion="15"))
        self.assertEqual(report["components"][0]["minOs"], "16.0.0")

    def test_framework_identifiers_do_not_require_a_registered_app_id(self):
        analyzer = load("analyzer")
        info = {
            "CFBundleIdentifier": "ExampleSDK",
            "CFBundleExecutable": "ExampleSDK",
            "MinimumOSVersion": "16.0",
            "CFBundleSupportedPlatforms": ["iPhoneOS"],
        }
        report = analyzer.analyze_bytes(
            archive(
                [
                    (
                        "Payload/App.app/Frameworks/ExampleSDK.framework/Info.plist",
                        plistlib.dumps(info),
                    ),
                    (
                        "Payload/App.app/Frameworks/ExampleSDK.framework/ExampleSDK",
                        macho(filetype=6),
                    ),
                ]
            )
        )
        framework = next(c for c in report["components"] if c["kind"] == "framework")
        self.assertEqual(framework["bundleId"], "ExampleSDK")
        with self.assertRaisesRegex(ValueError, "METADATA_INVALID"):
            analyzer.analyze_bytes(source_with_metadata(CFBundleIdentifier="MainApp"))

    def test_accepts_safe_executable_names_and_infers_missing_optional_platform_metadata(self):
        analyzer = load("analyzer")
        report = analyzer.analyze_bytes(
            source_with_metadata(
                CFBundleExecutable="Example App+",
                MinimumOSVersion=None,
                CFBundleSupportedPlatforms=None,
                CFBundleShortVersionString=None,
            )
        )
        self.assertEqual(report["version"], "7")
        self.assertEqual(report["components"][0]["minOs"], "16.0.0")
        self.assertEqual(report["components"][0]["platform"], "ios")

    def test_does_not_infer_over_invalid_explicit_metadata(self):
        analyzer = load("analyzer")
        for metadata in (
            {"CFBundleExecutable": "../escape"},
            {"CFBundleExecutable": ".."},
            {"CFBundleSupportedPlatforms": ["iPhoneSimulator"]},
            {"MinimumOSVersion": "invalid"},
        ):
            with (
                self.subTest(metadata=metadata),
                self.assertRaisesRegex(ValueError, "METADATA_INVALID|ZIP_PATH_REJECTED"),
            ):
                analyzer.analyze_bytes(source_with_metadata(**metadata))
