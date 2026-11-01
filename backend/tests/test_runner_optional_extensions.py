"""Source-only recovery must remove exactly encrypted optional extension trees."""

import io
import plistlib
import struct
import unittest
import zipfile

from runner_modules import load
from test_runner_analyzer import archive, macho

NOTIFICATION = "Payload/App.app/PlugIns/Notification.appex"
WIDGET = "Payload/App.app/PlugIns/Widget.appex"


def extension(path, *, point="com.apple.usernotifications.service", encrypted=True):
    binary = bytearray(macho(encrypted=int(encrypted)))
    struct.pack_into("<II", binary, 64, 80, 16)
    binary.extend(b"protected bytes!")
    info = {
        "CFBundleIdentifier": "org.example.app." + path.rsplit("/", 1)[-1][:-6],
        "CFBundleExecutable": "Extension",
        "MinimumOSVersion": "16.0",
        "NSExtension": {"NSExtensionPointIdentifier": point},
    }
    return [(path + "/Info.plist", plistlib.dumps(info)), (path + "/Extension", bytes(binary))]


class OptionalExtensionTests(unittest.TestCase):
    def test_encrypted_notification_is_removed_but_clear_widget_and_shared_library_remain(self):
        extras = extension(NOTIFICATION) + extension(
            WIDGET, point="com.apple.widgetkit-extension", encrypted=False
        )
        extras += [(NOTIFICATION + "/private.txt", b"extension-only resource")]
        extras += [("Payload/App.app/Frameworks/shared.dylib", macho(filetype=6))]
        report = load("analyzer").analyze_bytes(archive(extras))
        self.assertEqual(
            {c["path"] for c in report["components"]},
            {"Payload/App.app", WIDGET, "Payload/App.app/Frameworks/shared.dylib"},
        )
        self.assertEqual(
            report["removedExtensions"],
            [
                {
                    "path": NOTIFICATION,
                    "bundleId": "org.example.app.Notification",
                    "extensionPoint": "com.apple.usernotifications.service",
                }
            ],
        )
        self.assertIn(
            {
                "code": "ENCRYPTED_EXTENSION_REMOVED",
                "componentPath": NOTIFICATION,
                "extensionPoint": "com.apple.usernotifications.service",
            },
            report["warnings"],
        )

    def test_clear_optional_extensions_are_never_removed(self):
        report = load("analyzer").analyze_bytes(archive(extension(NOTIFICATION, encrypted=False)))
        self.assertEqual(len(report["components"]), 2)
        self.assertFalse(report.get("removedExtensions"))
        self.assertFalse(report.get("warnings"))

    def test_main_network_and_unknown_encrypted_code_still_fail(self):
        cases = [archive(binary=macho(encrypted=1))]
        for point in ("com.apple.networkextension.packet-tunnel", "unknown.extension", ""):
            cases.append(archive(extension(NOTIFICATION, point=point)))
        cases.append(archive(extension("Payload/App.app/Other/Notification.appex")))
        for raw in cases:
            with (
                self.subTest(case=cases.index(raw)),
                self.assertRaisesRegex(ValueError, "DRM_UNSUPPORTED"),
            ):
                load("analyzer").analyze_bytes(raw)

    def test_removes_private_frameworks_with_the_extension_without_touching_shared_code(self):
        path = NOTIFICATION + "/Frameworks/Private.framework"
        extras = extension(NOTIFICATION, encrypted=False)
        extras += [
            (
                path + "/Info.plist",
                plistlib.dumps(
                    {
                        "CFBundleIdentifier": "Private",
                        "CFBundleExecutable": "Private",
                        "MinimumOSVersion": "16.0",
                    }
                ),
            ),
            (path + "/Private", macho(encrypted=1, filetype=6)),
        ]
        report = load("analyzer").analyze_bytes(archive(extras))
        self.assertEqual([c["path"] for c in report["components"]], ["Payload/App.app"])
        self.assertEqual(report["removedExtensions"][0]["path"], NOTIFICATION)

    def test_signed_output_cannot_hide_encrypted_extension_or_low_minimum(self):
        raw = archive(extension(NOTIFICATION))
        with self.assertRaisesRegex(ValueError, "DRM_UNSUPPORTED"):
            load("analyzer")._analyze(raw, allow_verified_der=True)
        from test_runner_source_metadata import source_with_metadata

        with self.assertRaisesRegex(ValueError, "MIN_OS_MISMATCH"):
            load("analyzer")._analyze(
                source_with_metadata(MinimumOSVersion="15.0"), allow_verified_der=True
            )

    def test_source_low_minimum_is_raised_to_binary_requirement_with_warning(self):
        from test_runner_source_metadata import source_with_metadata

        report = load("analyzer").analyze_bytes(source_with_metadata(MinimumOSVersion="15.0"))
        self.assertEqual(report["components"][0]["minOs"], "16.0.0")
        self.assertIn(
            {
                "code": "MIN_OS_CORRECTED",
                "componentPath": "Payload/App.app",
                "originalMinOs": "15.0",
                "targetMinOs": "16.0.0",
            },
            report["warnings"],
        )

    def test_bad_bounds_inside_removed_code_still_fail(self):
        extras = extension(NOTIFICATION)
        binary = bytearray(extras[-1][1])
        struct.pack_into("<I", binary, 68, 1 << 30)
        extras[-1] = (extras[-1][0], bytes(binary))
        with self.assertRaisesRegex(ValueError, "MACHO_BOUNDS"):
            load("analyzer").analyze_bytes(archive(extras))
