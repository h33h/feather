import plistlib
import struct
import unittest
from runner_modules import load


class SourceNormalizationTests(unittest.TestCase):
    def test_analyzer_reports_capabilities_for_an_approved_stripping_plan(self):
        analyzer = load("analyzer")
        ent = {
            "application-identifier": "OLD.com.example.app",
            "keychain-access-groups": ["OLD.com.example.app", "OLD.shared"],
            "aps-environment": "production",
        }
        xml = plistlib.dumps(ent)
        blob = struct.pack(">II", 0xFADE7171, 8 + len(xml)) + xml
        signed = (
            struct.pack(">III", 0xFADE0CC0, 20 + len(blob), 1) + struct.pack(">II", 5, 20) + blob
        )
        self.assertEqual(analyzer.entitlements(signed), ent)

    def test_profile_ceiling_keeps_signed_capabilities_separate_from_output(self):
        verifier = load("verification")
        emitted = verifier.profile_entitlement_ceiling(
            {
                "application-identifier": "TEAM123.*",
                "com.apple.developer.team-identifier": "TEAM123",
                "get-task-allow": False,
                "aps-environment": "production",
            },
            "TEAM123",
            "com.example.app",
            "TEAM123",
        )
        self.assertEqual(
            emitted,
            {
                "application-identifier": "TEAM123.*",
                "com.apple.developer.team-identifier": "TEAM123",
                "get-task-allow": False,
                "aps-environment": "production",
            },
        )
