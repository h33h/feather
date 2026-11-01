import copy
import unittest
from runner_modules import load


class CapabilityCeilingTests(unittest.TestCase):
    def setUp(self):
        self.verification = load("verification")
        self.ceiling = {
            "application-identifier": "PREFIX.com.example.*",
            "com.apple.developer.team-identifier": "TEAM",
            "get-task-allow": False,
            "keychain-access-groups": ["PREFIX.*", "group.shared"],
            "aps-environment": "production",
            "com.apple.developer.icloud-container-identifiers": ["iCloud.com.example.*"],
            "com.example.nested": {"enabled": True, "versions": [1, 2]},
        }

    def test_profile_ceiling_retains_exact_signed_authority_without_emitting_it(self):
        actual = self.verification.profile_entitlement_ceiling(
            self.ceiling, "PREFIX", "com.example.app", "TEAM"
        )
        self.assertEqual(actual, self.ceiling)
        actual["keychain-access-groups"].append("foreign")
        self.assertEqual(self.ceiling["keychain-access-groups"], ["PREFIX.*", "group.shared"])

    def test_authorization_is_typed_recursive_and_only_known_suffix_wildcards(self):
        from guest.entitlement_policy import permits

        cases = [
            ("aps-environment", "production", "production", True),
            ("com.example.claim", True, 1, False),
            ("com.example.claim", 1, True, False),
            ("com.example.claim", ["a"], ["a", "b"], True),
            ("com.example.claim", ["a", "foreign"], ["a"], False),
            ("com.example.claim", {"x": True}, {"x": True, "y": False}, True),
            ("com.example.claim", "anything", "*", False),
            (
                "com.apple.developer.icloud-container-identifiers",
                ["iCloud.com.example.documents"],
                ["iCloud.com.example.*"],
                True,
            ),
            (
                "com.apple.developer.icloud-container-identifiers",
                ["iCloud.com.example.documents.more"],
                ["iCloud.com.example.*.more"],
                False,
            ),
        ]
        for key, claim, ceiling, expected in cases:
            with self.subTest(key=key, claim=claim, ceiling=ceiling):
                self.assertIs(permits(key, claim, ceiling), expected)

    def test_unsafe_signed_claims_rejected(self):
        for value in (None, 1.5, 9007199254740992, {"nested": None}, "\0", {"constructor": True}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.verification.profile_entitlement_ceiling(
                    dict(self.ceiling, **{"com.example.claim": value}),
                    "PREFIX",
                    "com.example.app",
                    "TEAM",
                )

    def test_der_integer_encoding_and_unsafe_value_rejection(self):
        verifier = load("linux_verification")
        for value, encoded in [
            (0, b"\x02\x01\x00"),
            (127, b"\x02\x01\x7f"),
            (128, b"\x02\x02\x00\x80"),
            (-1, b"\x02\x01\xff"),
            (-128, b"\x02\x01\x80"),
            (-129, b"\x02\x02\xff\x7f"),
        ]:
            self.assertEqual(verifier.entitlement_der(value), encoded)
        for value in (None, 1.5, 9007199254740992, "\0", {"constructor": True}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                verifier.entitlement_der(value)

    def test_reserved_data_marker_is_never_an_output_capability(self):
        from guest.entitlement_policy import permits, safe_value

        marker = {"$isignData": "AA=="}
        self.assertTrue(safe_value(marker, allow_data=True))
        self.assertFalse(safe_value(marker))
        self.assertFalse(permits("com.example.claim", marker, marker))
        ceiling = dict(self.ceiling, **{"com.example.data": b"\0"})
        self.assertEqual(
            self.verification.profile_entitlement_ceiling(
                ceiling, "PREFIX", "com.example.app", "TEAM"
            )["com.example.data"],
            marker,
        )

    def test_entitlement_xml_preserves_integer_type(self):
        from guest.entitlement_policy import exact

        self.assertFalse(exact({"claim": 1}, {"claim": True}))
        self.assertFalse(exact({"claim": [False]}, {"claim": [0]}))

    def test_regenerates_source_private_keychain_even_when_wildcard_authorizes_old_id(self):
        from guest.entitlement_policy import normalized_entitlements

        actual = normalized_entitlements(
            {
                "application-identifier": "PREFIX.old.app",
                "keychain-access-groups": ["PREFIX.old.app", "group.shared"],
            },
            {
                "prefix": "PREFIX",
                "bundleId": "com.example.app",
                "teamId": "TEAM",
                "entitlements": self.ceiling,
            },
        )
        self.assertEqual(
            actual["keychain-access-groups"], ["PREFIX.com.example.app", "group.shared"]
        )

    def test_retains_authorized_entries_from_partially_permitted_capability_lists(self):
        from guest.entitlement_policy import normalized_entitlements

        actual = normalized_entitlements(
            {
                "com.apple.security.application-groups": ["group.shared", "group.foreign"],
                "com.apple.developer.icloud-services": ["CloudDocuments", "CloudKit"],
                "com.apple.developer.associated-domains": [
                    "applinks:example.com",
                    "webcredentials:other.com",
                ],
                "com.example.none": ["foreign"],
                "com.example.typed": [True, 1],
            },
            {
                "prefix": "PREFIX",
                "bundleId": "com.example.app",
                "teamId": "TEAM",
                "entitlements": dict(
                    self.ceiling,
                    **{
                        "com.apple.security.application-groups": ["group.shared"],
                        "com.apple.developer.icloud-services": ["CloudDocuments"],
                        "com.apple.developer.associated-domains": ["applinks:*"],
                        "com.example.none": ["allowed"],
                        "com.example.typed": [1],
                    },
                ),
            },
        )
        self.assertEqual(
            actual,
            {
                "application-identifier": "PREFIX.com.example.app",
                "com.apple.developer.team-identifier": "TEAM",
                "get-task-allow": False,
                "keychain-access-groups": ["PREFIX.com.example.app"],
                "com.apple.security.application-groups": ["group.shared"],
                "com.apple.developer.icloud-services": ["CloudDocuments"],
                "com.apple.developer.associated-domains": ["applinks:example.com"],
                "com.example.typed": [1],
            },
        )

    def test_associated_domain_literal_wildcard_requires_authorized_array_ceiling(self):
        from guest.entitlement_policy import permits

        requested = ["applinks:*.example.com"]
        for permission, expected in [
            (["*"], True),
            (["applinks:*"], True),
            (["applinks:*.example.com"], True),
            (["webcredentials:*"], False),
            (["applinks:other.*"], False),
            (["applinks:*example.com"], False),
            ("*", False),
        ]:
            with self.subTest(permission=permission):
                self.assertIs(
                    permits("com.apple.developer.associated-domains", requested, permission),
                    expected,
                )
        self.assertFalse(permits("application-identifier", "PREFIX.*.app", "PREFIX.*"))
        self.assertFalse(permits("keychain-access-groups", ["PREFIX.*.group"], ["PREFIX.*"]))
