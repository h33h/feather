"""Literal Apple entitlement dialect fixtures; never use the signing encoder."""

import json
import plistlib
import struct
import unittest

from runner_modules import load


analyzer = load("analyzer")

# application[16] { INTEGER 1, context[16] { SEQUENCE { "root", ARRAY } } }
# ARRAY contains true, 127, "é", DATA 00ff, and {"k": -1}.
MODERN = bytes.fromhex(
    "7027020101b02230200c04726f6f7430180101ff02017f0c02c3a9040200ffb00830060c016b0201ff"
)
LEGACY = bytes.fromhex("312230200c04726f6f7430180101ff02017f0c02c3a9040200ff310830060c016b0201ff")
LINUX = bytes.fromhex("b00830060c01610101ff")
# Independent native codesign --generate-entitlement-der output from a locally
# compiled fixture with deliberately different pair-length and key ordering.
APPLE_CODESIGN = bytes.fromhex(
    "704a020101b04530070c02616101010030130c056172726179300a0101ff02017f0c02c3a9"
    "301d0c066e6573746564b01330060c01610201ff30090c046c6f6e670101ff30060c017a0101ff"
)


def signature(*entries):
    """Wrap already-encoded literal blobs in a code-signature superblob."""
    table = bytearray()
    body = bytearray()
    offset = 12 + len(entries) * 8
    for slot, magic, payload in entries:
        blob = struct.pack(">II", magic, len(payload) + 8) + payload
        table.extend(struct.pack(">II", slot, offset))
        body.extend(blob)
        offset += len(blob)
    return struct.pack(">III", 0xFADE0CC0, offset, len(entries)) + table + body


def der_signature(payload):
    return signature((7, 0xFADE7172, payload))


def matching_signature(value, payload):
    return signature((5, 0xFADE7171, plistlib.dumps(value)), (7, 0xFADE7172, payload))


def tlv(tag, payload):
    """Test-only length framing for oversized/deep hostile literal values."""
    length = len(payload)
    if length < 128:
        encoded = bytes([length])
    else:
        count = (length.bit_length() + 7) // 8
        encoded = bytes([0x80 | count]) + length.to_bytes(count, "big")
    return bytes([tag]) + encoded + payload


class EntitlementsTests(unittest.TestCase):
    def test_accepts_modern_and_legacy_der_only_typed_values(self):
        expected = {"root": [True, 127, "é", {"$isignData": "AP8="}, {"k": -1}]}
        for payload in (MODERN, LEGACY):
            with self.subTest(payload=payload):
                self.assertEqual(analyzer.entitlements(der_signature(payload)), expected)

    def test_accepts_existing_linux_dictionary_encoding(self):
        self.assertEqual(analyzer.entitlements(der_signature(LINUX)), {"a": True})

    def test_legacy_set_booleans_follow_apple_single_byte_semantics(self):
        for payload, expected in (
            (bytes.fromhex("310830060c0161010100"), False),
            (bytes.fromhex("310830060c0161010101"), True),
            (bytes.fromhex("310830060c016101017f"), True),
            (bytes.fromhex("310830060c01610101ff"), True),
        ):
            with self.subTest(payload=payload):
                self.assertEqual(analyzer.entitlements(der_signature(payload)), {"a": expected})
                self.assertEqual(
                    analyzer.entitlements(matching_signature({"a": expected}, payload)),
                    {"a": expected},
                )
                for mismatch in (int(expected), not expected):
                    with self.assertRaisesRegex(ValueError, "ENTITLEMENTS_MISMATCH"):
                        analyzer.entitlements(matching_signature({"a": mismatch}, payload))

    def test_legacy_boolean_length_and_modern_boolean_canonicality_remain_strict(self):
        for payload in (
            bytes.fromhex("310730050c01610100"),
            bytes.fromhex("310930070c016101020001"),
            bytes.fromhex("b00830060c0161010101"),
            bytes.fromhex("b00830060c016101017f"),
            bytes.fromhex("700d020101b00830060c0161010101"),
            bytes.fromhex("700d020101b00830060c016101017f"),
        ):
            with (
                self.subTest(payload=payload),
                self.assertRaisesRegex(ValueError, "ENTITLEMENTS_INVALID"),
            ):
                analyzer.entitlements(der_signature(payload))

    def test_accepts_independent_apple_codesign_fixture(self):
        expected = {
            "aa": False,
            "array": [True, 127, "é"],
            "nested": {"a": -1, "long": True},
            "z": True,
        }
        self.assertEqual(
            analyzer.entitlements(matching_signature(expected, APPLE_CODESIGN)), expected
        )

    def test_der_only_ipa_analysis_produces_json_source_report(self):
        from test_runner_analyzer import archive

        signed = der_signature(MODERN)
        commands = struct.pack("<6I", 0x32, 24, 2, 0x100000, 0, 0)
        commands += struct.pack("<4I", 0x1D, 16, 72, len(signed))
        binary = struct.pack("<8I", 0xFEEDFACF, 0x100000C, 0, 2, 2, 40, 0, 0)
        report = analyzer.analyze_bytes(archive(binary=binary + commands + signed))
        expected = {"root": [True, 127, "é", {"$isignData": "AP8="}, {"k": -1}]}
        self.assertEqual(report["components"][0]["entitlements"], expected)
        self.assertIn("$isignData", json.dumps(report, allow_nan=False))

    def test_xml_and_der_must_match_before_data_normalization(self):
        value = {"root": [True, 127, "é", b"\0\xff", {"k": -1}]}
        for payload in (MODERN, LEGACY):
            self.assertEqual(
                analyzer.entitlements(matching_signature(value, payload)),
                {"root": [True, 127, "é", {"$isignData": "AP8="}, {"k": -1}]},
            )

    def test_matching_types_and_nested_values_are_required(self):
        for value in ({"a": 1}, {"a": False}, {"a": [True]}, {}, {"b": True}):
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(ValueError, "ENTITLEMENTS_MISMATCH"),
            ):
                analyzer.entitlements(matching_signature(value, LINUX))
        nested = bytes.fromhex("b00d300b0c016130060101ff020101")
        with self.assertRaisesRegex(ValueError, "ENTITLEMENTS_MISMATCH"):
            analyzer.entitlements(matching_signature({"a": [1, True]}, nested))
        with self.assertRaisesRegex(ValueError, "ENTITLEMENTS_MISMATCH"):
            analyzer.entitlements(
                matching_signature(
                    {"root": [True, 127, "é", {"$isignData": "AP8="}, {"k": -1}]}, MODERN
                )
            )

    def test_der_validation_and_consistency_are_always_required(self):
        for payload in (b"broken", LINUX):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                analyzer.entitlements(matching_signature({"a": False}, payload))

    def test_integer_values_survive_json_without_rounding(self):
        for encoded, expected in (
            ("02071fffffffffffff", 9007199254740991),
            ("0207e0000000000001", -9007199254740991),
            ("02020080", 128),
            ("0202ff7f", -129),
            ("020100", 0),
        ):
            payload = tlv(0xB0, tlv(0x30, b"\x0c\x01a" + bytes.fromhex(encoded)))
            with self.subTest(expected=expected):
                self.assertEqual(analyzer.entitlements(der_signature(payload)), {"a": expected})
        for encoded in ("020720000000000000", "0207e0000000000000"):
            payload = tlv(0xB0, tlv(0x30, b"\x0c\x01a" + bytes.fromhex(encoded)))
            with (
                self.subTest(encoded=encoded),
                self.assertRaisesRegex(ValueError, "ENTITLEMENTS_VALUE_UNSUPPORTED"),
            ):
                analyzer.entitlements(der_signature(payload))
        for value in (9007199254740992, -9007199254740992):
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(ValueError, "ENTITLEMENTS_VALUE_UNSUPPORTED"),
            ):
                analyzer.entitlements(signature((5, 0xFADE7171, plistlib.dumps({"a": value}))))

    def test_accepts_canonical_long_der_lengths_and_binary_plists(self):
        payload = tlv(0xB0, tlv(0x30, b"\x0c\x01a" + b"\x0c\x81\x80" + b"x" * 128))
        self.assertEqual(analyzer.entitlements(der_signature(payload)), {"a": "x" * 128})
        binary = plistlib.dumps({"a": True}, fmt=plistlib.FMT_BINARY)
        self.assertEqual(analyzer.entitlements(signature((5, 0xFADE7171, binary))), {"a": True})

    def test_empty_and_xml_only_entitlements(self):
        self.assertEqual(analyzer.entitlements(signature()), {})
        self.assertEqual(analyzer.entitlements(der_signature(b"\x31\x00")), {})
        self.assertEqual(analyzer.entitlements(der_signature(bytes.fromhex("7005020101b000"))), {})
        self.assertEqual(
            analyzer.entitlements(signature((5, 0xFADE7171, plistlib.dumps({"a": True})))),
            {"a": True},
        )

    def test_legacy_set_order_is_unrestricted_but_modern_keys_remain_sorted(self):
        # Apple's legacy encoder sorts DER pairs, but its decoder does not.
        legacy = bytes.fromhex("311130060c017a0101ff30070c026161010100")
        legacy_reversed = bytes.fromhex("311130070c02616101010030060c017a0101ff")
        modern = bytes.fromhex("b01130070c02616101010030060c017a0101ff")
        self.assertEqual(analyzer.entitlements(der_signature(legacy)), {"z": True, "aa": False})
        self.assertEqual(
            analyzer.entitlements(der_signature(legacy_reversed)), {"aa": False, "z": True}
        )
        self.assertEqual(analyzer.entitlements(der_signature(modern)), {"aa": False, "z": True})
        with self.assertRaises(ValueError):
            analyzer.entitlements(
                der_signature(bytes.fromhex("b01130060c017a0101ff30070c026161010100"))
            )

    def test_nested_unsorted_legacy_sets_preserve_typed_xml_consistency(self):
        payload = bytes.fromhex(
            "312030150c017a311030060c016201010130060c016101010030070c026161010100"
        )
        expected = {"z": {"b": True, "a": False}, "aa": False}
        self.assertEqual(analyzer.entitlements(der_signature(payload)), expected)
        self.assertEqual(analyzer.entitlements(matching_signature(expected, payload)), expected)
        with self.assertRaisesRegex(ValueError, "ENTITLEMENTS_MISMATCH"):
            analyzer.entitlements(
                matching_signature({"z": {"b": 1, "a": False}, "aa": False}, payload)
            )

    def test_legacy_integer_decoding_accepts_apple_sign_padding_and_empty_zero(self):
        for encoded, expected in (
            ("0200", 0),
            ("0203000001", 1),
            ("0202ffff", -1),
            ("0203ffff7f", -129),
            ("0208ffffffffffffffff", -1),
        ):
            payload = tlv(0x31, tlv(0x30, b"\x0c\x01a" + bytes.fromhex(encoded)))
            with self.subTest(encoded=encoded):
                self.assertEqual(
                    analyzer.entitlements(matching_signature({"a": expected}, payload)),
                    {"a": expected},
                )
                with self.assertRaisesRegex(ValueError, "ENTITLEMENTS_INVALID"):
                    analyzer.entitlements(der_signature(bytes([0xB0]) + payload[1:]))
        for encoded in ("020720000000000000", "02080020000000000000"):
            payload = tlv(0x31, tlv(0x30, b"\x0c\x01a" + bytes.fromhex(encoded)))
            with (
                self.subTest(encoded=encoded),
                self.assertRaisesRegex(ValueError, "ENTITLEMENTS_VALUE_UNSUPPORTED"),
            ):
                analyzer.entitlements(der_signature(payload))
        too_wide = tlv(0x31, tlv(0x30, b"\x0c\x01a\x02\x09" + b"\xff" * 9))
        with self.assertRaisesRegex(ValueError, "ENTITLEMENTS_INVALID"):
            analyzer.entitlements(der_signature(too_wide))

    def test_legacy_numeric_string_uses_validated_utf8_for_keys_and_values(self):
        payload = bytes.fromhex("310930071201611202c3a9")
        self.assertEqual(analyzer.entitlements(matching_signature({"a": "é"}, payload)), {"a": "é"})
        for invalid in (
            bytes.fromhex("310930070c01611202c0af"),
            bytes.fromhex("b00930070c01611202c3a9"),
            bytes.fromhex("700e020101b00930070c01611202c3a9"),
            bytes.fromhex("311030060c01610101003006120161010101"),
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                analyzer.entitlements(der_signature(invalid))

    def test_rejects_duplicate_keys_and_invalid_dictionary_pairs(self):
        for payload in (
            bytes.fromhex("b01030060c01610101ff30060c01610101ff"),
            bytes.fromhex("311030060c01610101ff30060c01610101ff"),
            bytes.fromhex("b00530030c0161"),  # missing value
            bytes.fromhex("b00b30090c01610101ff010100"),  # extra value
            bytes.fromhex("b00830060201010101ff"),  # integer key
            bytes.fromhex("b00630040c000500"),  # unsupported null value
        ):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                analyzer.entitlements(der_signature(payload))

    def test_rejects_noncanonical_primitive_encodings(self):
        for value in (
            b"\x01\x00",
            b"\x01\x01\x01",
            b"\x01\x02\0\xff",
            b"\x02\x00",
            b"\x02\x02\0\x01",
            b"\x02\x02\xff\xff",
            b"\x02\x09\0\x80\0\0\0\0\0\0\0",  # exceeds signed int64
            b"\x0c\x02\xc0\xaf",  # invalid UTF-8
            b"\x04\x81\x01x",  # nonminimal length
            b"\x24\x00",
            b"\x05\x00",
            b"\x13\x01a",
            b"\x1f\x01\0",
        ):
            payload = tlv(0xB0, tlv(0x30, b"\x0c\x01a" + value))
            with self.subTest(value=value), self.assertRaises(ValueError):
                analyzer.entitlements(der_signature(payload))

    def test_rejects_truncation_indefinite_or_nonminimal_lengths_and_trailing_data(self):
        for payload in (
            b"",
            b"\xb0",
            b"\xb0\x80\0\0",
            b"\xb0\x81\0",
            b"\xb0\x82\0\x80" + b"\0" * 128,
            b"\xb0\x85\x01\0\0\0\0",
            LINUX[:-1],
            LINUX + b"\0",
            bytes.fromhex("7008020101b0000101ff"),  # envelope extra member
            bytes.fromhex("7005020102b000"),  # unknown version
            bytes.fromhex("70053100020101"),  # wrong envelope members
            bytes.fromhex("70050201013100"),  # wrong dictionary dialect
            b"\x30\x00",
            b"\x01\x01\xff",
        ):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                analyzer.entitlements(der_signature(payload))
        for end in range(len(MODERN)):
            with self.subTest(end=end), self.assertRaises(ValueError):
                analyzer.entitlements(der_signature(MODERN[:end]))

    def test_rejects_wrong_slot_magic_duplicate_slots_and_overlapping_blobs(self):
        for data in (
            signature((7, 0xFADE7171, LINUX)),
            signature((5, 0xFADE7172, plistlib.dumps({}))),
            signature((7, 0xFADE7172, LINUX), (7, 0xFADE7172, LINUX)),
        ):
            with self.subTest(data=data), self.assertRaises(ValueError):
                analyzer.entitlements(data)
        data = bytearray(signature((7, 0xFADE7172, LINUX), (9, 0xFADE7172, LINUX)))
        struct.pack_into(">I", data, 24, 28)  # both slots point to the same blob
        with self.assertRaises(ValueError):
            analyzer.entitlements(data)

    def test_rejects_xml_duplicate_keys_unsupported_types_and_excessive_depth(self):
        duplicate = (
            b'<plist version="1.0"><dict><key>a</key><true/><key>a</key><false/></dict></plist>'
        )
        for xml in (duplicate, plistlib.dumps({"a": 1.5}), plistlib.dumps(["a"])):
            with self.subTest(xml=xml), self.assertRaises(ValueError):
                analyzer.entitlements(signature((5, 0xFADE7171, xml)))
        nested = b"<array>" * 70 + b"<true/>" + b"</array>" * 70
        xml = b'<plist version="1.0"><dict><key>a</key>' + nested + b"</dict></plist>"
        with self.assertRaises(ValueError):
            analyzer.entitlements(signature((5, 0xFADE7171, xml)))

    def test_rejects_ignored_xml_elements_text_entities_and_malformed_data(self):
        for xml in (
            b"<plist><dict><unknown/><key>a</key><true/></dict></plist>",
            b"<plist><dict>ignored<key>a</key><true/></dict></plist>",
            b"<plist><dict><key>a</key><true>ignored</true></dict></plist>",
            b"<plist><dict><key>a</key><data>!not base64!</data></dict></plist>",
            b'<plist><dict><key>a</key><string bad="x">x</string></dict></plist>',
            b'<!DOCTYPE plist [<!ENTITY hidden "true">]><plist><dict><key>a</key><string>&hidden;</string></dict></plist>',
            b"<plist><dict/></plist><dict/>",
        ):
            with self.subTest(xml=xml), self.assertRaises(ValueError):
                analyzer.entitlements(signature((5, 0xFADE7171, xml)))

    def test_source_signature_uses_declared_blob_length_with_unused_allocation_tail(self):
        data = der_signature(LINUX)
        for tail in (b"\0" * 8, b"previous-signature-bytes" + b"\0" * 512):
            with self.subTest(tail=tail[:24]):
                self.assertEqual(analyzer.entitlements(data + tail), {"a": True})
                self.assertEqual(
                    analyzer.entitlements(matching_signature({"a": True}, LINUX) + tail),
                    {"a": True},
                )
                with self.assertRaisesRegex(ValueError, "ENTITLEMENTS_MISMATCH"):
                    analyzer.entitlements(matching_signature({"a": 1}, LINUX) + tail)

    def test_source_allocation_tail_cannot_extend_indexed_blob_bounds(self):
        original = der_signature(LINUX)
        tail = struct.pack(">II", 0xFADE7172, len(LINUX) + 8) + LINUX
        outside = bytearray(original + tail)
        struct.pack_into(">I", outside, 16, len(original))
        overlong = bytearray(original + tail)
        struct.pack_into(">I", overlong, 24, len(LINUX) + 9)
        for data in (outside, overlong):
            with self.subTest(data=data), self.assertRaisesRegex(ValueError, "SIGNATURE_BOUNDS"):
                analyzer.entitlements(data)
        with self.assertRaisesRegex(ValueError, "ENTITLEMENTS_INVALID"):
            analyzer.entitlements(der_signature(LINUX + b"\0") + tail)

    def test_independent_output_validator_still_requires_zero_allocation_tail(self):
        output = load("linux_verification")
        data = signature((0, 0xFADE0C02, b""), (2, 0xFADE0C01, b""), (0x10000, 0xFADE0B01, b""))

        def macho(allocation):
            header = struct.pack("<8I", 0xFEEDFACF, 0x100000C, 0, 2, 1, 16, 0, 0)
            return header + struct.pack("<4I", 0x1D, 16, 48, len(allocation)) + allocation

        zero_tail = data + b"\0" * 64
        self.assertEqual(set(output.macho_signature(macho(zero_tail))[2]), {0, 2, 0x10000})
        nonzero_tail = data + b"previous-signature-bytes" + b"\0" * 64
        self.assertEqual(analyzer.entitlements(nonzero_tail), {})
        with self.assertRaisesRegex(ValueError, "SIGNATURE_CONTAINER_INVALID"):
            output.macho_signature(macho(nonzero_tail))

    def test_rejects_excessive_der_size_depth_and_node_count(self):
        deep = b"\x01\x01\xff"
        for _ in range(70):
            deep = tlv(0x30, deep)
        deep = tlv(0xB0, tlv(0x30, b"\x0c\x01a" + deep))
        many = tlv(0xB0, tlv(0x30, b"\x0c\x01a" + tlv(0x30, b"\x01\x01\xff" * 65536)))
        huge = tlv(0xB0, tlv(0x30, b"\x0c\x01a" + tlv(0x04, b"x" * (4 << 20))))
        for payload in (deep, many, huge):
            with self.subTest(length=len(payload)), self.assertRaises(ValueError):
                analyzer.entitlements(der_signature(payload))


if __name__ == "__main__":
    unittest.main()
