import struct
import unittest
from runner_modules import load
from test_runner_analyzer import archive, macho


def universal(slices, *, wide=False, endian=">"):
    width = 32 if wide else 20
    offset = (8 + width * len(slices) + 7) // 8 * 8
    table = bytearray(struct.pack(endian + "II", 0xCAFEBABF if wide else 0xCAFEBABE, len(slices)))
    payload = bytearray()
    for cpu, subtype, raw in slices:
        if wide:
            table += struct.pack(endian + "IIQQII", cpu, subtype, offset, len(raw), 3, 0)
        else:
            table += struct.pack(endian + "IIIII", cpu, subtype, offset, len(raw), 3)
        payload += raw
        padding = (-len(raw)) % 8
        payload += b"\0" * padding
        offset += len(raw) + padding
    table += b"\0" * ((-len(table)) % 8)
    return bytes(table + payload)


class UniversalMachOTests(unittest.TestCase):
    def test_chooses_arm64_from_mixed_architectures_for_every_fat_layout(self):
        analyzer = load("analyzer")
        thin = macho()
        for wide in (False, True):
            for endian in (">", "<"):
                with self.subTest(wide=wide, endian=endian):
                    raw = universal(
                        [(12, 9, b"legacy" * 8), (0x100000C, 0, thin)], wide=wide, endian=endian
                    )
                    self.assertEqual(analyzer.macho(raw), analyzer.macho(thin))
                    result = analyzer.analyze_bytes(archive(binary=raw))
                    self.assertEqual(result["components"][0]["architectures"], ["arm64"])

    def test_rejects_overlapping_or_misidentified_selected_slices(self):
        analyzer = load("analyzer")
        raw = bytearray(universal([(0x100000C, 0, macho())]))
        struct.pack_into(">I", raw, 16, 8)
        with self.assertRaisesRegex(ValueError, "FAT_BOUNDS"):
            analyzer.macho(bytes(raw))
        raw = universal([(0x100000C, 0, macho(cpu=7))])
        with self.assertRaisesRegex(ValueError, "FAT_ARCHITECTURE_MISMATCH"):
            analyzer.macho(raw)

    def test_rejects_ambiguous_architectures_and_archives_without_arm64(self):
        analyzer = load("analyzer")
        for raw, code in (
            (
                universal([(0x100000C, 0, macho()), (0x100000C, 0, macho())]),
                "FAT_ARCHITECTURE_DUPLICATE",
            ),
            (universal([(12, 9, b"legacy" * 8)]), "ARCHITECTURE_UNSUPPORTED"),
        ):
            with self.subTest(code=code), self.assertRaisesRegex(ValueError, code):
                analyzer.macho(raw)


if __name__ == "__main__":
    unittest.main()
