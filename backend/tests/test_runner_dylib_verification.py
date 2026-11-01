from runner_modules import module_path
import hashlib, importlib.util, pathlib, struct, unittest


def load(name):
    spec = importlib.util.spec_from_file_location(name, module_path(name))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class StandaloneDirectoryTests(unittest.TestCase):
    def fixture(self):
        module = load("linux_verification")
        component = {"kind": "dylib", "bundleId": "isign.dylib.fixture", "entitlements": {}}
        text = struct.pack("<II16sQQQQIIII", 0x19, 72, b"__TEXT", 0, 4096, 0, 4096, 7, 5, 0, 0)
        raw = struct.pack("<8I", 0xFEEDFACF, 0x100000C, 0, 6, 1, 72, 0, 0) + text
        raw += b"\0" * (4096 - len(raw))
        req = module.requirement(component["bundleId"], "Synthetic")
        strings = component["bundleId"].encode() + b"\0TEAM\0"
        hashoffset = 88 + len(strings) + 64
        length = hashoffset + 32
        header = struct.pack(
            ">9I4B3I",
            0xFADE0C02,
            length,
            0x20400,
            0,
            hashoffset,
            88,
            2,
            1,
            4096,
            32,
            2,
            0,
            12,
            0,
            0,
            88 + len(component["bundleId"]) + 1,
        )
        header += struct.pack(">IQQQQ", 0, 0, 0, 4096, 0)
        directory = (
            header
            + strings
            + hashlib.sha256(req).digest()
            + b"\0" * 32
            + hashlib.sha256(raw).digest()
        )
        return module, raw, component, {0: directory, 2: req, 0x10000: b"unused-cms"}

    def test_standalone_directory_has_no_info_resource_slots_or_main_exec_flag(self):
        module, raw, component, entries = self.fixture()
        evidence = module.verify_directory(
            raw, 4096, entries, component, None, None, "TEAM", "Synthetic"
        )
        self.assertEqual(evidence["directory"], entries[0])
        for case in ("info", "main", "entitlements"):
            with self.subTest(case=case):
                changed = dict(entries)
                if case == "entitlements":
                    changed[7] = module.blob(0xFADE7172, b"bad")
                else:
                    directory = bytearray(entries[0])
                    if case == "main":
                        struct.pack_into(">Q", directory, 80, 1)
                    if case == "info":
                        hashoffset = struct.unpack_from(">I", directory, 16)[0]
                        directory[hashoffset - 32] = 1
                    changed[0] = bytes(directory)
                with self.assertRaises(ValueError):
                    module.verify_directory(
                        raw, 4096, changed, component, None, None, "TEAM", "Synthetic"
                    )
