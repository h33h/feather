"""Apple resource exclusions must agree with the sealed file inventory."""

import copy, hashlib, pathlib, plistlib, tempfile, unittest
from runner_modules import load


class ResourceEnvelopeTests(unittest.TestCase):
    def fixture(self, root):
        files = {
            "Info.plist": b"synthetic info",
            "PkgInfo": b"APPL????",
            "resource.txt": b"synthetic resource",
            "en.lproj/locversion.plist": b"localization metadata",
            "Assets.bundle/PkgInfo": b"BNDL????",
        }
        for name, raw in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        (root / "Fixture").write_bytes(b"synthetic executable")
        rules = {
            "^.*": True,
            r"^.*\.lproj/": {"optional": True, "weight": 1000.0},
            r"^Base\.lproj/": {"weight": 1010.0},
            "^version.plist$": True,
        }
        rules2 = {
            "^.*": True,
            r".*\.dSYM($|/)": {"weight": 11.0},
            r"^(.*/)?\.DS_Store$": {"omit": True, "weight": 2000.0},
            r"^.*\.lproj/": {"optional": True, "weight": 1000.0},
            r"^Base\.lproj/": {"weight": 1010.0},
            r"^Info\.plist$": {"omit": True, "weight": 20.0},
            "^PkgInfo$": {"omit": True, "weight": 20.0},
            r"^embedded\.provisionprofile$": {"weight": 20.0},
            r"^version\.plist$": {"weight": 20.0},
        }
        document = {"files": {}, "files2": {}, "rules": rules, "rules2": rules2}
        for name, raw in files.items():
            sha1, sha256 = hashlib.sha1(raw).digest(), hashlib.sha256(raw).digest()
            document["files"][name] = sha1
            if name not in ("Info.plist", "PkgInfo"):
                document["files2"][name] = {"hash": sha1, "hash2": sha256}
        return document

    def verify(self, root, document):
        verifier = object.__new__(load("linux_verification").LinuxVerifier)
        verifier.verify_resources(root, {"CFBundleExecutable": "Fixture"}, plistlib.dumps(document))

    def test_known_root_exclusions_do_not_exclude_nested_pkginfo_or_localization(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            document = self.fixture(root)
            self.verify(root, document)
            for name in ("PkgInfo", "Assets.bundle/PkgInfo", "en.lproj/locversion.plist"):
                with self.subTest(name=name):
                    path = root / name
                    original = path.read_bytes()
                    path.write_bytes(b"tampered")
                    with self.assertRaises(ValueError):
                        self.verify(root, document)
                    path.write_bytes(original)

    def test_rejects_pkginfo_sealed_in_files2_even_with_correct_hash(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            document = self.fixture(root)
            raw = (root / "PkgInfo").read_bytes()
            document["files2"]["PkgInfo"] = {
                "hash": hashlib.sha1(raw).digest(),
                "hash2": hashlib.sha256(raw).digest(),
            }
            with self.assertRaises(ValueError):
                self.verify(root, document)

    def test_rejects_rules_that_allow_unchecked_resources(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            document = self.fixture(root)
            (root / "PkgInfo").unlink()
            del document["files"]["PkgInfo"]
            for key in ("rules", "rules2"):
                with self.subTest(key=key):
                    changed = copy.deepcopy(document)
                    changed[key]["^resource.txt$"] = {"omit": True, "weight": 3000.0}
                    # All hashes still match: rules must be checked independently.
                    with self.assertRaises(ValueError):
                        self.verify(root, changed)

    def test_rejects_missing_legacy_seal_for_resource(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            document = self.fixture(root)
            (root / "PkgInfo").unlink()
            del document["files"]["PkgInfo"]
            del document["files"]["resource.txt"]
            with self.assertRaises(ValueError):
                self.verify(root, document)
