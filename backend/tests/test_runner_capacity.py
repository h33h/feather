from runner_modules import module_path
import hashlib, importlib.util, io, pathlib, plistlib, tempfile, tracemalloc, unittest, zipfile
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, module_path(name))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CapacityTests(unittest.TestCase):
    def test_linux_full_source_and_unpacked_metadata_boundaries(self):
        m = load("linux_runtime")
        guest = m.LinuxGuestRuntime.__new__(m.LinuxGuestRuntime)
        # Boundary metadata only; no claim of executing a 1 GiB successful sign.
        for source_size, unpacked, allowed in [
            (1 << 30, 4 << 30, True),
            ((1 << 30) + 1, 4 << 30, False),
            (1 << 30, (4 << 30) + 1, False),
        ]:
            with self.subTest(source_size=source_size, unpacked=unpacked):
                archive = unittest.mock.MagicMock()
                archive.__enter__.return_value = archive
                archive.infolist.return_value = [type("Entry", (), {"file_size": unpacked})()]
                with (
                    patch.object(m.zipfile, "ZipFile", return_value=archive),
                    patch.object(
                        m.pathlib.Path,
                        "stat",
                        return_value=type("Size", (), {"st_size": source_size})(),
                    ),
                ):
                    if allowed:
                        guest.validate_source_format(
                            pathlib.Path("/synthetic/source.ipa"), {"components": []}
                        )
                    else:
                        with self.assertRaisesRegex(
                            ValueError, "LINUX_SOURCE_CAPACITY_UNSUPPORTED"
                        ):
                            guest.validate_source_format(
                                pathlib.Path("/synthetic/source.ipa"), {"components": []}
                            )

    def test_signed_entry_allowance_does_not_relax_source_limit(self):
        m = load("analyzer")
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            for index in range(m.MAX_ENTRIES + 2):
                archive.writestr("resource-" + str(index), b"")
        stream.seek(0)
        with self.assertRaisesRegex(ValueError, "ARCHIVE_METADATA_LIMIT"):
            m.validate_zip_directory(stream)
        stream.seek(0)
        m.validate_zip_directory(stream, m.MAX_ENTRIES + 2)
