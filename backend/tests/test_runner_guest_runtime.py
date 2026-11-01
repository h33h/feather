from runner_modules import module_path
import importlib.util, pathlib, tempfile, unittest, hashlib
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]


class RuntimeTests(unittest.TestCase):
    def test_failed_execute_clears_guest_password_and_material(self):
        spec = importlib.util.spec_from_file_location("guest_runtime", module_path("linux_runtime"))
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)

        class Verifier:
            verify_component = verify_archive = verify_materials = lambda *a, **kw: True

        with tempfile.TemporaryDirectory() as td:
            signer = pathlib.Path(td) / "zsign"
            signer.write_bytes(b"synthetic signer")
            runtime = m.LinuxGuestRuntime(
                td,
                None,
                Verifier(),
                openssl_path="/configured/openssl",
                validate_vm=lambda *a: False,
                proof_key=b"K" * 32,
                key_id="synthetic",
                zsign_path=str(signer),
                zsign_digest=hashlib.sha256(signer.read_bytes()).hexdigest(),
            )
            directory = pathlib.Path(td) / "materials"
            directory.mkdir()
            (directory / "key.p12").write_bytes(b"SYNTHETIC")
            runtime.materials.passwords["materials/key.p12"] = {
                "password": "synthetic",
                "binding": {},
            }
            with patch.object(
                m.driver,
                "execute_linux_task",
                side_effect=ValueError("SYNTHETIC_VERIFICATION_FAILURE"),
            ):
                with self.assertRaisesRegex(ValueError, "SYNTHETIC_VERIFICATION_FAILURE"):
                    runtime.execute({}, {}, {})
            self.assertFalse(directory.exists())
            self.assertEqual(runtime.materials.passwords, {})


if __name__ == "__main__":
    unittest.main()
