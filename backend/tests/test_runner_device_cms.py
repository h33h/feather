from runner_modules import module_path
import importlib.util, pathlib, tempfile, unittest, plistlib, hashlib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load():
    s = importlib.util.spec_from_file_location("device_cms", module_path("device_cms"))
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


class DeviceCMSTests(unittest.TestCase):
    def setUp(self):
        self.module = load()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name).resolve()
        self.ca = self.root / "device-ca.pem"
        self.ca.write_bytes(b"SYNTHETIC")
        self.calls = []
        self.payload = {
            "CHALLENGE": "challenge",
            "UDID": "00008110-0012345678901234",
            "PRODUCT": "iPhone15,2",
            "VERSION": "18.0",
        }

    def command(self, args, **kwargs):
        self.calls.append(args)
        if args[1] == "cms":
            pathlib.Path(args[args.index("-signer") + 1]).write_bytes(
                b"-----BEGIN CERTIFICATE-----\nQQ==\n-----END CERTIFICATE-----\n"
            )
            return {"stdout": plistlib.dumps(self.payload), "stderr": b""}
        if args[1] == "x509":
            return {"stdout": b"SYNTHETIC-DEVICE-CERT", "stderr": b""}
        raise AssertionError(args)

    def verifier(self, policy=None):
        return self.module.DeviceCMSVerifier(
            self.root,
            self.command,
            openssl_path="/configured/openssl",
            device_ca_file=self.ca,
            device_leaf_policy=policy or (lambda der, udid: der == b"SYNTHETIC-DEVICE-CERT"),
        )

    def test_verified_cms_issuer_leaf_and_exact_payload(self):
        result = self.verifier().verify(b"SYNTHETIC-CMS")
        self.assertEqual(result["challenge"], "challenge")
        self.assertTrue(result["signatureVerified"])
        self.assertTrue(result["issuerTrusted"])
        self.assertEqual(
            result["deviceCertificate"], hashlib.sha256(b"SYNTHETIC-DEVICE-CERT").hexdigest()
        )
        self.assertIn("-verify_retcode", self.calls[0])
        self.assertNotIn("-noverify", self.calls[0])

    def test_missing_policy_and_untrusted_leaf_fail_closed(self):
        with self.assertRaises(ValueError):
            self.module.DeviceCMSVerifier(
                self.root,
                self.command,
                openssl_path="/configured/openssl",
                device_ca_file=self.ca,
                device_leaf_policy=None,
            )
        with self.assertRaises(ValueError):
            self.verifier(lambda *args: False).verify(b"SYNTHETIC-CMS")

    def test_payload_extra_fields_bad_udid_and_input_limit(self):
        self.payload["OTHER"] = "extra"
        with self.assertRaises(ValueError):
            self.verifier().verify(b"SYNTHETIC-CMS")
        self.payload.pop("OTHER")
        self.payload["UDID"] = "bad"
        with self.assertRaises(ValueError):
            self.verifier().verify(b"SYNTHETIC-CMS")
        with self.assertRaises(ValueError):
            self.verifier().verify(b"x" * 65537)


class OpenSSLDeviceCMSTests(unittest.TestCase):
    """Real cryptography with a newly generated SYNTHETIC test CA; no Apple trust claim."""

    def setUp(self):
        import subprocess, shutil

        self.openssl = (
            "/opt/homebrew/opt/openssl@3/bin/openssl"
            if pathlib.Path("/opt/homebrew/opt/openssl@3/bin/openssl").is_file()
            else shutil.which("openssl")
        )
        if not self.openssl:
            self.skipTest("OpenSSL unavailable")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name).resolve()
        self.module = load()
        self.udid = "00008110-0012345678901234"

        def run(args, *, cwd, timeout, input_bytes=None):
            result = subprocess.run(
                args,
                cwd=cwd,
                timeout=timeout,
                input=input_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if result.returncode:
                raise ValueError("SYNTHETIC_OPENSSL_VERIFICATION_FAILED")
            return {"stdout": result.stdout, "stderr": result.stderr}

        self.run = run
        self.cmd(
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "ca.key",
            "-out",
            "ca.pem",
            "-days",
            "1",
            "-subj",
            "/CN=SYNTHETIC Device Test CA",
        )
        self.cmd(
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "device.key",
            "-out",
            "device.csr",
            "-subj",
            "/serialNumber=" + self.udid,
        )
        self.cmd(
            "x509",
            "-req",
            "-in",
            "device.csr",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-out",
            "device.pem",
            "-days",
            "1",
        )
        self.policy = self.module.DeviceLeafPolicy(
            run,
            self.root,
            self.openssl,
            issuer_dn="CN=SYNTHETIC Device Test CA",
            udid_subject_attribute="serialNumber",
        )
        self.verifier = self.module.DeviceCMSVerifier(
            self.root,
            run,
            openssl_path=self.openssl,
            device_ca_file=self.root / "ca.pem",
            device_leaf_policy=self.policy,
            policy_id="synthetic-only",
        )

    def cmd(self, *args):
        return self.run([self.openssl, *args], cwd=str(self.root), timeout=30)

    def cms(self, udid=None, challenge=None):
        (self.root / "payload.plist").write_bytes(
            plistlib.dumps({"CHALLENGE": challenge or "a" * 43, "UDID": udid or self.udid})
        )
        self.cmd(
            "cms",
            "-sign",
            "-binary",
            "-nodetach",
            "-in",
            "payload.plist",
            "-signer",
            "device.pem",
            "-inkey",
            "device.key",
            "-outform",
            "DER",
            "-out",
            "device.cms",
        )
        return (self.root / "device.cms").read_bytes()

    def test_minimal_payload_has_real_signature_chain_and_udid_bound_leaf(self):
        result = self.verifier.verify(self.cms())
        self.assertEqual(result["udid"], self.udid)
        self.assertEqual(result["challenge"], "a" * 43)
        self.assertNotIn("version", result)
        self.assertNotIn("product", result)

    def test_tamper_leaf_mismatch_and_untrusted_chain_fail(self):
        with self.assertRaises(ValueError):
            self.verifier.verify(self.cms("00008110-0099999999999999"))
        raw = bytearray(self.cms())
        raw[-5] ^= 1
        with self.assertRaises(ValueError):
            self.verifier.verify(bytes(raw))
        self.cmd(
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "other.key",
            "-out",
            "other.pem",
            "-days",
            "1",
            "-subj",
            "/CN=SYNTHETIC Other CA",
        )
        other = self.module.DeviceCMSVerifier(
            self.root,
            self.run,
            openssl_path=self.openssl,
            device_ca_file=self.root / "other.pem",
            device_leaf_policy=self.policy,
        )
        with self.assertRaises(ValueError):
            other.verify(self.cms())


if __name__ == "__main__":
    unittest.main()
