from runner_modules import load
import datetime
import hashlib
import pathlib
import tempfile
import unittest


class FeatherProfileReceiptTests(unittest.TestCase):
    def test_receipt_entitlements_come_from_verified_cms(self):
        module = load("verification")
        certificate = b"synthetic certificate"
        entitlements = {
            "application-identifier": "ABCDEFGHIJ.com.example.*",
            "com.apple.developer.team-identifier": "ABCDEFGHIJ",
            "get-task-allow": False,
            "keychain-access-groups": ["ABCDEFGHIJ.*"],
        }
        expected = {
            "udid": "A" * 40,
            "certificateSha256": hashlib.sha256(certificate).hexdigest(),
            "teamId": "ABCDEFGHIJ",
            "bundleId": "com.example.app",
        }
        with tempfile.TemporaryDirectory() as directory:

            class VerifiedCmsBoundary:
                root = pathlib.Path(directory)

                def clock(self):
                    return 1700000000000

                def decode_profile(self, path):
                    return {
                        "TeamIdentifier": ["ABCDEFGHIJ"],
                        "ApplicationIdentifierPrefix": ["ABCDEFGHIJ"],
                        "ExpirationDate": datetime.datetime(2030, 1, 1),
                        "ProvisionedDevices": [expected["udid"]],
                        "DeveloperCertificates": [certificate],
                        "Entitlements": entitlements,
                    }

                def openssl_command(self, args, data):
                    if "-startdate" in args:
                        return b"notBefore=Jan  1 00:00:00 2020 GMT\nnotAfter=Jan  1 00:00:00 2030 GMT\n"
                    return b"synthetic pem"

                def certificate(self, pem, identity):
                    return certificate

            receipt = module.DeviceProfileVerifier(VerifiedCmsBoundary()).verify(b"cms", expected)
            self.assertEqual(receipt["entitlements"], entitlements)
            self.assertEqual(
                receipt["entitlements"]["application-identifier"], "ABCDEFGHIJ.com.example.*"
            )
