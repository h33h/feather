"""Internal runner peers use one explicit current protocol shape."""

import time
import unittest
from runner_modules import load


class CurrentContractTests(unittest.TestCase):
    def grant(self):
        return {
            "ownerId": "owner",
            "connectionOwnerId": "owner",
            "jobId": "job",
            "leaseToken": "lease",
            "connectionId": "connection",
            "deviceId": "device",
            "connectionGeneration": 1,
            "uploadDigest": "a" * 64,
            "taskNonce": "nonce",
            "isolationInstanceId": "guest",
            "expiresAt": int(time.time() * 1000) + 60000,
        }

    def test_grant_requires_explicit_connection_owner(self):
        grants = load("analyzer")
        request = self.grant()
        request.pop("connectionOwnerId")
        with self.assertRaisesRegex(ValueError, "ISOLATION_GRANT_REQUIRED"):
            grants.validate_grant(request)

    def test_current_own_connection_does_not_require_a_share(self):
        load("analyzer").validate_grant(self.grant())

    def test_vm_evidence_requires_discriminator(self):
        native = load("native")
        evidence = {key: True for key in native.REQUIRED_ISOLATION}
        with self.assertRaisesRegex(ValueError, "VM_ISOLATION_EVIDENCE_REQUIRED"):
            native.validated_isolation(evidence)

    def test_current_vm_evidence_retains_discriminator(self):
        native = load("native")
        evidence = {"type": "vm", **{key: True for key in native.REQUIRED_ISOLATION}}
        self.assertEqual(native.validated_isolation(evidence), evidence)

    def test_control_grant_requires_explicit_connection_owner(self):
        grant = self.grant()
        grant.update(operation="bootstrap-request", jobId="bootstrap:" + grant["taskNonce"])
        grant.pop("connectionOwnerId")
        with self.assertRaisesRegex(ValueError, "CONTROL_EXECUTION_GRANT_INVALID"):
            load("native").validate_execution_grant(grant)
