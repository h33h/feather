"""Concrete composition installed only in an authenticated disposable guest.

Transport authentication and physical VM evidence are mandatory deployment inputs.
This module never starts a listener or obtains controller secrets.
"""

import base64, hashlib, hmac, importlib.util, pathlib, secrets, tempfile, os


import guest.native as native
import guest.executor as executor
import guest.verification as verification
import guest.material_prepare as material_prepare
import guest.bootstrap_sealing as bootstrap_sealing


class GuestRuntime:
    def __init__(
        self,
        workspace,
        command_runner,
        verifier,
        *,
        openssl_path,
        validate_vm,
        proof_key,
        key_id,
        seal_grant_authorizer=None,
    ):
        if not callable(validate_vm) or not isinstance(proof_key, bytes) or len(proof_key) < 32:
            raise ValueError("TRUSTED_GUEST_CONFIGURATION_REQUIRED")
        self.root = pathlib.Path(workspace).resolve()
        self.run = command_runner
        self.verifier = verifier
        self.validate_vm = validate_vm
        self.key = proof_key
        self.key_id = key_id
        self.openssl = openssl_path
        self.seal_grant_authorizer = seal_grant_authorizer
        self.materials = material_prepare.GuestMaterialStore(
            self.root, command_runner, verifier, openssl_path=openssl_path, validate_vm=validate_vm
        )

    def signed(self, report):
        return {
            "report": report,
            "attestation": hmac.new(self.key, native.canonical(report), hashlib.sha256).hexdigest(),
        }

    def bootstrap_prepare(self, binding, payload, execution_grant, proof):
        native.validate_execution_grant(execution_grant)
        if (
            self.validate_vm(proof, execution_grant) is not True
            or execution_grant["operation"] != "bootstrap-request"
            or execution_grant["ownerId"] != binding["ownerId"]
            or execution_grant["taskNonce"] != binding["nonce"]
            or execution_grant["isolationInstanceId"] != payload["instanceId"]
        ):
            raise ValueError("BOOTSTRAP_VM_BINDING_MISMATCH")
        seal = payload["sealGrant"]
        key = base64.b64decode(payload["dataKey"], validate=True)
        bootstrap_sealing.validate_seal_grant(
            seal,
            self.key,
            seal["audience"],
            execution_grant,
            proof,
            self.validate_vm,
            grant_authorizer=self.seal_grant_authorizer,
        )
        if len(key) != 32:
            raise ValueError("BOOTSTRAP_DATA_KEY_INVALID")
        password = secrets.token_urlsafe(48)
        try:
            with tempfile.TemporaryDirectory(prefix="bootstrap-key-", dir=self.root) as td:
                material = pathlib.Path(td) / "encrypted.pem"

                def command(args, data=None):
                    return self.run(
                        [self.openssl, *args], cwd=str(self.root), timeout=120, input_bytes=data
                    )["stdout"]

                command(
                    [
                        "genpkey",
                        "-algorithm",
                        "RSA",
                        "-pkeyopt",
                        "rsa_keygen_bits:2048",
                        "-aes-256-cbc",
                        "-pass",
                        "stdin",
                        "-out",
                        str(material),
                    ],
                    (password + "\n").encode(),
                )
                os.chmod(material, 0o600)
                csr = command(
                    [
                        "req",
                        "-new",
                        "-sha256",
                        "-key",
                        str(material),
                        "-passin",
                        "stdin",
                        "-subj",
                        "/CN=iSign Distribution Key",
                        "-outform",
                        "PEM",
                    ],
                    (password + "\n").encode(),
                )
                command(["req", "-verify", "-noout"], csr)
                spki = command(
                    [
                        "pkey",
                        "-in",
                        str(material),
                        "-passin",
                        "stdin",
                        "-pubout",
                        "-outform",
                        "DER",
                    ],
                    (password + "\n").encode(),
                )
                if material.stat().st_size > 65536:
                    raise ValueError("BOOTSTRAP_KEY_LIMIT")
                return bootstrap_sealing.seal_bootstrap_material(
                    grant=seal,
                    data_key=key,
                    material=material.read_bytes(),
                    secret_password=password,
                    csr=csr.decode("ascii"),
                    spki_der=spki,
                    proof_key=self.key,
                    audience=seal["audience"],
                    runner_grant=execution_grant,
                    vm_proof=proof,
                    validate_vm=self.validate_vm,
                    grant_authorizer=self.seal_grant_authorizer,
                )
        finally:
            password = None
            key = b""

    def material_prepare(self, grant, payload, proof):
        value = self.materials.prepare(grant, payload, proof)
        return self.signed(
            {
                "version": 1,
                "operation": "material-prepare",
                "binding": grant,
                "instanceId": grant["isolationInstanceId"],
                "expected": payload["expected"],
                "payloadDigest": hashlib.sha256(native.canonical(payload)).hexdigest(),
                "value": value,
            }
        )

    def device_profile_verify(self, binding, payload, execution_grant, proof):
        native.validate_execution_grant(execution_grant)
        if (
            self.validate_vm(proof, execution_grant) is not True
            or execution_grant["operation"] != "device-profile-verify"
            or execution_grant["ownerId"] != binding["ownerId"]
            or execution_grant["taskNonce"] != binding["nonce"]
            or execution_grant["isolationInstanceId"] != payload["instanceId"]
        ):
            raise ValueError("DEVICE_PROFILE_VM_BINDING_MISMATCH")
        cms = base64.b64decode(payload["cmsBase64"], validate=True)
        return verification.DeviceProfileVerifier(self.verifier).envelope(
            cms, payload["expected"], binding, payload["instanceId"], self.key
        )

    def artifact(self, ref):
        if ref != "signed_ipa":
            raise ValueError("ARTIFACT_REFERENCE_INVALID")
        path = self.root / "signed.ipa"
        if path.is_symlink() or not path.is_file():
            raise ValueError("ARTIFACT_UNAVAILABLE")
        with path.open("rb") as stream:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                yield chunk

    def destroy(self):
        self.materials.clear()
        (self.root / "signed.ipa").unlink(missing_ok=True)
