"""Guest-only distribution key/CSR and PKCS#12 bootstrap; no Apple API calls."""

import hashlib, importlib.util, os, pathlib, re, tempfile, time

import guest.verification as verification

executor = verification.executor
import guest.native as native


def reject(code):
    raise ValueError(code)


def guest(workspace, grant, proof, validate, operation):
    if (
        os.environ.get("ISIGN_ISOLATED_EXECUTOR") != "1"
        or not callable(validate)
        or validate(proof, grant) is not True
    ):
        reject("TRUSTED_VM_PROOF_REQUIRED")
    native.validate_execution_grant(grant)
    root = pathlib.Path(workspace).absolute()
    if (
        root.resolve() != root
        or not root.is_dir()
        or grant.get("operation") != operation
        or (
            operation == "bootstrap-pkcs12"
            and not re.fullmatch("[A-Za-z0-9]{1,64}", str(grant.get("teamId", "")))
        )
        or (
            grant.get("teamId") is not None
            and not re.fullmatch("[A-Za-z0-9]{1,64}", str(grant.get("teamId")))
        )
    ):
        reject("BOOTSTRAP_GRANT_INVALID")
    return root


def password(provider, grant, kind):
    if not callable(provider):
        reject("MATERIAL_PASSWORD_REQUIRED")
    value = provider(grant, kind)
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 1024
        or any(c in value for c in ("\0", "\n", "\r"))
    ):
        reject("MATERIAL_PASSWORD_INVALID")
    return value


def persisted_receipt(seal, material, kind, grant, secret_password):
    if not callable(seal):
        reject("ENCRYPTED_BROKER_REQUIRED")
    receipt = seal(material, kind=kind, grant=grant, secret_password=secret_password)
    if (
        not isinstance(receipt, dict)
        or receipt.get("persisted") is not True
        or receipt.get("passwordSealed") is not True
        or any(
            receipt.get(k) != grant[k]
            for k in ("ownerId", "connectionId", "connectionGeneration", "taskNonce")
        )
        or receipt.get("materialKind") != kind
        or not isinstance(receipt.get("storageRef"), str)
        or not receipt["storageRef"]
        or not re.fullmatch("[a-f0-9]{64}", str(receipt.get("ciphertextDigest", "")))
    ):
        reject("ENCRYPTED_PERSISTENCE_UNCONFIRMED")
    return receipt


def generate_distribution_request(
    *,
    workspace,
    grant,
    vm_proof,
    validate_vm,
    command_runner,
    openssl_path,
    password_provider,
    seal_material,
):
    root = guest(workspace, grant, vm_proof, validate_vm, "bootstrap-request")
    phrase = password(password_provider, grant, "distribution-key")

    def run(args, secret=None):
        native.validate_execution_grant(grant)
        return command_runner(
            [openssl_path, *args], cwd=str(root), timeout=120, input_bytes=secret
        )["stdout"]

    with tempfile.TemporaryDirectory(prefix="bootstrap-key-", dir=root) as td:
        key = pathlib.Path(td) / "distribution-key.pem"
        try:
            run(
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
                    str(key),
                ],
                (phrase + "\n").encode("utf8"),
            )
            os.chmod(key, 0o600)
            csr = run(
                [
                    "req",
                    "-new",
                    "-sha256",
                    "-key",
                    str(key),
                    "-passin",
                    "stdin",
                    "-subj",
                    "/CN=iSign Distribution"
                    + ("/OU=" + grant["teamId"] if grant.get("teamId") else ""),
                ],
                (phrase + "\n").encode("utf8"),
            )
            if len(csr) > 65536 or not csr.startswith(b"-----BEGIN CERTIFICATE REQUEST-----"):
                reject("CSR_INVALID")
            run(["req", "-verify", "-noout"], csr)
            spki = run(
                ["pkey", "-in", str(key), "-passin", "stdin", "-pubout", "-outform", "DER"],
                (phrase + "\n").encode("utf8"),
            )
            if not spki or len(spki) > 65536:
                reject("SPKI_INVALID")
            if key.stat().st_size > 65536:
                reject("KEY_MATERIAL_LIMIT")
            receipt = persisted_receipt(
                seal_material, key.read_bytes(), "distribution-key", grant, phrase
            )
            native.validate_execution_grant(grant)
            return {
                "operation": "bootstrap-request",
                "ownerId": grant["ownerId"],
                "connectionId": grant["connectionId"],
                "connectionGeneration": grant["connectionGeneration"],
                "taskNonce": grant["taskNonce"],
                **({"teamId": grant["teamId"]} if grant.get("teamId") else {}),
                "csr": csr.decode("ascii"),
                "spkiDigest": hashlib.sha256(spki).hexdigest(),
                "encryptedKeyRef": receipt["storageRef"],
                "ciphertextDigest": receipt["ciphertextDigest"],
                "persistedBeforeCertificateRequest": True,
            }
        finally:
            phrase = None
            key.unlink(missing_ok=True)


def seal_distribution_pkcs12(
    *,
    workspace,
    grant,
    vm_proof,
    validate_vm,
    command_runner,
    openssl_path,
    password_provider,
    seal_material,
    encrypted_key_path,
    certificate_der,
    expected_spki_digest,
    identity,
    verifier,
):
    root = guest(workspace, grant, vm_proof, validate_vm, "bootstrap-pkcs12")
    key = executor.guest_path(root, encrypted_key_path)
    if (
        not key.is_file()
        or key.stat().st_size > 65536
        or not isinstance(certificate_der, bytes)
        or not certificate_der
        or len(certificate_der) > 65536
        or not re.fullmatch("[a-f0-9]{64}", expected_spki_digest)
    ):
        reject("BOOTSTRAP_MATERIAL_INVALID")
    key_password = None
    p12_password = None

    def run(args, secret=None):
        native.validate_execution_grant(grant)
        return command_runner(
            [openssl_path, *args], cwd=str(root), timeout=120, input_bytes=secret
        )["stdout"]

    try:
        key_password = password(password_provider, grant, "distribution-key")
        p12_password = password(password_provider, grant, "distribution-pkcs12")
        public = run(
            ["pkey", "-in", str(key), "-passin", "stdin", "-pubout", "-outform", "DER"],
            (key_password + "\n").encode("utf8"),
        )
        certpem = run(["x509", "-inform", "DER", "-outform", "PEM"], certificate_der)
        certpublic = run(
            ["pkey", "-pubin", "-pubout", "-outform", "DER"],
            run(["x509", "-pubkey", "-noout"], certpem),
        )
        if public != certpublic or hashlib.sha256(public).hexdigest() != expected_spki_digest:
            reject("CERTIFICATE_KEY_MISMATCH")
        if identity.get("ownerId") != grant["ownerId"] or identity.get("teamId") != grant["teamId"]:
            reject("BOOTSTRAP_IDENTITY_MISMATCH")
        if verifier.certificate(certpem, identity) != certificate_der:
            reject("BOOTSTRAP_CERTIFICATE_MISMATCH")
        with tempfile.TemporaryDirectory(prefix="bootstrap-p12-", dir=root) as td:
            certificate = pathlib.Path(td) / "certificate.pem"
            certificate.write_bytes(certpem)
            output = pathlib.Path(td) / "identity.p12"
            # OpenSSL documents successive stdin lines for passin/passout.
            run(
                [
                    "pkcs12",
                    "-export",
                    "-inkey",
                    str(key),
                    "-in",
                    str(certificate),
                    "-passin",
                    "stdin",
                    "-passout",
                    "stdin",
                    "-out",
                    str(output),
                ],
                (key_password + "\n" + p12_password + "\n").encode("utf8"),
            )
            if not output.is_file() or output.stat().st_size > 65536:
                reject("PKCS12_MATERIAL_INVALID")
            receipt = persisted_receipt(
                seal_material, output.read_bytes(), "distribution-pkcs12", grant, p12_password
            )
            native.validate_execution_grant(grant)
            return {
                "operation": "bootstrap-pkcs12",
                "ownerId": grant["ownerId"],
                "connectionId": grant["connectionId"],
                "connectionGeneration": grant["connectionGeneration"],
                "taskNonce": grant["taskNonce"],
                "teamId": grant["teamId"],
                "fingerprint": identity["fingerprint"],
                "certificateExpiresAt": identity["expiresAt"],
                "spkiDigest": expected_spki_digest,
                "encryptedPkcs12Ref": receipt["storageRef"],
                "ciphertextDigest": receipt["ciphertextDigest"],
            }
    finally:
        key_password = None
        p12_password = None
        key.unlink(missing_ok=True)
