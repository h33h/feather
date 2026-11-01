"""Guest-only AES-256-GCM envelope bridge matching bootstrap-sealing.ts.

Requires audited cryptography AESGCM in the pinned guest image. No dependency is
installed here and no home-grown AEAD or host private-key processing is used.
"""

import base64, hashlib, hmac, importlib.util, json, os, re, time

import guest.native as native

canonical = native.canonical
GRANT_DOMAIN = b"isign-bootstrap-grant-v1\0"
RECEIPT_DOMAIN = b"isign-bootstrap-envelope-v1\0"


def reject(code):
    raise ValueError(code)


def validate_seal_grant(
    grant, key, audience, runner_grant, vm_proof, validate_vm, now=None, grant_authorizer=None
):
    fields = {
        "version",
        "operation",
        "lease",
        "secretId",
        "grantNonce",
        "audience",
        "instanceId",
        "purpose",
        "materialFormat",
        "expiresAt",
        "wrappedKey",
        "aad",
        "signature",
    }
    now = int(time.time() * 1000) if now is None else now
    if (
        os.environ.get("ISIGN_ISOLATED_EXECUTOR") != "1"
        or not callable(validate_vm)
        or validate_vm(vm_proof, runner_grant) is not True
    ):
        reject("TRUSTED_GUEST_REQUIRED")
    if (
        not isinstance(grant, dict)
        or set(grant) != fields
        or grant["version"] != 1
        or grant["operation"] != "bootstrap-seal"
        or grant["purpose"] != "distribution-key"
        or grant["materialFormat"] != "encrypted-pem-with-password-v1"
        or grant["audience"] != audience
        or grant["instanceId"] != runner_grant.get("isolationInstanceId")
        or type(grant["expiresAt"]) is not int
        or not now < grant["expiresAt"] <= runner_grant["expiresAt"]
    ):
        reject("BOOTSTRAP_SEAL_GRANT_INVALID")
    lease = grant["lease"]
    if (
        not isinstance(lease, dict)
        or set(lease) != {"ownerId", "connectionId", "generation", "nonce", "expiresAt"}
        or type(lease["expiresAt"]) is not int
        or lease["expiresAt"] <= now
        or lease["ownerId"] != runner_grant["ownerId"]
        or lease["connectionId"] != runner_grant["connectionId"]
        or lease["generation"] != runner_grant["connectionGeneration"]
    ):
        reject("BOOTSTRAP_LEASE_MISMATCH")
    for k in ("secretId", "grantNonce", "wrappedKey", "signature"):
        if not isinstance(grant[k], str) or not grant[k] or len(grant[k]) > 65536:
            reject("BOOTSTRAP_SEAL_GRANT_INVALID")
    if not isinstance(key, bytes) or len(key) < 32:
        reject("BOOTSTRAP_PROOF_KEY_REQUIRED")
    signature = hmac.new(
        key,
        GRANT_DOMAIN + canonical({k: v for k, v in grant.items() if k != "signature"}),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(signature, grant["signature"]) and (
        not callable(grant_authorizer) or grant_authorizer(grant) is not True
    ):
        reject("BOOTSTRAP_SEAL_SIGNATURE_INVALID")
    aad = json.dumps(
        {
            "owner": lease["ownerId"],
            "connection": lease["connectionId"],
            "purpose": grant["purpose"],
            "secret": grant["secretId"],
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf8")
    if grant["aad"] != aad.decode("utf8"):
        reject("BOOTSTRAP_AAD_MISMATCH")
    return aad


def seal_bootstrap_material(
    *,
    grant,
    data_key,
    material,
    secret_password,
    csr,
    spki_der,
    proof_key,
    audience,
    runner_grant,
    vm_proof,
    validate_vm,
    nonce_provider=os.urandom,
    aesgcm_factory=None,
    grant_authorizer=None,
):
    aad = validate_seal_grant(
        grant,
        proof_key,
        audience,
        runner_grant,
        vm_proof,
        validate_vm,
        grant_authorizer=grant_authorizer,
    )
    if (
        not isinstance(data_key, bytes)
        or len(data_key) != 32
        or not isinstance(material, bytes)
        or not material
        or len(material) > 65536
        or not isinstance(secret_password, str)
        or not secret_password
        or len(secret_password) > 1024
        or any(c in secret_password for c in ("\0", "\r", "\n"))
        or not isinstance(csr, str)
        or len(csr) > 65536
        or not csr.startswith("-----BEGIN CERTIFICATE REQUEST-----")
        or not isinstance(spki_der, bytes)
        or not spki_der
        or len(spki_der) > 65536
    ):
        reject("BOOTSTRAP_SEAL_MATERIAL_INVALID")
    if aesgcm_factory is None:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError as exc:
            raise ValueError("TRUSTED_GUEST_AESGCM_UNAVAILABLE") from exc
        aesgcm_factory = AESGCM
    nonce = nonce_provider(12)
    if not isinstance(nonce, bytes) or len(nonce) != 12:
        reject("BOOTSTRAP_NONCE_INVALID")
    plaintext = canonical(
        {
            "format": grant["materialFormat"],
            "material": base64.b64encode(material).decode("ascii"),
            "password": secret_password,
        }
    )
    sealed = aesgcm_factory(data_key).encrypt(nonce, plaintext, aad)
    plaintext = b""
    if not isinstance(sealed, bytes) or len(sealed) < 17:
        reject("BOOTSTRAP_CIPHERTEXT_INVALID")
    ciphertext, tag = sealed[:-16], sealed[-16:]
    envelope = {k: grant[k] for k in ("audience", "purpose", "expiresAt", "wrappedKey", "aad")}
    envelope.update(
        secretId=grant["secretId"],
        grantNonce=grant["grantNonce"],
        instanceId=grant["instanceId"],
        nonce=base64.b64encode(nonce).decode("ascii"),
        ciphertext=base64.b64encode(ciphertext).decode("ascii"),
        tag=base64.b64encode(tag).decode("ascii"),
    )
    report = {
        "version": 1,
        "operation": "bootstrap-envelope",
        "grant": grant,
        "materialFormat": grant["materialFormat"],
        "envelope": envelope,
        "csr": csr,
        "spkiSha256": hashlib.sha256(spki_der).hexdigest(),
        "ciphertextSha256": hashlib.sha256(ciphertext).hexdigest(),
    }
    return {
        "report": report,
        "attestation": hmac.new(
            proof_key, RECEIPT_DOMAIN + canonical(report), hashlib.sha256
        ).hexdigest(),
    }
