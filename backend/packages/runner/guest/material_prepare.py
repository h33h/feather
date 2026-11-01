"""Restore sealed job material and produce verified signing files inside a guest."""

import base64, hashlib, importlib.util, json, os, pathlib, plistlib, re, secrets, shutil, tempfile

import guest.verification as verification

executor = verification.executor
import guest.native as native


def reject(code):
    raise ValueError(code)


def decode_job_key(sealed, grant, *, aesgcm_factory=None):
    if (
        not isinstance(sealed, dict)
        or set(sealed) != {"envelope", "dataKey"}
        or not isinstance(sealed["envelope"], dict)
    ):
        reject("SEALED_JOB_KEY_INVALID")
    envelope = sealed["envelope"]
    fields = {
        "owner",
        "connection",
        "purpose",
        "secret",
        "aad",
        "wrappedKey",
        "nonce",
        "ciphertext",
        "tag",
        "generation",
    }
    if (
        set(envelope) != fields
        or envelope["owner"] != grant.get("connectionOwnerId", grant["ownerId"])
        or envelope["connection"] != grant["connectionId"]
        or envelope["generation"] != grant["connectionGeneration"]
        or envelope["purpose"] != "distribution-key"
        or not isinstance(envelope["secret"], str)
        or not envelope["secret"]
    ):
        reject("SEALED_JOB_KEY_BINDING_MISMATCH")
    aad = json.dumps(
        {
            "owner": grant.get("connectionOwnerId", grant["ownerId"]),
            "connection": grant["connectionId"],
            "purpose": "distribution-key",
            "secret": envelope["secret"],
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf8")
    if envelope["aad"] != aad.decode("utf8"):
        reject("SEALED_JOB_KEY_AAD_MISMATCH")
    try:
        key = base64.b64decode(sealed["dataKey"], validate=True)
        nonce = base64.b64decode(envelope["nonce"], validate=True)
        tag = base64.b64decode(envelope["tag"], validate=True)
        ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
    except (ValueError, TypeError):
        reject("SEALED_JOB_KEY_ENCODING_INVALID")
    if (
        len(key) != 32
        or len(nonce) != 12
        or len(tag) != 16
        or not ciphertext
        or len(ciphertext) > 65536
    ):
        reject("SEALED_JOB_KEY_LIMIT")
    if aesgcm_factory is None:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError as exc:
            raise ValueError("TRUSTED_GUEST_AESGCM_UNAVAILABLE") from exc
        aesgcm_factory = AESGCM
    try:
        plaintext = aesgcm_factory(key).decrypt(nonce, ciphertext + tag, aad)
    except Exception as exc:
        raise ValueError("SEALED_JOB_KEY_AUTHENTICATION_FAILED") from exc
    key = b""
    if not isinstance(plaintext, bytes) or len(plaintext) > 65536:
        reject("SEALED_JOB_KEY_PLAINTEXT_LIMIT")
    try:
        package = json.loads(plaintext.decode("utf8"))
    except (ValueError, UnicodeError):
        reject("SEALED_JOB_KEY_PACKAGE_INVALID")
    plaintext = b""
    if (
        not isinstance(package, dict)
        or set(package) != {"format", "material", "password"}
        or package["format"] != "encrypted-pem-with-password-v1"
        or not isinstance(package["password"], str)
        or not package["password"]
        or len(package["password"]) > 1024
        or any(c in package["password"] for c in ("\0", "\r", "\n"))
    ):
        reject("SEALED_JOB_KEY_PACKAGE_INVALID")
    try:
        material = base64.b64decode(package["material"], validate=True)
    except (ValueError, TypeError):
        reject("SEALED_JOB_KEY_PACKAGE_INVALID")
    if not material or len(material) > 65536:
        reject("SEALED_JOB_KEY_MATERIAL_LIMIT")
    return material, package["password"]


class GuestMaterialStore:
    def __init__(
        self,
        workspace,
        command_runner,
        guest_verifier,
        *,
        openssl_path,
        validate_vm,
        aesgcm_factory=None,
    ):
        self.root = pathlib.Path(workspace).resolve()
        self.run = command_runner
        self.verifier = guest_verifier
        self.openssl = openssl_path
        self.validate_vm = validate_vm
        self.aesgcm_factory = aesgcm_factory
        self.passwords = {}

    def command(self, args, input_bytes=None):
        return self.run(
            [self.openssl, *args], cwd=str(self.root), timeout=120, input_bytes=input_bytes
        )["stdout"]

    def prepare(self, grant, payload, vm_proof):
        if (
            os.environ.get("ISIGN_ISOLATED_EXECUTOR") != "1"
            or self.validate_vm(vm_proof, grant) is not True
        ):
            reject("TRUSTED_VM_PROOF_REQUIRED")
        native.validate_execution_grant(grant)
        if not isinstance(payload, dict) or set(payload) != {
            "sealedKey",
            "certificatePem",
            "profiles",
            "expected",
        }:
            reject("JOB_MATERIAL_PAYLOAD_INVALID")
        expected = payload["expected"]
        profiles = payload["profiles"]
        certificate_pem = payload["certificatePem"]
        if (
            not isinstance(expected, dict)
            or set(expected)
            != {"ownerId", "teamId", "certificateSha256", "fingerprint", "udid", "deviceOs"}
            or expected["ownerId"] != grant["ownerId"]
            or not isinstance(profiles, list)
            or not profiles
            or len(profiles) > 20000
            or not isinstance(certificate_pem, str)
            or len(certificate_pem) > 65536
            or not re.fullmatch("[a-f0-9]{64}", str(expected["certificateSha256"]))
        ):
            reject("JOB_MATERIAL_EXPECTED_INVALID")
        directory = self.root / "materials"
        if directory.exists():
            reject("JOB_MATERIAL_ALREADY_PREPARED")
        directory.mkdir(mode=0o700)
        success = False
        try:
            key_material, key_password = decode_job_key(
                payload["sealedKey"], grant, aesgcm_factory=self.aesgcm_factory
            )
            with tempfile.TemporaryDirectory(prefix="prepare-key-", dir=self.root) as td:
                key = pathlib.Path(td) / "key.pem"
                key.write_bytes(key_material)
                os.chmod(key, 0o600)
                key_material = b""
                pem = verification.one_pem_certificate(certificate_pem.encode("ascii"))
                der = self.command(["x509", "-outform", "DER"], pem)
                if (
                    hashlib.sha256(der).hexdigest() != expected["certificateSha256"]
                    or verification.fingerprint(der, expected["fingerprint"])
                    != expected["fingerprint"]
                ):
                    reject("JOB_CERTIFICATE_IDENTITY_MISMATCH")
                public_key = self.command(
                    ["pkey", "-in", str(key), "-passin", "stdin", "-pubout", "-outform", "DER"],
                    (key_password + "\n").encode(),
                )
                public_certificate = self.command(
                    ["pkey", "-pubin", "-pubout", "-outform", "DER"],
                    self.command(["x509", "-pubkey", "-noout"], pem),
                )
                if not public_key or public_key != public_certificate:
                    reject("CERTIFICATE_KEY_MISMATCH")
                _, expires = verification.parse_cert_dates(
                    self.command(["x509", "-noout", "-startdate", "-enddate"], pem)
                )
                identity = {
                    "ownerId": grant["ownerId"],
                    "teamId": expected["teamId"],
                    "prefix": None,
                    "fingerprint": expected["fingerprint"],
                    "expiresAt": expires,
                    "materialPath": "materials/key.p12",
                }
                if self.verifier.certificate(pem, identity) != der:
                    reject("JOB_CERTIFICATE_CHAIN_MISMATCH")
                prepared = {}
                prefix = None
                for item in profiles:
                    if (
                        not isinstance(item, dict)
                        or set(item) != {"bundleId", "cmsBase64", "cmsSha256", "resourceId"}
                        or not isinstance(item["bundleId"], str)
                        or not re.fullmatch(r"([A-Za-z0-9-]+\.)+[A-Za-z0-9-]+", item["bundleId"])
                        or item["bundleId"] in prepared
                        or not isinstance(item["cmsBase64"], str)
                        or len(item["cmsBase64"]) > 87384
                    ):
                        reject("JOB_PROFILE_INPUT_INVALID")
                    try:
                        cms = base64.b64decode(item["cmsBase64"], validate=True)
                    except (ValueError, TypeError):
                        reject("JOB_PROFILE_INPUT_INVALID")
                    if (
                        not cms
                        or len(cms) > 65536
                        or hashlib.sha256(cms).hexdigest() != item["cmsSha256"]
                    ):
                        reject("JOB_PROFILE_DIGEST_MISMATCH")
                    relative = (
                        "materials/profile_"
                        + hashlib.sha256(item["bundleId"].encode()).hexdigest()[:32]
                        + ".mobileprovision"
                    )
                    path = self.root / relative
                    path.write_bytes(cms)
                    profile = self.verifier.decode_profile(path)
                    prefixes = profile.get("ApplicationIdentifierPrefix")
                    devices = profile.get("ProvisionedDevices")
                    ent = profile.get("Entitlements")
                    expiration = profile.get("ExpirationDate")
                    if (
                        not isinstance(prefixes, list)
                        or len(prefixes) != 1
                        or not isinstance(prefixes[0], str)
                        or not re.fullmatch("[A-Za-z0-9]+", prefixes[0])
                        or (prefix is not None and prefix != prefixes[0])
                        or not isinstance(devices, list)
                        or not isinstance(ent, dict)
                        or not hasattr(expiration, "timestamp")
                    ):
                        reject("JOB_PROFILE_SCOPE_MISMATCH")
                    prefix = prefixes[0]
                    profile_expiry = int(
                        expiration.replace(tzinfo=verification.datetime.timezone.utc).timestamp()
                        * 1000
                    )
                    descriptor = {
                        **identity,
                        "prefix": prefix,
                        "bundleId": item["bundleId"],
                        "udids": devices,
                        "entitlements": verification.profile_entitlement_ceiling(
                            ent, prefix, item["bundleId"], expected["teamId"]
                        ),
                        "expiresAt": profile_expiry,
                        "materialPath": relative,
                        "cmsSha256": item["cmsSha256"],
                        "certificateSha256": expected["certificateSha256"],
                    }
                    verification.validate_profile(
                        profile, descriptor, expected["udid"], der, self.verifier.clock()
                    )
                    prepared[item["bundleId"]] = descriptor
                identity["prefix"] = prefix
                pkcs12_password = secrets.token_urlsafe(48)
                certfile = pathlib.Path(td) / "leaf.pem"
                certfile.write_bytes(pem)
                output = directory / "key.p12"
                export = ["pkcs12", "-export", "-inkey", str(key), "-in", str(certfile)]
                chain_provider = getattr(self.verifier, "signing_chain_pem", None)
                if callable(chain_provider):
                    chain_pem = chain_provider()
                    if (
                        not isinstance(chain_pem, bytes)
                        or not chain_pem
                        or len(chain_pem) > 327680
                        or b"PRIVATE KEY" in chain_pem
                    ):
                        reject("PINNED_SIGNING_CHAIN_REQUIRED")
                    chainfile = pathlib.Path(td) / "chain.pem"
                    chainfile.write_bytes(chain_pem)
                    export += ["-certfile", str(chainfile)]
                self.command(
                    export + ["-passin", "stdin", "-passout", "stdin", "-out", str(output)],
                    (key_password + "\n" + pkcs12_password + "\n").encode(),
                )
                if not output.is_file() or output.stat().st_size > 65536:
                    reject("JOB_PKCS12_INVALID")
                os.chmod(output, 0o600)
                key_password = None
            native.validate_execution_grant(grant)
            self.passwords[identity["materialPath"]] = {
                "password": pkcs12_password,
                "binding": {
                    k: grant[k]
                    for k in (
                        *(
                            "ownerId",
                            "jobId",
                            "connectionId",
                            "connectionGeneration",
                            "isolationInstanceId",
                        ),
                        *(
                            k
                            for k in ("connectionOwnerId", "accessGrantId", "accessGrantGeneration")
                            if k in grant
                        ),
                    )
                },
            }
            success = True
            return {
                "identity": identity,
                "profiles": prepared,
                "udid": expected["udid"],
                "deviceOs": expected["deviceOs"],
            }
        finally:
            if not success:
                shutil.rmtree(directory, ignore_errors=True)

    def password_provider(self, path, grant):
        relative = str(pathlib.Path(path).relative_to(self.root))
        record = self.passwords.get(relative)
        if not record or any(grant.get(k) != v for k, v in record["binding"].items()):
            reject("JOB_PASSWORD_BINDING_MISMATCH")
        return record["password"]

    def clear(self):
        for record in self.passwords.values():
            record["password"] = None
        self.passwords.clear()
        shutil.rmtree(self.root / "materials", ignore_errors=True)
