"""Device Profile Service CMS verifier; no browser-provided trust booleans."""

import hashlib, pathlib, plistlib, re, tempfile

from verification_core.certificates import one_pem_certificate


def reject(code):
    raise ValueError(code)


class DeviceLeafPolicy:
    """Concrete explicitly configured device issuer/subject policy.

    No guessed Apple CA, subject format or EKU is configured by default. Deployment
    must pin the supported real device certificate policy; unsupported chains fail.
    """

    def __init__(
        self, command_runner, workspace, openssl_path, *, issuer_dn, udid_subject_attribute
    ):
        if (
            not isinstance(issuer_dn, str)
            or not issuer_dn
            or udid_subject_attribute not in ("CN", "serialNumber", "UID")
        ):
            reject("DEVICE_POLICY_REQUIRED")
        self.run = command_runner
        self.root = pathlib.Path(workspace).resolve()
        self.openssl = openssl_path
        self.issuer = issuer_dn
        self.attribute = udid_subject_attribute

    def __call__(self, der, udid):
        output = self.run(
            [
                self.openssl,
                "x509",
                "-inform",
                "DER",
                "-noout",
                "-subject",
                "-issuer",
                "-nameopt",
                "RFC2253",
            ],
            cwd=str(self.root),
            timeout=30,
            input_bytes=der,
        )["stdout"].decode("utf8")
        fields = {}
        for line in output.splitlines():
            key, value = line.split("=", 1)
            if key in fields:
                return False
            fields[key] = value
        if fields.get("issuer") != self.issuer:
            return False
        subject = fields.get("subject", "")
        values = re.findall(r"(?:^|,)" + re.escape(self.attribute) + r"=([^,]+)", subject)
        return values == [udid]


class DeviceCMSVerifier:
    def __init__(
        self,
        workspace,
        command_runner,
        *,
        openssl_path,
        device_ca_file,
        device_leaf_policy,
        policy_id=None,
    ):
        self.root = pathlib.Path(workspace).resolve()
        self.run = command_runner
        self.openssl = openssl_path
        self.ca = pathlib.Path(device_ca_file).resolve()
        self.policy = device_leaf_policy
        self.policy_id = policy_id
        self.ca_sha256 = (
            hashlib.sha256(self.ca.read_bytes()).hexdigest() if self.ca.is_file() else None
        )
        if not self.root.is_dir() or not self.ca.is_file() or not callable(self.policy):
            reject("DEVICE_PINNED_TRUST_REQUIRED")

    def __call__(self, cms):
        return self.verify(cms)

    def verify(self, cms):
        if not isinstance(cms, bytes) or not cms or len(cms) > 65536:
            reject("DEVICE_CMS_LIMIT")
        with tempfile.TemporaryDirectory(prefix="device-cms-", dir=self.root) as td:
            source = pathlib.Path(td) / "input.cms"
            source.write_bytes(cms)
            signer = pathlib.Path(td) / "signer.pem"
            result = self.run(
                [
                    self.openssl,
                    "cms",
                    "-verify",
                    "-verify_retcode",
                    "-inform",
                    "DER",
                    "-in",
                    str(source),
                    "-binary",
                    "-CAfile",
                    str(self.ca),
                    "-no-CApath",
                    "-no-CAstore",
                    "-purpose",
                    "any",
                    "-signer",
                    str(signer),
                ],
                cwd=str(self.root),
                timeout=30,
            )
            content = result["stdout"]
            if len(content) > 65536:
                reject("DEVICE_PAYLOAD_LIMIT")
            payload = plistlib.loads(content)
            if (
                not isinstance(payload, dict)
                or not {"CHALLENGE", "UDID"} <= set(payload)
                or not set(payload) <= {"CHALLENGE", "UDID", "PRODUCT", "VERSION"}
                or any(not isinstance(v, str) or not v for v in payload.values())
            ):
                reject("DEVICE_PAYLOAD_INVALID")
            if (
                len(payload["CHALLENGE"]) > 1024
                or not re.fullmatch(
                    r"(?:[A-Fa-f0-9]{40}|[A-Fa-f0-9]{8}-[A-Fa-f0-9]{16})", payload["UDID"]
                )
                or (
                    "PRODUCT" in payload
                    and not re.fullmatch(r"iPhone[0-9]{1,3},[0-9]{1,3}", payload["PRODUCT"])
                )
                or (
                    "VERSION" in payload
                    and not re.fullmatch(r"[0-9]+(?:\.[0-9]+){0,2}", payload["VERSION"])
                )
            ):
                reject("DEVICE_PAYLOAD_INVALID")
            pem = one_pem_certificate(signer.read_bytes())
            der = self.run(
                [self.openssl, "x509", "-outform", "DER"],
                cwd=str(self.root),
                timeout=30,
                input_bytes=pem,
            )["stdout"]
            if self.policy(der, payload["UDID"]) is not True:
                reject("DEVICE_LEAF_POLICY_REJECTED")
            return {
                "challenge": payload["CHALLENGE"],
                "udid": payload["UDID"],
                **({"product": payload["PRODUCT"]} if "PRODUCT" in payload else {}),
                **({"version": payload["VERSION"]} if "VERSION" in payload else {}),
                "signatureVerified": True,
                "issuerTrusted": True,
                "deviceCertificate": hashlib.sha256(der).hexdigest(),
            }
