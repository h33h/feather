"""Independent guest verification of source materials and CMS using pinned OpenSSL 3.

Only instantiate with a proof-gated NativeGuestRunner, never host subprocesses.
"""

import datetime, hashlib, importlib.util, io, pathlib, plistlib, re, shutil, tempfile, time, zipfile
import contextlib, copy, os

from verification_core.certificates import (
    fingerprint as fingerprint,
    one_pem_certificate as one_pem_certificate,
    parse_cert_dates as parse_cert_dates,
)

import guest.executor as executor
from guest import entitlement_policy as entitlement_policy

analyzer = executor._analyzer


def reject(code):
    raise ValueError(code)


profile_identifier_permits = entitlement_policy.profile_identifier_permits


def profile_entitlement_ceiling(raw, prefix, bundle_id, team_id):
    from guest.entitlements import json_entitlements

    if not isinstance(raw, dict):
        reject("PROFILE_ENTITLEMENTS_MISMATCH")
    ceiling = json_entitlements(raw)
    entitlement_policy.identity_entitlements(
        {
            "prefix": prefix,
            "bundleId": bundle_id,
            "teamId": team_id,
            "entitlements": ceiling,
        }
    )
    return ceiling


def validate_profile(profile, expected, udid, certificate_der, now):
    if not isinstance(profile, dict) or not isinstance(
        profile.get("ExpirationDate"), datetime.datetime
    ):
        reject("PROFILE_INVALID")
    expiry = int(profile["ExpirationDate"].replace(tzinfo=datetime.timezone.utc).timestamp() * 1000)
    if (
        expiry != expected["expiresAt"]
        or expiry <= now
        or profile.get("TeamIdentifier") != [expected["teamId"]]
        or profile.get("ApplicationIdentifierPrefix") != [expected["prefix"]]
        or not entitlement_policy.exact(
            profile_entitlement_ceiling(
                profile.get("Entitlements"),
                expected["prefix"],
                expected["bundleId"],
                expected["teamId"],
            ),
            expected["entitlements"],
        )
        or profile.get("ProvisionsAllDevices", False) is not False
    ):
        reject("PROFILE_EXACT_MISMATCH")
    devices = profile.get("ProvisionedDevices")
    if (
        not isinstance(devices, list)
        or len(devices) != len(set(devices))
        or set(devices) != set(expected["udids"])
        or udid not in devices
    ):
        reject("PROFILE_DEVICE_MISMATCH")
    certs = profile.get("DeveloperCertificates")
    if (
        not isinstance(certs, list)
        or not certs
        or any(not isinstance(c, bytes) for c in certs)
        or certs != [certificate_der]
        or fingerprint(certificate_der, expected["fingerprint"]) != expected["fingerprint"]
    ):
        reject("PROFILE_CERTIFICATE_MISMATCH")
    entitlement_policy.identity_entitlements(expected)


class GuestVerifier:
    def __init__(
        self,
        workspace,
        command_runner,
        *,
        openssl_path,
        ca_file,
        intermediate_file,
        cms_signer_fingerprints,
        apple_certificate_policy=None,
        clock=lambda: int(time.time() * 1000),
    ):
        self.root = pathlib.Path(workspace).resolve()
        self.run = command_runner
        self.openssl = openssl_path
        self.ca = pathlib.Path(ca_file).resolve()
        self.intermediate = pathlib.Path(intermediate_file).resolve()
        self.cms_signers = set(cms_signer_fingerprints)
        self.clock = clock
        self.leaf_der = None
        self._execute_analysis = None
        self.apple_certificate_policy = apple_certificate_policy
        if (
            not self.cms_signers
            or any(not re.fullmatch("[a-f0-9]{64}", p) for p in self.cms_signers)
            or not self.ca.is_file()
            or not self.intermediate.is_file()
        ):
            reject("PINNED_TRUST_REQUIRED")

    def _source_stamp(self, stream):
        stamp = analyzer.file_stamp(os.fstat(stream.fileno()))
        if analyzer.file_stamp(os.stat(self.root / "source.ipa", follow_symlinks=False)) != stamp:
            reject("SOURCE_CHANGED")
        return stamp

    def _check_source(self, stream, digest, size=None, stamp=None):
        before = self._source_stamp(stream)
        if before[3] > analyzer.MAX_INPUT or (size is not None and before[3] != size):
            reject("SOURCE_SIZE_MISMATCH")
        if stamp is not None and before != stamp:
            reject("SOURCE_CHANGED")
        stream.seek(0)
        hashed = hashlib.sha256()
        count = 0
        for block in iter(lambda: stream.read(analyzer.bounded.CHUNK), b""):
            count += len(block)
            if count > analyzer.MAX_INPUT:
                reject("SOURCE_SIZE_MISMATCH")
            hashed.update(block)
        if self._source_stamp(stream) != before:
            reject("SOURCE_CHANGED")
        if count != before[3]:
            reject("SOURCE_SIZE_MISMATCH")
        if hashed.hexdigest() != digest:
            reject("SOURCE_DIGEST_MISMATCH")
        stream.seek(0)
        return before

    @contextlib.contextmanager
    def execute_analysis(self, analysis, grant, size):
        """Private guest-computed metadata, valid for one execute call only."""
        if getattr(self, "_execute_analysis", None) is not None:
            reject("SOURCE_ANALYSIS_ALREADY_BOUND")
        if not isinstance(analysis, dict) or analysis.get("sha256") != grant["uploadDigest"]:
            reject("SOURCE_DIGEST_MISMATCH")
        if type(size) is not int or not 0 < size <= analyzer.MAX_INPUT:
            reject("SOURCE_SIZE_MISMATCH")
        with analyzer.bounded.open_regular(self.root / "source.ipa") as stream:
            stamp = self._check_source(stream, grant["uploadDigest"], size)
            self._execute_analysis = {
                "analysis": copy.deepcopy(analysis),
                "binding": executor.canonical_digest(grant),
                "source": stream,
                "stamp": stamp,
                "size": size,
                "used": False,
            }
            try:
                yield stream
            finally:
                self._execute_analysis = None

    def command(self, args, input_bytes=None):
        result = self.run(args, cwd=str(self.root), timeout=120, input_bytes=input_bytes)
        return result["stdout"]

    def openssl_command(self, args, input_bytes=None):
        return self.command([self.openssl, *args], input_bytes)

    def decode_profile(self, path):
        path = pathlib.Path(path)
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1 << 20:
            reject("PROFILE_MATERIAL_INVALID")
        with tempfile.TemporaryDirectory(prefix="verify-cms-", dir=self.root) as td:
            signer = pathlib.Path(td) / "signer.pem"
            content = self.openssl_command(
                [
                    "cms",
                    "-verify",
                    "-verify_retcode",
                    "-inform",
                    "DER",
                    "-in",
                    str(path),
                    "-binary",
                    "-CAfile",
                    str(self.ca),
                    "-no-CApath",
                    "-no-CAstore",
                    "-purpose",
                    "any",
                    "-signer",
                    str(signer),
                ]
            )
            if len(content) > analyzer.MAX_METADATA:
                reject("PROFILE_LIMIT")
            signer_pem = one_pem_certificate(signer.read_bytes())
            der = self.openssl_command(["x509", "-outform", "DER"], signer_pem)
            if hashlib.sha256(der).hexdigest() not in self.cms_signers:
                reject("CMS_SIGNER_UNTRUSTED")
            return plistlib.loads(content)

    def certificate(self, pem, identity):
        pem = one_pem_certificate(pem)
        der = self.openssl_command(["x509", "-outform", "DER"], pem)
        if fingerprint(der, identity["fingerprint"]) != identity["fingerprint"]:
            reject("LEAF_IDENTITY_MISMATCH")
        start, expiry = parse_cert_dates(
            self.openssl_command(["x509", "-noout", "-startdate", "-enddate"], pem)
        )
        if start > self.clock() or expiry <= self.clock() or expiry != identity["expiresAt"]:
            reject("CERTIFICATE_EXPIRY_MISMATCH")
        subject = (
            self.openssl_command(["x509", "-noout", "-subject", "-nameopt", "RFC2253"], pem)
            .decode("utf8")
            .strip()
        )
        units = re.findall(r"(?:^|,)OU=([^,]+)", subject.removeprefix("subject="))
        if units != [identity["teamId"]]:
            reject("CERTIFICATE_TEAM_MISMATCH")
        if self.apple_certificate_policy is not None:
            if (
                not callable(self.apple_certificate_policy)
                or self.apple_certificate_policy(der, identity) is not True
            ):
                reject("APPLE_CERTIFICATE_POLICY_REJECTED")
        else:
            with tempfile.TemporaryDirectory(prefix="verify-leaf-", dir=self.root) as td:
                leaf = pathlib.Path(td) / "leaf.pem"
                leaf.write_bytes(pem)
                self.openssl_command(
                    [
                        "verify",
                        "-CAfile",
                        str(self.ca),
                        "-untrusted",
                        str(self.intermediate),
                        "-no-CApath",
                        "-no-CAstore",
                        "-purpose",
                        "any",
                        str(leaf),
                    ]
                )
        return der

    def verify_materials(self, task, root, grant, *, pkcs12_password):
        executor.validate_plan(task, grant, self.root, self.clock())
        identity = task["identity"]
        path = executor.guest_path(self.root, identity["materialPath"])
        password = (pkcs12_password + "\n").encode("utf8")
        cert = self.openssl_command(
            ["pkcs12", "-in", str(path), "-passin", "stdin", "-clcerts", "-nokeys"], password
        )
        key = self.openssl_command(
            ["pkcs12", "-in", str(path), "-passin", "stdin", "-nocerts", "-nodes"], password
        )
        if len(re.findall(rb"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----", key)) != 1:
            reject("PRIVATE_KEY_COUNT_INVALID")
        public_key = self.openssl_command(["pkey", "-pubout", "-outform", "DER"], key)
        public_cert = self.openssl_command(
            ["pkey", "-pubin", "-pubout", "-outform", "DER"],
            self.openssl_command(["x509", "-pubkey", "-noout"], one_pem_certificate(cert)),
        )
        key = b""
        password = b""
        if not public_key or public_key != public_cert:
            reject("CERTIFICATE_KEY_MISMATCH")
        self.leaf_der = self.certificate(cert, identity)
        for expected in task["profiles"].values():
            validate_profile(
                self.decode_profile(executor.guest_path(self.root, expected["materialPath"])),
                expected,
                task["udid"],
                self.leaf_der,
                self.clock(),
            )
        source = self.root / "source.ipa"
        if (
            source.is_symlink()
            or not source.is_file()
            or source.stat().st_size > analyzer.MAX_INPUT
        ):
            reject("SOURCE_ARCHIVE_REQUIRED")
        with contextlib.ExitStack() as stack:
            cached = getattr(self, "_execute_analysis", None)
            if cached is not None:
                if cached["used"]:
                    reject("SOURCE_ANALYSIS_ALREADY_USED")
                cached["used"] = True
                if cached["binding"] != executor.canonical_digest(grant):
                    reject("SOURCE_ANALYSIS_BINDING_MISMATCH")
                stream = cached["source"]
                stack.callback(stream.close)
                stamp = self._check_source(
                    stream, grant["uploadDigest"], cached["size"], cached["stamp"]
                )
                analysis = cached["analysis"]
            else:
                analysis = analyzer.analyze_file(source)
                stream = stack.enter_context(analyzer.bounded.open_regular(source))
                stamp = self._check_source(stream, grant["uploadDigest"])
            if analysis["sha256"] != grant["uploadDigest"]:
                reject("SOURCE_DIGEST_MISMATCH")
            removed = analysis.get("removedExtensions", [])
            if task.get("removedExtensions", []) != removed:
                reject("SOURCE_REMOVALS_MISMATCH")
            expected = {c["path"]: c for c in task["components"]}
            if set(expected) != {c["path"] for c in analysis["components"]}:
                reject("SOURCE_GRAPH_MISMATCH")
            for component in analysis["components"]:
                planned = expected[component["path"]]
                if not entitlement_policy.exact(
                    component["entitlements"], planned.get("sourceEntitlements", {})
                ):
                    reject("SOURCE_ENTITLEMENTS_MISMATCH")
                if component["bundleId"] != planned.get(
                    "sourceBundleId", planned["bundleId"]
                ) or any(
                    component[k] != planned[k]
                    for k in ("kind", "architectures", "platform", "encrypted", "minOs")
                ):
                    reject("SOURCE_COMPONENT_MISMATCH")
            with zipfile.ZipFile(stream) as archive:
                files = {
                    e.filename
                    for e in archive.infolist()
                    if not e.is_dir()
                    and e.filename.startswith("Payload/")
                    and not any(e.filename.startswith(item["path"] + "/") for item in removed)
                }
                actual = {
                    str(p.relative_to(self.root))
                    for p in (self.root / "Payload").rglob("*")
                    if p.is_file()
                }
                if files != actual:
                    reject("STAGED_SOURCE_TREE_MISMATCH")
                for name in files:
                    path = executor.guest_path(self.root, name)
                    digest = hashlib.sha256()
                    with path.open("rb") as f:
                        for block in iter(lambda: f.read(1 << 20), b""):
                            digest.update(block)
                    packed = hashlib.sha256()
                    with archive.open(name) as f:
                        for block in iter(lambda: f.read(1 << 20), b""):
                            packed.update(block)
                    if digest.digest() != packed.digest():
                        reject("STAGED_SOURCE_BYTES_MISMATCH")
            if self._source_stamp(stream) != stamp:
                reject("SOURCE_CHANGED")
        return {k: True for k in executor.MATERIAL_VERIFICATION}

    def verify_archive(self, path, task, grant):
        path = pathlib.Path(path)
        if path.is_symlink() or path.stat().st_size > analyzer.MAX_INPUT:
            reject("ARCHIVE_LIMIT")
        analysis = analyzer.analyze_file(
            path,
            allow_verified_der=True,
            max_unpacked=getattr(self, "signed_unpacked_limit", analyzer.MAX_UNPACKED),
            max_entries=analyzer.MAX_ENTRIES + 2 * len(task["components"])
            if hasattr(self, "signed_unpacked_limit")
            else None,
        )
        planned = {c["path"]: c for c in task["components"]}
        if set(planned) != {c["path"] for c in analysis["components"]}:
            reject("ARCHIVE_GRAPH_MISMATCH")
        for actual in analysis["components"]:
            expected = planned[actual["path"]]
            if any(
                actual[k] != expected[k]
                for k in ("bundleId", "kind", "architectures", "platform", "encrypted", "minOs")
            ):
                reject("ARCHIVE_METADATA_MISMATCH")
        with (
            tempfile.TemporaryDirectory(prefix="verify-archive-", dir=self.root) as td,
            zipfile.ZipFile(path) as archive,
        ):
            base = pathlib.Path(td)
            for entry in archive.infolist():
                if not entry.filename.startswith("Payload/"):
                    reject("ARCHIVE_EXTRA_ENTRY")
                destination = executor.guest_path(base, entry.filename.rstrip("/"))
                if entry.is_dir():
                    destination.mkdir(parents=True, exist_ok=True)
                    continue
                destination.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(entry) as source, destination.open("xb") as target:
                    shutil.copyfileobj(source, target, 1 << 20)
            for component in task["components"]:
                self.verify_component(base / component["path"], component, task, grant)
        return {k: True for k in executor.REQUIRED_VERIFICATION}


class DeviceProfileVerifier:
    """Guest-side actual CMS eligibility proof, never an enabled/provider flag."""

    def __init__(self, guest_verifier):
        self.verifier = guest_verifier

    def verify(self, cms, expected):
        if (
            not isinstance(cms, bytes)
            or not cms
            or len(cms) > 65536
            or not isinstance(expected, dict)
            or set(expected) != {"udid", "certificateSha256", "teamId", "bundleId"}
            or not re.fullmatch("[a-f0-9]{64}", str(expected["certificateSha256"]))
        ):
            reject("DEVICE_PROFILE_INPUT_INVALID")
        with tempfile.TemporaryDirectory(prefix="device-profile-", dir=self.verifier.root) as td:
            path = pathlib.Path(td) / "profile.cms"
            path.write_bytes(cms)
            profile = self.verifier.decode_profile(path)
        if (
            not isinstance(profile, dict)
            or profile.get("TeamIdentifier") != [expected["teamId"]]
            or profile.get("ProvisionsAllDevices", False) is not False
            or not isinstance(profile.get("ExpirationDate"), datetime.datetime)
        ):
            reject("DEVICE_PROFILE_SCOPE_MISMATCH")
        expires = int(
            profile["ExpirationDate"].replace(tzinfo=datetime.timezone.utc).timestamp() * 1000
        )
        devices = profile.get("ProvisionedDevices")
        certificates = profile.get("DeveloperCertificates")
        prefixes = profile.get("ApplicationIdentifierPrefix")
        ent = profile.get("Entitlements")
        if (
            expires <= self.verifier.clock()
            or not isinstance(devices, list)
            or not devices
            or any(not isinstance(v, str) or not v for v in devices)
            or len(devices) != len(set(devices))
            or expected["udid"] not in devices
            or not isinstance(certificates, list)
            or not certificates
            or any(not isinstance(c, bytes) or not c or len(c) > 65536 for c in certificates)
            or not isinstance(prefixes, list)
            or len(prefixes) != 1
            or not isinstance(prefixes[0], str)
            or not isinstance(ent, dict)
        ):
            reject("DEVICE_PROFILE_INELIGIBLE")
        if (
            not profile_identifier_permits(
                ent.get("application-identifier"), prefixes[0], expected["bundleId"]
            )
            or ent.get("com.apple.developer.team-identifier") != expected["teamId"]
            or ent.get("get-task-allow") is not False
        ):
            reject("DEVICE_PROFILE_ENTITLEMENTS_MISMATCH")
        ceiling = profile_entitlement_ceiling(
            ent, prefixes[0], expected["bundleId"], expected["teamId"]
        )
        hashes = [hashlib.sha256(c).hexdigest() for c in certificates]
        if len(hashes) != len(set(hashes)) or expected["certificateSha256"] not in hashes:
            reject("DEVICE_PROFILE_CERTIFICATE_MISMATCH")
        der = certificates[hashes.index(expected["certificateSha256"])]
        pem = self.verifier.openssl_command(["x509", "-inform", "DER", "-outform", "PEM"], der)
        _, cert_expiry = parse_cert_dates(
            self.verifier.openssl_command(["x509", "-noout", "-startdate", "-enddate"], pem)
        )
        identity = {
            "fingerprint": expected["certificateSha256"].upper(),
            "teamId": expected["teamId"],
            "expiresAt": cert_expiry,
        }
        if self.verifier.certificate(pem, identity) != der:
            reject("DEVICE_PROFILE_LEAF_MISMATCH")
        return {
            "digest": hashlib.sha256(cms).hexdigest(),
            "teamId": expected["teamId"],
            "bundleId": expected["bundleId"],
            "devices": devices,
            "certificates": hashes,
            "expiresAt": expires,
            "profileType": "ad-hoc",
            "entitlements": ceiling,
        }

    def envelope(self, cms, expected, binding, instance_id, proof_key):
        import hmac

        if (
            type(binding.get("expiresAt")) is not int
            or binding["expiresAt"] <= self.verifier.clock()
        ):
            reject("DEVICE_PROFILE_BINDING_EXPIRED")
        report = {
            "version": 1,
            "operation": "device-profile",
            "binding": binding,
            "instanceId": instance_id,
            "expected": expected,
            "value": self.verify(cms, expected),
        }
        return {
            "report": report,
            "attestation": hmac.new(
                proof_key,
                __import__("json")
                .dumps(
                    report,
                    sort_keys=True,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    allow_nan=False,
                )
                .encode("utf8"),
                hashlib.sha256,
            ).hexdigest(),
        }
