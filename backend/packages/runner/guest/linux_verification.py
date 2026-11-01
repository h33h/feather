"""Independent strict zsign output verifier; signer exit status is not evidence."""

import hashlib, importlib.util, pathlib, plistlib, struct, tempfile, re

bounded = None
import guest.verification as v

bounded = v.analyzer.bounded
SIGNED_EXPANSION = 512 << 20
MAX_RESOURCE_ENVELOPE = 64 << 20

# Accept only the pinned driver's rules. Hashes alone do not show that Apple's
# resource scanner will actually visit a sealed file (notably root PkgInfo).
RESOURCE_RULES = {
    "^.*": True,
    r"^.*\.lproj/": {"optional": True, "weight": 1000.0},
    r"^Base\.lproj/": {"weight": 1010.0},
    "^version.plist$": True,
}
RESOURCE_RULES2 = {
    "^.*": True,
    r".*\.dSYM($|/)": {"weight": 11.0},
    r"^(.*/)?\.DS_Store$": {"omit": True, "weight": 2000.0},
    r"^.*\.lproj/": {"optional": True, "weight": 1000.0},
    r"^Base\.lproj/": {"weight": 1010.0},
    r"^Info\.plist$": {"omit": True, "weight": 20.0},
    "^PkgInfo$": {"omit": True, "weight": 20.0},
    r"^embedded\.provisionprofile$": {"weight": 20.0},
    r"^version\.plist$": {"weight": 20.0},
}


def reject(code):
    raise ValueError(code)


def be(*values):
    return struct.pack(">" + "I" * len(values), *values)


def blob(magic, data):
    return be(magic, len(data) + 8) + data


def der(tag, data):
    size = len(data)
    encoded = (
        bytes([size])
        if size < 128
        else bytes([128 + (size.bit_length() + 7) // 8])
        + size.to_bytes((size.bit_length() + 7) // 8, "big")
    )
    return bytes([tag]) + encoded + data


def entitlement_der(value):
    if not v.entitlement_policy.safe_value(value):
        reject("DER_ENTITLEMENT_UNSUPPORTED")

    def encode(current):
        if type(current) is bool:
            return der(1, b"\xff" if current else b"\0")
        if type(current) is int:
            length = max(1, (current.bit_length() + 8) // 8)
            raw = current.to_bytes(length, "big", signed=True)
            while len(raw) > 1 and (
                raw[:1] == b"\0" and raw[1] < 128 or raw[:1] == b"\xff" and raw[1] >= 128
            ):
                raw = raw[1:]
            return der(2, raw)
        if isinstance(current, str):
            return der(12, current.encode())
        if isinstance(current, list):
            return der(48, b"".join(encode(e) for e in current))
        return der(176, b"".join(der(48, encode(k) + encode(current[k])) for k in sorted(current)))

    return encode(value)


def requirement(identifier, cn):
    def padded(data):
        if isinstance(data, str):
            data = data.encode()
        return be(len(data)) + data + b"\0" * ((-len(data)) % 4)

    expression = (
        be(1, 6, 2)
        + padded(identifier)
        + be(6, 15, 6, 11, 0)
        + padded("subject.CN")
        + be(1)
        + padded(cn)
        + be(14, 1)
        + padded(bytes.fromhex("2a864886f76364060201"))
        + be(0)
    )
    inner = blob(0xFADE0C00, expression)
    return be(0xFADE0C01, len(inner) + 20, 1, 3, 20) + inner


def cms_directory_attributes(cms, directory):
    # Strict DER navigation; hashes must be signed attributes of the sole signer.
    def node(data, offset=0):
        if offset + 2 > len(data):
            reject("CMS_DER_TRUNCATED")
        tag = data[offset]
        size = data[offset + 1]
        start = offset + 2
        if size & 128:
            count = size & 127
            if not 1 <= count <= 4 or start + count > len(data) or data[start] == 0:
                reject("CMS_DER_LENGTH")
            size = int.from_bytes(data[start : start + count], "big")
            start += count
            if size < 128:
                reject("CMS_DER_LENGTH")
        end = start + size
        if end > len(data):
            reject("CMS_DER_TRUNCATED")
        return tag, data[start:end], end

    def children(data):
        result = []
        offset = 0
        while offset < len(data):
            tag, value, end = node(data, offset)
            result.append((tag, value))
            offset = end
        return result

    tag, outer, end = node(cms)
    if tag != 48 or end != len(cms):
        reject("CMS_DER_INVALID")
    outer = children(outer)
    if (
        len(outer) != 2
        or outer[0] != (6, bytes.fromhex("2a864886f70d010702"))
        or outer[1][0] != 160
    ):
        reject("CMS_SIGNED_DATA_REQUIRED")
    tag, signed, end = node(outer[1][1])
    if tag != 48 or end != len(outer[1][1]):
        reject("CMS_SIGNED_DATA_REQUIRED")
    parts = children(signed)
    if len(parts) < 4 or parts[-1][0] != 49:
        reject("CMS_SIGNERS_REQUIRED")
    signers = children(parts[-1][1])
    if len(signers) != 1 or signers[0][0] != 48:
        reject("CMS_SINGLE_SIGNER_REQUIRED")
    signer = children(signers[0][1])
    if len(signer) < 6 or signer[3][0] != 160:
        reject("CMS_SIGNED_ATTRIBUTES_REQUIRED")
    attributes = {}
    for tag, value in children(signer[3][1]):
        fields = children(value)
        if (
            tag != 48
            or len(fields) != 2
            or fields[0][0] != 6
            or fields[1][0] != 49
            or fields[0][1] in attributes
        ):
            reject("CMS_ATTRIBUTES_INVALID")
        attributes[fields[0][1]] = children(fields[1][1])
    digest = hashlib.sha256(directory).digest()
    agility = attributes.get(bytes.fromhex("2a864886f763640902"))
    expected = der(6, bytes.fromhex("608648016503040201")) + der(4, digest)
    if agility != [(48, expected)]:
        reject("CMS_DIRECTORY_AGILITY_MISMATCH")
    hashes = attributes.get(bytes.fromhex("2a864886f763640901"))
    if not hashes or len(hashes) != 1 or hashes[0][0] != 4:
        reject("CMS_DIRECTORY_HASHES_REQUIRED")
    try:
        plist = plistlib.loads(hashes[0][1])
    except Exception:
        reject("CMS_DIRECTORY_HASHES_INVALID")
    if plist != {"cdhashes": [digest[:20]]}:
        reject("CMS_DIRECTORY_HASHES_MISMATCH")


def macho_signature(raw):
    if len(raw) < 32 or raw[:4] != b"\xcf\xfa\xed\xfe":
        reject("SIGNED_MACHO_UNSUPPORTED")
    cpu, subtype, filetype, count, size = struct.unpack_from("<IIIII", raw, 4)
    if cpu != 0x100000C or count > 10000 or 32 + size > len(raw):
        reject("SIGNED_MACHO_HEADER_INVALID")
    position = 32
    signature = None
    for _ in range(count):
        if position + 8 > 32 + size:
            reject("SIGNED_LOAD_COMMAND_INVALID")
        command, length = struct.unpack_from("<II", raw, position)
        if length < 8 or length % 8 or position + length > 32 + size:
            reject("SIGNED_LOAD_COMMAND_INVALID")
        if command == 0x1D:
            if length != 16 or signature is not None:
                reject("SIGNED_SIGNATURE_COMMAND_INVALID")
            signature = struct.unpack_from("<II", raw, position + 8)
        position += length
    if position != 32 + size or not signature:
        reject("SIGNATURE_REQUIRED")
    offset, length = signature
    if offset < position or not 12 <= length <= 32 << 20 or offset + length != len(raw):
        reject("SIGNATURE_BOUNDS_INVALID")
    signature = raw[offset:]
    magic, total, count = struct.unpack_from(">III", signature)
    if (
        magic != 0xFADE0CC0
        or total > length
        or total < 12 + 8 * count
        or count > 10
        or any(signature[total:])
    ):
        reject("SIGNATURE_CONTAINER_INVALID")
    entries = {}
    intervals = []
    for index in range(count):
        slot, start = struct.unpack_from(">II", signature, 12 + index * 8)
        if (
            slot in entries
            or slot not in (0, 2, 5, 7, 0x10000)
            or start < 12 + count * 8
            or start + 8 > total
        ):
            reject("SIGNATURE_SLOT_INVALID")
        magic, size = struct.unpack_from(">II", signature, start)
        expected_magic = {
            0: 0xFADE0C02,
            2: 0xFADE0C01,
            5: 0xFADE7171,
            7: 0xFADE7172,
            0x10000: 0xFADE0B01,
        }[slot]
        if magic != expected_magic:
            reject("SIGNATURE_SLOT_MAGIC_INVALID")
        if (
            size < 8
            or start + size > total
            or any(start < b and a < start + size for a, b in intervals)
        ):
            reject("SIGNATURE_SLOT_BOUNDS_INVALID")
        intervals.append((start, start + size))
        entries[slot] = signature[start : start + size]
    if intervals and (
        sorted(intervals)[0][0] != 12 + count * 8
        or sorted(intervals)[-1][1] != total
        or any(left[1] != right[0] for left, right in zip(sorted(intervals), sorted(intervals)[1:]))
    ):
        reject("SIGNATURE_UNINDEXED_DATA")
    if 0x10000 in entries and struct.unpack_from(">I", entries[0x10000])[0] != 0xFADE0B01:
        reject("CMS_WRAPPER_INVALID")
    if not {0, 2, 0x10000} <= set(entries):
        reject("SIGNATURE_SLOT_MISSING")
    return offset, filetype, entries


def verify_directory(raw, offset, entries, component, info, resources, team, cn):
    directory = entries[0]
    if len(directory) < 52:
        reject("CODEDIRECTORY_INVALID")
    magic, length, version, flags, hashoffset, identoffset, special, pages, limit = (
        struct.unpack_from(">9I", directory)
    )
    hashsize, hashtype, platform, pagesize = struct.unpack_from("4B", directory, 36)
    if (
        magic != 0xFADE0C02
        or length != len(directory)
        or version != 0x20400
        or flags != 0
        or hashsize != 32
        or hashtype != 2
        or platform != 0
        or pagesize != 12
        or special > 7
        or limit != offset
        or pages != (limit + 4095) // 4096
        or hashoffset - special * 32 < 88
        or hashoffset + pages * 32 != length
        or struct.unpack_from(">I", directory, 44)[0] != 0
    ):
        reject("CODEDIRECTORY_POLICY_MISMATCH")

    def string(start):
        end = directory.find(b"\0", start)
        if (
            not 88 <= start < hashoffset - special * 32
            or not start < end < hashoffset - special * 32
        ):
            reject("CODEDIRECTORY_STRING_INVALID")
        return directory[start:end].decode("utf8")

    if (
        identoffset != 88
        or struct.unpack_from(">I", directory, 40)[0] != 0
        or struct.unpack_from(">I", directory, 52)[0] != 0
        or struct.unpack_from(">Q", directory, 56)[0] != 0
    ):
        reject("CODEDIRECTORY_HEADER_LAYOUT_INVALID")
    if (
        string(identoffset) != component["bundleId"]
        or string(struct.unpack_from(">I", directory, 48)[0]) != team
    ):
        reject("CODEDIRECTORY_IDENTITY_MISMATCH")
    teamoffset = struct.unpack_from(">I", directory, 48)[0]
    if (
        teamoffset != 88 + len(component["bundleId"].encode()) + 1
        or hashoffset - special * 32 != teamoffset + len(team.encode()) + 1
    ):
        reject("CODEDIRECTORY_HASH_LAYOUT_INVALID")
    position = 32
    text_limit = None
    for _ in range(struct.unpack_from("<I", raw, 16)[0]):
        command, size = struct.unpack_from("<II", raw, position)
        if command == 0x19 and raw[position + 8 : position + 24].rstrip(b"\0") == b"__TEXT":
            if text_limit is not None:
                reject("DUPLICATE_TEXT_SEGMENT")
            text_limit = struct.unpack_from("<Q", raw, position + 32)[0]
        position += size
    if text_limit is None or struct.unpack_from(">QQQ", directory, 64) != (
        0,
        text_limit,
        1 if component["kind"] in ("app", "appex") else 0,
    ):
        reject("CODEDIRECTORY_EXEC_SEGMENT_MISMATCH")
    for page in range(pages):
        if (
            directory[hashoffset + page * 32 : hashoffset + (page + 1) * 32]
            != hashlib.sha256(raw[page * 4096 : min((page + 1) * 4096, limit)]).digest()
        ):
            reject("EXECUTABLE_PAGE_HASH_MISMATCH")
    ent = component["entitlements"]
    expected = {2: entries[2]}
    if component["kind"] != "dylib":
        expected.update({1: info, 3: resources})
    if entries[2] != requirement(component["bundleId"], cn):
        reject("DESIGNATED_REQUIREMENT_MISMATCH")
    if ent:
        if (
            5 not in entries
            or not v.entitlement_policy.exact(plistlib.loads(entries[5][8:]), ent)
            or struct.unpack_from(">I", entries[5])[0] != 0xFADE7171
        ):
            reject("SIGNED_ENTITLEMENTS_MISMATCH")
        expected[5] = entries[5]
        if 7 not in entries:
            reject("SIGNED_DER_ENTITLEMENTS_REQUIRED")
        if 7 in entries:
            if entries[7] != blob(0xFADE7172, der(112, b"\x02\x01\x01" + entitlement_der(ent))):
                reject("SIGNED_DER_ENTITLEMENTS_MISMATCH")
            expected[7] = entries[7]
    else:
        if 7 in entries:
            reject("FRAMEWORK_ENTITLEMENTS_REJECTED")
        if 5 in entries:
            if (
                struct.unpack_from(">I", entries[5])[0] != 0xFADE7171
                or plistlib.loads(entries[5][8:]) != {}
            ):
                reject("FRAMEWORK_ENTITLEMENTS_REJECTED")
            expected[5] = entries[5]
    for slot in range(1, special + 1):
        actual = directory[hashoffset - slot * 32 : hashoffset - (slot - 1) * 32]
        wanted = hashlib.sha256(expected[slot]).digest() if slot in expected else b"\0" * 32
        if actual != wanted:
            reject("SPECIAL_SLOT_HASH_MISMATCH")
    if any(slot > special for slot in expected):
        reject("SPECIAL_SLOT_MISSING")
    return {
        "cdhash": hashlib.sha256(directory).digest()[:20],
        "directory": directory,
        "cms": entries[0x10000][8:],
    }


class LinuxVerifier(v.GuestVerifier):
    def signing_chain_pem(self):
        from cryptography.hazmat.primitives import serialization

        chain = getattr(self.apple_certificate_policy, "chain", None)
        if not isinstance(chain, list) or not 1 <= len(chain) <= 5:
            reject("PINNED_SIGNING_CHAIN_REQUIRED")
        pem = b"".join(cert.public_bytes(serialization.Encoding.PEM) for cert in chain)
        if not pem or len(pem) > 327680:
            reject("PINNED_SIGNING_CHAIN_LIMIT")
        return pem

    signed_unpacked_limit = v.analyzer.MAX_UNPACKED + SIGNED_EXPANSION

    def __init__(self, *args, **kwargs):
        if not callable(kwargs.get("apple_certificate_policy")):
            reject("LINUX_PINNED_CERTIFICATE_POLICY_REQUIRED")
        super().__init__(*args, **kwargs)

    def verify_component(self, path, component, task, grant):
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        path = pathlib.Path(path)
        standalone = component["kind"] == "dylib"
        info_raw = resources = info = None
        if standalone:
            binary = path
        else:
            info_raw = bounded.read_bounded(path / "Info.plist", v.analyzer.MAX_METADATA)
            info = plistlib.loads(info_raw)
            if info["CFBundleIdentifier"] != component["bundleId"]:
                reject("SIGNED_BUNDLE_ID_MISMATCH")
            executable = info.get("CFBundleExecutable")
            if (
                not isinstance(executable, str)
                or not executable
                or len(executable.encode("utf8")) > 255
                or any(character in executable for character in ("/", "\\", ":", "\0"))
                or executable in (".", "..")
            ):
                reject("SIGNED_EXECUTABLE_INVALID")
            binary = path / executable
        raw = bounded.read_bounded(binary, v.analyzer.MAX_SIGNED_BINARY)
        offset, filetype, entries = macho_signature(raw)
        if not standalone:
            resources = bounded.read_bounded(
                path / "_CodeSignature/CodeResources", MAX_RESOURCE_ENVELOPE
            )
        if standalone and (
            filetype != 6 or component["entitlements"] or component["profileRequired"]
        ):
            reject("SIGNED_DYLIB_METADATA_MISMATCH")
        if self.leaf_der is None:
            reject("VERIFIED_LEAF_REQUIRED")
        cert = x509.load_der_x509_certificate(self.leaf_der)
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if len(cn) != 1:
            reject("CERTIFICATE_CN_REQUIRED")
        evidence = verify_directory(
            raw,
            offset,
            entries,
            component,
            info_raw,
            resources,
            task["identity"]["teamId"],
            cn[0].value,
        )
        cms_directory_attributes(evidence["cms"], evidence["directory"])
        with tempfile.TemporaryDirectory(prefix="verify-linux-cms-", dir=self.root) as td:
            cms = pathlib.Path(td) / "signature.der"
            content = pathlib.Path(td) / "directory.bin"
            signer = pathlib.Path(td) / "signer.pem"
            cms.write_bytes(evidence["cms"])
            content.write_bytes(evidence["directory"])
            verified = self.openssl_command(
                [
                    "cms",
                    "-verify",
                    "-verify_retcode",
                    "-inform",
                    "DER",
                    "-in",
                    str(cms),
                    "-binary",
                    "-content",
                    str(content),
                    "-noverify",
                    "-signer",
                    str(signer),
                ]
            )
            if (
                verified != evidence["directory"]
                or self.certificate(v.one_pem_certificate(signer.read_bytes()), task["identity"])
                != self.leaf_der
            ):
                reject("SIGNATURE_CMS_IDENTITY_MISMATCH")
        metadata = v.analyzer.macho(raw, allow_verified_der=True)
        if any(metadata[k] != component[k] for k in ("architectures", "platform", "encrypted")):
            reject("SIGNED_PLATFORM_MISMATCH")
        version = lambda text: tuple(int(part) for part in (text.split(".") + ["0", "0"])[:3])
        if standalone:
            if version(metadata["binaryMinOs"]) != version(component["minOs"]):
                reject("SIGNED_MIN_OS_MISMATCH")
        else:
            if version(metadata["binaryMinOs"]) > version(component["minOs"]) or version(
                info["MinimumOSVersion"]
            ) != version(component["minOs"]):
                reject("SIGNED_MIN_OS_MISMATCH")
            self.verify_resources(path, info, resources)
        if component["profileRequired"]:
            expected = task["profiles"][component["bundleId"]]
            profile_path = path / "embedded.mobileprovision"
            if bounded.digests(profile_path)[0].hex() != expected["cmsSha256"]:
                reject("EMBEDDED_PROFILE_DIGEST_MISMATCH")
            v.validate_profile(
                self.decode_profile(profile_path),
                expected,
                task["udid"],
                self.leaf_der,
                self.clock(),
            )
        return {k: True for k in v.executor.REQUIRED_VERIFICATION}

    def verify_resources(self, path, info, raw):
        document = plistlib.loads(raw)
        if not isinstance(document, dict) or set(document) != {
            "files",
            "files2",
            "rules",
            "rules2",
        }:
            reject("RESOURCE_ENVELOPE_UNSUPPORTED")
        if document["rules"] != RESOURCE_RULES or document["rules2"] != RESOURCE_RULES2:
            reject("RESOURCE_RULES_MISMATCH")
        if not isinstance(document["files"], dict) or not isinstance(document["files2"], dict):
            reject("RESOURCE_ENVELOPE_UNSUPPORTED")
        actual = {str(p.relative_to(path)): p for p in path.rglob("*") if p.is_file()}
        if any(p.is_symlink() for p in path.rglob("*")):
            reject("RESOURCE_SYMLINK_REJECTED")
        actual.pop("_CodeSignature/CodeResources", None)
        actual.pop(info["CFBundleExecutable"], None)
        if any(pathlib.PurePosixPath(name).name.endswith(".DS_Store") for name in actual):
            reject("RESOURCE_FINDER_METADATA")
        if set(document["files2"]) != set(actual) - {"Info.plist", "PkgInfo"}:
            reject("RESOURCE_INVENTORY_MISMATCH")
        if set(document["files"]) != set(actual):
            reject("LEGACY_RESOURCE_INVENTORY_MISMATCH")
        for relative, p in actual.items():
            if relative in ("Info.plist", "PkgInfo"):
                continue
            entry = document["files2"].get(relative)
            sha256, sha1 = bounded.digests(p, ("sha256", "sha1"))
            if (
                not isinstance(entry, dict)
                or set(entry) - {"hash", "hash2", "optional"}
                or entry.get("hash2") != sha256
                or ("hash" in entry and entry["hash"] != sha1)
            ):
                reject("RESOURCE_HASH_MISMATCH")
        if set(document["files2"]) - set(actual):
            reject("RESOURCE_MISSING")
        for relative, entry in document["files"].items():
            if relative not in actual:
                reject("LEGACY_RESOURCE_MISSING")
            digest = (
                entry
                if isinstance(entry, bytes)
                else entry.get("hash")
                if isinstance(entry, dict)
                else None
            )
            if digest != bounded.digests(actual[relative], ("sha1",))[0]:
                reject("LEGACY_RESOURCE_HASH_MISMATCH")
