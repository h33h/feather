from protocol.grants import (
    BINDINGS,
    OPTIONAL_BINDINGS,
    binding_fields,
    validate_grant,
    reject,
    make_report,
)

"""Static IPA inspection. Production entry point is isolated CLI, never a web import."""
from xml.parsers.expat import ExpatError
import hashlib, io, json, math, os, plistlib, re, stat, struct, sys, time, zipfile, importlib.util, pathlib

import protocol.bounded_io as bounded
from guest.entitlements import (
    MAX_SIZE as MAX_ENTITLEMENTS_SIZE,
    decode_der,
    decode_plist,
    json_entitlements,
    typed_equal,
)

MAX_INPUT = 1 << 30
MAX_UNPACKED = 4 << 30
MAX_ENTRIES = 20000
MAX_METADATA = 4 << 20
MAX_BINARY = 512 << 20
MAX_SIGNED_BINARY = MAX_BINARY + (32 << 20)
MAX_ZIP_DIRECTORY = 32 << 20
# Adjunct UI/notification extensions can be omitted without removing the main app.
# Unknown and service-critical extension points (VPN, file providers, etc.) stay strict.
OPTIONAL_EXTENSION_POINTS = frozenset(
    {
        "com.apple.usernotifications.service",
        "com.apple.usernotifications.content-extension",
        "com.apple.widgetkit-extension",
        "com.apple.widget-extension",
        "com.apple.share-services",
        "com.apple.ui-services",
    }
)
MACHO_MAGIC = (
    b"\xcf\xfa\xed\xfe",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xfe\xed\xfa\xce",
    b"\xca\xfe\xba\xbe",
    b"\xca\xfe\xba\xbf",
    b"\xbe\xba\xfe\xca",
    b"\xbf\xba\xfe\xca",
)


def validate_resource_entry(name, head=b"", metadata=None):
    parts = name.rstrip("/").split("/")
    if any(part.endswith(".xpc") for part in parts):
        reject("UNMODELED_EXECUTABLE")
    if not any(part.endswith(".bundle") for part in parts):
        return
    if head in MACHO_MAGIC:
        reject("UNMODELED_EXECUTABLE")
    if len(parts) > 1 and parts[-1] == "Info.plist" and parts[-2].endswith(".bundle"):
        if not isinstance(metadata, bytes) or len(metadata) > MAX_METADATA:
            return
        try:
            info = plistlib.loads(metadata)
        except (plistlib.InvalidFileException, ExpatError, ValueError):
            # Resource metadata is opaque data, never application identity.
            # Recognize common declarations without requiring a plist dialect.
            try:
                info = json.loads(metadata)
            except (ValueError, UnicodeError):
                # OpenStep and other resource encodings stay opaque. Native
                # bytes are independently rejected regardless of metadata.
                return
        if isinstance(info, dict) and "CFBundleExecutable" in info:
            reject("UNMODELED_EXECUTABLE")


ALLOWED = {
    "application-identifier",
    "com.apple.developer.team-identifier",
    "get-task-allow",
    "keychain-access-groups",
}


def entitlements(data):
    if len(data) < 12:
        reject("SIGNATURE_BOUNDS")
    magic, size, count = struct.unpack_from(">III", data)
    if magic != 0xFADE0CC0 or size > len(data) or size < 12 + count * 8 or count > 4096:
        reject("SIGNATURE_BOUNDS")
    # LC_CODE_SIGNATURE may reserve more bytes than this source SuperBlob uses.
    # Apple's readBlob reads its declared length and treats the allocation as a
    # maximum. Only indexed bytes within size can supply entitlement claims.
    # https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_codesigning/lib/machorep.cpp#L327-L343
    # Every DER blob is parsed and checked.
    xml = None
    der = None
    seen = set()
    ranges = []
    for i in range(count):
        slot, offset = struct.unpack_from(">II", data, 12 + i * 8)
        if slot in seen or offset < 12 + count * 8 or offset + 8 > size:
            reject("SIGNATURE_BOUNDS")
        seen.add(slot)
        blobmagic, length = struct.unpack_from(">II", data, offset)
        if length < 8 or offset + length > size:
            reject("SIGNATURE_BOUNDS")
        ranges.append((offset, offset + length))
        if slot in (5, 7) and length > MAX_ENTITLEMENTS_SIZE + 8:
            reject("ENTITLEMENTS_INVALID")
        if slot == 7:
            if blobmagic != 0xFADE7172:
                reject("ENTITLEMENTS_INVALID")
            der = decode_der(data[offset + 8 : offset + length])
        if slot == 5:
            if blobmagic != 0xFADE7171:
                reject("ENTITLEMENTS_INVALID")
            xml = decode_plist(data[offset + 8 : offset + length])
    ranges.sort()
    if any(left[1] > right[0] for left, right in zip(ranges, ranges[1:])):
        reject("SIGNATURE_BOUNDS")
    if xml is not None and der is not None and not typed_equal(xml, der):
        reject("ENTITLEMENTS_MISMATCH")
    return json_entitlements(der if der is not None else xml if xml is not None else {})


def macho(data, depth=0, allow_verified_der=False, required_filetype=None, allow_encrypted=False):
    from guest.macho import arm64_slice

    if depth > 1 or len(data) < 4:
        reject("MACHO_BOUNDS")
    data = arm64_slice(data)
    if len(data) < 32 or data[:4] != b"\xcf\xfa\xed\xfe":
        reject("MACHO_UNSUPPORTED")
    _, cpu, sub, filetype, ncmds, cmdbytes, flags, reserved = struct.unpack_from("<8I", data)
    if cpu == 0x100000C and sub & 0xFFFFFF not in (0, 1):
        reject("ARCHITECTURE_UNSUPPORTED")
    if cpu != 0x100000C or filetype not in (2, 6) or ncmds > 4096 or cmdbytes > len(data) - 32:
        reject("MACHO_UNSUPPORTED")
    if required_filetype is not None and filetype != required_filetype:
        reject("DYLIB_TYPE_REQUIRED")
    offset = 32
    end = 32 + cmdbytes
    platform = None
    minimum = None
    ent = {}
    signature = False
    encrypted = False
    for _ in range(ncmds):
        if offset + 8 > end:
            reject("MACHO_BOUNDS")
        cmd, size = struct.unpack_from("<II", data, offset)
        if size < 8 or size % 4 or offset + size > end:
            reject("MACHO_BOUNDS")
        if cmd == 0x19:
            if size < 72:
                reject("SEGMENT_BOUNDS")
            fileoff, filesize = struct.unpack_from("<QQ", data, offset + 40)
            sections = struct.unpack_from("<I", data, offset + 64)[0]
            if size != 72 + sections * 80 or fileoff + filesize > len(data):
                reject("SEGMENT_BOUNDS")
            for index in range(sections):
                sec = offset + 72 + index * 80
                secsize = struct.unpack_from("<Q", data, sec + 40)[0]
                secoff = struct.unpack_from("<I", data, sec + 48)[0]
                sectype = struct.unpack_from("<I", data, sec + 64)[0] & 255
                if sectype not in (1, 12, 18) and (
                    secoff < fileoff or secoff + secsize > fileoff + filesize
                ):
                    reject("SECTION_BOUNDS")
        if cmd in (0x21, 0x2C):
            if size < (24 if cmd == 0x2C else 20):
                reject("MACHO_BOUNDS")
            start, length, crypt = struct.unpack_from("<III", data, offset + 8)
            if start + length > len(data):
                reject("MACHO_BOUNDS")
            if crypt:
                if not allow_encrypted:
                    reject("DRM_UNSUPPORTED")
                encrypted = True
        if cmd == 0x32:
            if size < 24:
                reject("MACHO_BOUNDS")
            p, v, sdk, tools = struct.unpack_from("<4I", data, offset + 8)
            if size != 24 + tools * 8 or platform is not None:
                reject("PLATFORM_INVALID")
            platform = p
            minimum = v
        if cmd in (0x24, 0x25, 0x2F, 0x30):
            if size != 16 or platform is not None:
                reject("PLATFORM_INVALID")
            platform = 2 if cmd == 0x25 else -1
            minimum = struct.unpack_from("<I", data, offset + 8)[0]
        if cmd == 0x1D:
            if size != 16 or signature:
                reject("SIGNATURE_BOUNDS")
            start, length = struct.unpack_from("<II", data, offset + 8)
            if start < end or start + length > len(data):
                reject("SIGNATURE_BOUNDS")
            ent = entitlements(data[start : start + length])
            signature = True
        offset += size
    if offset != end or platform != 2:
        reject("PLATFORM_UNSUPPORTED")
    return {
        "platform": "ios",
        "architectures": ["arm64"],
        "encrypted": encrypted,
        "entitlements": ent,
        "binaryMinOs": f"{minimum >> 16}.{(minimum >> 8) & 255}.{minimum & 255}",
    }


def analyze_bytes(raw):
    if len(raw) > MAX_INPUT:
        reject("INPUT_TOO_LARGE")
    try:
        return _analyze(raw)
    except (
        zipfile.BadZipFile,
        ExpatError,
        EOFError,
        struct.error,
        plistlib.InvalidFileException,
        UnicodeError,
        RuntimeError,
        KeyError,
        TypeError,
        OverflowError,
    ) as exc:
        raise ValueError("ARCHIVE_INVALID") from exc


def file_stamp(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def analyze_file(path, allow_verified_der=False, max_unpacked=None, max_entries=None):
    with bounded.open_regular(path) as source:
        before = file_stamp(os.fstat(source.fileno()))
        if before[3] > MAX_INPUT:
            reject("INPUT_TOO_LARGE")
        digest = hashlib.sha256()
        for block in iter(lambda: source.read(bounded.CHUNK), b""):
            digest.update(block)
        source.seek(0)
        try:
            analysis = _analyze(
                source, allow_verified_der, max_unpacked, digest.hexdigest(), max_entries
            )
            if (
                file_stamp(os.fstat(source.fileno())) != before
                or file_stamp(os.stat(path, follow_symlinks=False)) != before
            ):
                reject("SOURCE_CHANGED")
            return analysis
        except (
            zipfile.BadZipFile,
            ExpatError,
            EOFError,
            struct.error,
            plistlib.InvalidFileException,
            UnicodeError,
            RuntimeError,
            KeyError,
            TypeError,
            OverflowError,
        ) as exc:
            raise ValueError("ARCHIVE_INVALID") from exc


def validate_zip_directory(source, max_entries=None):
    # zipfile parses the central directory into memory. Bound that metadata
    # before constructing ZipFile, including ZIP64 archives.
    max_entries = MAX_ENTRIES if max_entries is None else max_entries
    if not MAX_ENTRIES <= max_entries <= 3 * MAX_ENTRIES:
        reject("ARCHIVE_ENTRY_POLICY_INVALID")
    max_directory = MAX_ZIP_DIRECTORY + (max_entries - MAX_ENTRIES) * 4224
    position = source.tell()
    source.seek(0, 2)
    length = source.tell()
    source.seek(max(0, length - 65557))
    tail = source.read(65557)
    index = tail.rfind(b"PK\x05\x06")
    if index < 0 or index + 22 > len(tail):
        reject("ARCHIVE_INVALID")
    fields = struct.unpack_from("<4s4H2IH", tail, index)
    _, disk, start_disk, disk_entries, entries, size, offset, comment = fields
    if index + 22 + comment != len(tail) or disk or start_disk or disk_entries != entries:
        reject("ARCHIVE_INVALID")
    if size == 0xFFFFFFFF or offset == 0xFFFFFFFF or entries == 65535:
        end_position = length - len(tail) + index
        if end_position < 20:
            reject("ARCHIVE_INVALID")
        source.seek(end_position - 20)
        locator = source.read(20)
        magic, disk, record_offset, disks = struct.unpack("<4sIQI", locator)
        if magic != b"PK\x06\x07" or disk or disks != 1 or record_offset + 56 > end_position - 20:
            reject("ARCHIVE_INVALID")
        source.seek(record_offset)
        record = source.read(56)
        magic, record_size, made, needed, disk, start_disk, disk_entries, entries, size, offset = (
            struct.unpack("<4sQ2H2I4Q", record)
        )
        if (
            magic != b"PK\x06\x06"
            or record_size != 44
            or disk
            or start_disk
            or disk_entries != entries
        ):
            reject("ARCHIVE_INVALID")
    if entries > max_entries or size > max_directory:
        reject("ARCHIVE_METADATA_LIMIT")
    source.seek(position)


def _analyze(raw, allow_verified_der=False, max_unpacked=None, digest=None, max_entries=None):
    max_unpacked = MAX_UNPACKED if max_unpacked is None else max_unpacked
    max_entries = MAX_ENTRIES if max_entries is None else max_entries
    digest = digest or hashlib.sha256(raw).hexdigest()
    source = io.BytesIO(raw) if isinstance(raw, bytes) else raw
    validate_zip_directory(source, max_entries)
    with zipfile.ZipFile(source) as z:
        entries = z.infolist()
        if len(entries) > max_entries or sum(e.file_size for e in entries) > max_unpacked:
            reject("ARCHIVE_LIMIT")
        names = {}
        folded = set()
        actual = 0
        for e in entries:
            name = e.filename
            parts = name.rstrip("/").split("/")
            if (
                not name
                or len(name.encode("utf8")) > 4096
                or any(len(p.encode("utf8")) > 255 for p in parts)
                or "\\" in name
                or "\x00" in name
                or any(p in ("", "..", ".") for p in parts)
                or ":" in name
                or name.casefold() in folded
            ):
                reject("ZIP_PATH_REJECTED")
            folded.add(name.casefold())
            mode = e.external_attr >> 16
            if (
                stat.S_ISLNK(mode)
                or (stat.S_IFMT(mode) and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)))
                or e.flag_bits & 1
            ):
                reject("ZIP_ENTRY_REJECTED")
            names[name] = e
            with z.open(e) as f:
                while True:
                    chunk = f.read(1 << 20)
                    if not chunk:
                        break
                    actual += len(chunk)
                    if actual > max_unpacked:
                        reject("ARCHIVE_LIMIT")
        canonical = {n.rstrip("/").casefold(): e for n, e in names.items()}
        if len(canonical) != len(names):
            reject("ZIP_PATH_REJECTED")
        for name in canonical:
            parts = name.split("/")
            if any(
                "/".join(parts[:i]) in canonical and not canonical["/".join(parts[:i])].is_dir()
                for i in range(1, len(parts))
            ):
                reject("ZIP_PATH_REJECTED")
        roots = {
            n.split("/")[1]
            for n in names
            if n.startswith("Payload/")
            and len(n.split("/")) > 2
            and n.split("/")[1].endswith(".app")
        }
        if len(roots) != 1:
            reject("MAIN_APP_REQUIRED")
        root = "Payload/" + next(iter(roots))
        for name, entry in names.items():
            if not any(part.endswith((".bundle", ".xpc")) for part in name.split("/")):
                continue
            head = b""
            metadata = None
            if not entry.is_dir():
                with z.open(entry) as source:
                    head = source.read(4)
                if name.endswith(".bundle/Info.plist") and entry.file_size <= MAX_METADATA:
                    metadata = z.read(entry)
            validate_resource_entry(name, head, metadata)
        bundles = set()
        for n in names:
            parts = n.split("/")
            for i, p in enumerate(parts):
                if p.endswith((".app", ".appex", ".framework")):
                    bundles.add("/".join(parts[: i + 1]))
        if any(b != root and not b.startswith(root + "/") for b in bundles):
            reject("COMPONENT_GRAPH_REJECTED")
        result = []
        warnings = []
        optional_extensions = {}
        metadata = None
        executables = set()
        for b in sorted(bundles):
            kind = "app" if b.endswith(".app") else "appex" if b.endswith(".appex") else "framework"
            if kind == "app" and b != root:
                reject("NESTED_APP_UNSUPPORTED")
            if names[b + "/Info.plist"].file_size > MAX_METADATA:
                reject("METADATA_LIMIT")
            info = plistlib.loads(z.read(b + "/Info.plist"))
            if not isinstance(info, dict):
                reject("METADATA_INVALID")
            bid = info.get("CFBundleIdentifier")
            exe = info.get("CFBundleExecutable")
            minimum = info.get("MinimumOSVersion")
            if (
                not isinstance(bid, str)
                or not re.fullmatch(
                    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*"
                    if kind == "framework"
                    else r"([A-Za-z0-9-]+\.)+[A-Za-z0-9-]+",
                    bid,
                )
                or not isinstance(exe, str)
                or not exe
                or len(exe.encode("utf8")) > 255
                or any(c in exe for c in ("/", "\\", ":", "\0"))
                or exe in (".", "..")
                or (
                    minimum is not None
                    and (
                        not isinstance(minimum, str)
                        or not re.fullmatch(r"\d+(\.\d+){0,2}", minimum)
                    )
                )
                or info.get("CFBundleSupportedPlatforms", ["iPhoneOS"]) != ["iPhoneOS"]
            ):
                reject("METADATA_INVALID")
            binary = b + "/" + exe
            executables.add(binary)
            if names[binary].file_size > (MAX_SIGNED_BINARY if allow_verified_der else MAX_BINARY):
                reject("BINARY_LIMIT")
            extension = info.get("NSExtension")
            point = (
                extension.get("NSExtensionPointIdentifier") if isinstance(extension, dict) else None
            )
            if (
                not allow_verified_der
                and kind == "appex"
                and b.rsplit("/", 1)[0] == root + "/PlugIns"
                and isinstance(point, str)
                and point in OPTIONAL_EXTENSION_POINTS
            ):
                optional_extensions[b] = {"path": b, "bundleId": bid, "extensionPoint": point}
            m = macho(
                z.read(binary),
                allow_verified_der=allow_verified_der,
                allow_encrypted=any(b == p or b.startswith(p + "/") for p in optional_extensions),
            )
            binary_min = m.pop("binaryMinOs")
            if minimum is None:
                minimum = binary_min
            elif "." not in minimum:
                minimum += ".0"

            def version(s):
                return tuple((list(map(int, s.split("."))) + [0, 0])[:3])

            if version(minimum) < version(binary_min):
                if allow_verified_der:
                    reject("MIN_OS_MISMATCH")
                warnings.append(
                    {
                        "code": "MIN_OS_CORRECTED",
                        "componentPath": b,
                        "originalMinOs": minimum,
                        "targetMinOs": binary_min,
                    }
                )
                minimum = binary_min
            result.append({"kind": kind, "path": b, "bundleId": bid, "minOs": minimum, **m})
            if b == root:
                metadata = dict(info)
                if "CFBundleShortVersionString" not in metadata:
                    metadata["CFBundleShortVersionString"] = metadata.get("CFBundleVersion")
        for n, e in names.items():
            if e.is_dir() or n in executables:
                continue
            with z.open(e) as f:
                head = f.read(4)
            if head in MACHO_MAGIC:
                if not n.endswith(".dylib") or not n.startswith(root + "/"):
                    reject("UNMODELED_EXECUTABLE")
                if e.file_size > (MAX_SIGNED_BINARY if allow_verified_der else MAX_BINARY):
                    reject("BINARY_LIMIT")
                m = macho(
                    z.read(e),
                    allow_verified_der=allow_verified_der,
                    required_filetype=6,
                    allow_encrypted=any(n.startswith(p + "/") for p in optional_extensions),
                )
                minimum = m.pop("binaryMinOs")
                result.append(
                    {
                        "kind": "dylib",
                        "path": n,
                        "bundleId": "isign.dylib." + hashlib.sha256(n.encode()).hexdigest(),
                        "minOs": minimum,
                        **m,
                    }
                )
        mainid = metadata["CFBundleIdentifier"]
        if any(c["kind"] == "appex" and not c["bundleId"].startswith(mainid + ".") for c in result):
            reject("EXTENSION_ID_MISMATCH")
        removed = [
            optional_extensions[p]
            for p in sorted(optional_extensions)
            if any(
                c["encrypted"] and (c["path"] == p or c["path"].startswith(p + "/")) for c in result
            )
        ]

        def retained(path):
            return not any(
                path == item["path"] or path.startswith(item["path"] + "/") for item in removed
            )

        result = [c for c in result if retained(c["path"])]
        warnings = [w for w in warnings if retained(w["componentPath"])]
        warnings += [
            {
                "code": "ENCRYPTED_EXTENSION_REMOVED",
                "componentPath": item["path"],
                "extensionPoint": item["extensionPoint"],
            }
            for item in removed
        ]
        for key in ("CFBundleShortVersionString", "CFBundleVersion"):
            if (
                not isinstance(metadata.get(key), str)
                or not metadata[key]
                or len(metadata[key]) > 128
            ):
                reject("METADATA_INVALID")
        title = metadata.get("CFBundleDisplayName", metadata.get("CFBundleName", mainid))
        if not isinstance(title, str) or not title or len(title) > 200:
            reject("METADATA_INVALID")
        return {
            "title": title,
            "sha256": digest,
            "bundleId": mainid,
            "version": metadata["CFBundleShortVersionString"],
            "build": metadata["CFBundleVersion"],
            "components": result,
            **({"removedExtensions": removed} if removed else {}),
            **({"warnings": warnings} if warnings else {}),
        }


def main():
    if os.environ.get("ISIGN_ISOLATED_EXECUTOR") != "1":
        reject("ISOLATED_EXECUTOR_REQUIRED")
    if len(sys.argv) != 3:
        reject("USAGE: analyzer.py GRANT_JSON IPA")
    with open(sys.argv[1], encoding="utf8") as f:
        grant = json.load(f)
    validate_grant(grant)
    analysis = analyze_file(sys.argv[2])
    validate_grant(grant)
    print(json.dumps(make_report(grant, analysis), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError) as exc:
        print(json.dumps({"error": str(exc) if isinstance(exc, ValueError) else "IO_FAILED"}))
        sys.exit(1)
