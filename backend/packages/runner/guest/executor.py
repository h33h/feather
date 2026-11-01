from protocol.digests import canonical_digest

"""Signing orchestration for an externally provisioned, attested disposable VM.

This driver has no subprocess default: deployment must inject proof-gated adapters.
"""
import hashlib, importlib.util, json, os, pathlib, plistlib, re, secrets, shutil, time

import guest.analyzer as _analyzer
from guest import entitlement_policy

REQUIRED_VERIFICATION = (
    "strictSignature",
    "cmsChain",
    "certificateKeyMatch",
    "entitlementsExact",
    "identityExact",
    "profileExact",
    "udidExact",
    "platformExact",
)
MATERIAL_VERIFICATION = (
    "cmsChain",
    "certificateKeyMatch",
    "identityExact",
    "profileExact",
    "udidExact",
    "componentGraphExact",
    "inputDigestExact",
    "mappedMetadataExact",
)


def reject(code):
    raise ValueError(code)


def verified(evidence, keys):
    if not isinstance(evidence, dict) or any(evidence.get(k) is not True for k in keys):
        reject("VERIFICATION_FAILED")
    return {k: True for k in keys}


def guest_path(root, relative):
    if (
        not isinstance(relative, str)
        or "\\" in relative
        or ":" in relative
        or any(p in ("", ".", "..") for p in relative.split("/"))
    ):
        reject("GUEST_PATH_INVALID")
    path = root / relative
    if path.resolve() != path.absolute() or not path.resolve().is_relative_to(root):
        reject("GUEST_PATH_INVALID")
    return path


def validate_plan(task, grant, root, now, mapped=False):
    identity = task.get("identity", {})
    components = task.get("components", [])
    profiles = task.get("profiles", {})
    if (
        not isinstance(components, list)
        or not components
        or len(components) > 20000
        or not isinstance(profiles, dict)
    ):
        reject("PLAN_INVALID")
    if any(
        not isinstance(component, dict)
        or not isinstance(component.get("sourceBundleId"), str)
        or not component["sourceBundleId"]
        or not isinstance(component.get("sourceEntitlements"), dict)
        for component in components
    ):
        reject("SOURCE_IDENTITY_REQUIRED")

    def identity_valid(value):
        return (
            value.get("ownerId") == grant["ownerId"]
            and value.get("teamId") == identity.get("teamId")
            and value.get("prefix") == identity.get("prefix")
            and value.get("fingerprint") == identity.get("fingerprint")
            and type(value.get("expiresAt")) is int
            and value["expiresAt"] > now
        )

    if (
        not identity_valid(identity)
        or not re.fullmatch("[A-F0-9]{40,64}", str(identity.get("fingerprint", "")))
        or not re.fullmatch("[A-Za-z0-9]+", str(identity.get("teamId", "")))
        or not re.fullmatch("[A-Za-z0-9]+", str(identity.get("prefix", "")))
    ):
        reject("IDENTITY_INVALID")
    mains = [c for c in components if c.get("kind") == "app"]
    if len(mains) != 1 or not re.fullmatch(r"Payload/[^/]+\.app", str(mains[0].get("path", ""))):
        reject("MAIN_APP_REQUIRED")
    main = mains[0]
    mapping = any(c["sourceBundleId"] != c.get("bundleId") for c in components)
    main_source = main["sourceBundleId"]
    paths = set()
    folded = set()
    bundleids = set()
    materials = {guest_path(root, identity.get("materialPath"))}
    if not isinstance(task.get("udid"), str) or not task["udid"]:
        reject("DEVICE_REQUIRED")
    for c in components:
        path = c.get("path")
        kind = c.get("kind")
        bid = c.get("bundleId")
        ent = c.get("entitlements")
        folder = guest_path(root, path)
        if (
            kind not in ("app", "appex", "framework", "dylib")
            or not path.endswith(
                {"app": ".app", "appex": ".appex", "framework": ".framework", "dylib": ".dylib"}[
                    kind
                ]
            )
            or path in paths
            or path.casefold() in folded
            or bid in bundleids
            or (c is not main and not path.startswith(main["path"] + "/"))
        ):
            reject("COMPONENT_GRAPH_REJECTED")
        source = c["sourceBundleId"]
        identifier_pattern = (
            r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*"
            if kind == "framework"
            else r"([A-Za-z0-9-]+\.)+[A-Za-z0-9-]+"
        )
        if not isinstance(source, str) or not re.fullmatch(identifier_pattern, source):
            reject("SOURCE_ID_INVALID")
        if kind == "appex" and (
            not isinstance(bid, str)
            or not bid.startswith(main["bundleId"] + ".")
            or not source.startswith(main_source + ".")
        ):
            reject("EXTENSION_ID_MISMATCH")
        if (
            not isinstance(bid, str)
            or not re.fullmatch(identifier_pattern, bid)
            or c.get("platform") != "ios"
            or c.get("architectures") != ["arm64"]
            or c.get("encrypted") is not False
            or not re.fullmatch(r"\d+(\.\d+){1,2}", str(c.get("minOs", "")))
        ):
            reject("COMPONENT_UNSUPPORTED")
        if not isinstance(ent, dict) or not entitlement_policy.safe_value(ent):
            reject("UNSUPPORTED_ENTITLEMENT")
        if kind in ("framework", "dylib"):
            if ent or c.get("profileRequired") is not False:
                reject("FRAMEWORK_PROFILE_MISMATCH")
        else:
            p = profiles.get(bid)
            if (
                c.get("profileRequired") is not True
                or not isinstance(p, dict)
                or not identity_valid(p)
                or p.get("bundleId") != bid
                or task["udid"] not in p.get("udids", [])
                or not entitlement_policy.exact(
                    ent,
                    entitlement_policy.normalized_entitlements(c["sourceEntitlements"], p),
                )
            ):
                reject("PROFILE_MISMATCH")
            materials.add(guest_path(root, p.get("materialPath")))
        paths.add(path)
        folded.add(path.casefold())
        bundleids.add(bid)
        if kind == "dylib":
            if not folder.is_file() or folder.is_symlink():
                reject("COMPONENT_MISSING")
            expected_id = "isign.dylib." + hashlib.sha256(path.encode("utf8")).hexdigest()
            if bid != expected_id or source != expected_id:
                reject("SOURCE_METADATA_MISMATCH")
            raw = _analyzer.bounded.read_bounded(
                folder, _analyzer.MAX_SIGNED_BINARY if mapped else _analyzer.MAX_BINARY
            )
            metadata = _analyzer.macho(raw, allow_verified_der=mapped, required_filetype=6)
            if any(metadata[k] != c[k] for k in ("platform", "architectures", "encrypted")):
                reject("COMPONENT_UNSUPPORTED")
            version = lambda text: tuple(int(part) for part in (text.split(".") + ["0", "0"])[:3])
            if version(metadata["binaryMinOs"]) != version(c["minOs"]):
                reject("COMPONENT_UNSUPPORTED")
            continue
        if not folder.is_dir() or not (folder / "Info.plist").is_file():
            reject("COMPONENT_MISSING")
        info = plistlib.loads((folder / "Info.plist").read_bytes())
        if info.get("CFBundleIdentifier") != (bid if mapped else source):
            reject("SOURCE_METADATA_MISMATCH")
        if mapping:
            originals = {
                node["sourceBundleId"]
                for node in components
                if node["sourceBundleId"] != node["bundleId"]
            }

            def references(value, top=False):
                if isinstance(value, str):
                    return any(old in value for old in originals)
                if isinstance(value, dict):
                    return any(
                        references(v)
                        for k, v in value.items()
                        if not (top and k == "CFBundleIdentifier")
                    )
                if isinstance(value, list):
                    return any(references(v) for v in value)
                return False

            if references(info, True):
                reject("UNSUPPORTED_IDENTIFIER_REFERENCE")
    actual_bundles = {
        str(p.relative_to(root))
        for p in (root / "Payload").rglob("*")
        if p.is_dir() and p.name.endswith((".app", ".appex", ".framework"))
    }
    actual_libraries = {
        str(p.relative_to(root)) for p in (root / "Payload").rglob("*") if p.name.endswith(".dylib")
    }
    if actual_bundles | actual_libraries != paths:
        reject("COMPONENT_GRAPH_REJECTED")
    for entry in (root / "Payload").rglob("*"):
        relative = str(entry.relative_to(root))
        if not any(part.endswith((".bundle", ".xpc")) for part in relative.split("/")):
            continue
        head = b""
        metadata = None
        if entry.is_file():
            with entry.open("rb") as source:
                head = source.read(4)
            if (
                relative.endswith(".bundle/Info.plist")
                and entry.stat().st_size <= _analyzer.MAX_METADATA
            ):
                metadata = _analyzer.bounded.read_bounded(entry, _analyzer.MAX_METADATA)
        _analyzer.validate_resource_entry(relative, head, metadata)
    if set(profiles) != {c["bundleId"] for c in components if c["profileRequired"]}:
        reject("PROFILE_GRAPH_MISMATCH")
    if any(not p.is_file() for p in materials):
        reject("MATERIAL_MISSING")
    return sorted(components, key=lambda c: (-len(c["path"].split("/")), c["path"])), materials


def create_attested_envelope(report, attest_report):
    """Trusted deployment adapter signs canonical UTF-8 report bytes.

    No key loading or provisioning is performed here. Controller independently
    verifies this attestation and all grant/database eligibility before publishing.
    """
    if not callable(attest_report):
        reject("ATTESTOR_REQUIRED")
    content = json.dumps(
        report, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf8")
    attestation = attest_report(content)
    if (
        not isinstance(attestation, dict)
        or attestation.get("algorithm") != "hmac-sha256"
        or not isinstance(attestation.get("keyId"), str)
        or not attestation["keyId"]
        or not re.fullmatch("[a-f0-9]{64}", str(attestation.get("signature", "")))
    ):
        reject("ATTESTATION_INVALID")
    return {"report": report, "attestation": attestation}
