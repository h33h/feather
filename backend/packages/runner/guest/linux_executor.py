"""Pinned strict-plan zsign driver, usable only in a proved disposable sandbox."""

import hashlib, importlib.util, json, os, pathlib, plistlib, re, shutil, time, zipfile

import guest.executor as e
from guest.macho import normalize_executables


def execute_linux_task(
    *,
    grant,
    task,
    workspace,
    vm_proof,
    validate_vm,
    command_runner,
    verifier,
    zsign_path,
    zsign_digest,
    material_password_provider,
    clock=lambda: int(time.time() * 1000),
):
    root = pathlib.Path(workspace).resolve()
    output = root / "signed.ipa"
    plan_path = root / "zsign-plan.json"
    entdir = root / "job-entitlements"
    complete = False
    password = None
    if os.environ.get("ISIGN_ISOLATED_EXECUTOR") != "1" or validate_vm(vm_proof, grant) is not True:
        raise ValueError("TRUSTED_LINUX_SANDBOX_REQUIRED")
    e._analyzer.validate_grant(grant, now=clock())
    if grant.get("planDigest") != e.canonical_digest(task):
        raise ValueError("PLAN_DIGEST_MISMATCH")
    ordered, materials = e.validate_plan(task, grant, root, clock())
    key = e.guest_path(root, task["identity"]["materialPath"])
    if (
        not re.fullmatch("[a-f0-9]{64}", zsign_digest)
        or hashlib.sha256(pathlib.Path(zsign_path).read_bytes()).hexdigest() != zsign_digest
        or any(p.exists() for p in (output, plan_path, entdir))
    ):
        raise ValueError("PINNED_SIGNER_OR_CLEAN_WORKSPACE_REQUIRED")
    if any(path.is_symlink() for path in root.rglob("*")):
        raise ValueError("GUEST_SYMLINK_REJECTED")
    try:
        password = material_password_provider(key, grant)
        if (
            not isinstance(password, str)
            or not password
            or len(password) > 1024
            or any(c in password for c in ("\0", "\n", "\r"))
        ):
            raise ValueError("MATERIAL_PASSWORD_REQUIRED")
        verifier.verify_materials(task, root, grant, pkcs12_password=password)
        normalize_executables(root, ordered, e._analyzer.bounded)
        # Independent archive/staged-byte equality is now established; only one source tree remains.
        (root / "source.ipa").unlink()
        main = next(c for c in ordered if c["kind"] == "app")
        main_root = e.guest_path(root, main["path"])
        # Finder metadata can be dropped by the installer. Remove it before
        # sealing, never from an already signed tree or from the output ZIP.
        for path in main_root.rglob("*"):
            if path.is_file() and path.name.endswith(".DS_Store"):
                path.unlink()
        entdir.mkdir(mode=0o700)
        plan = {}
        for index, component in enumerate(ordered):
            folder = e.guest_path(root, component["path"])
            relative = "/" if folder == main_root else str(folder.relative_to(main_root))
            if component["kind"] == "dylib":
                plan[relative] = {
                    "bundleId": component["bundleId"],
                    "kind": "dylib",
                    "profileDigest": task["profiles"][main["bundleId"]]["cmsSha256"],
                    "applicationId": main["entitlements"]["application-identifier"],
                }
                continue
            info_path = folder / "Info.plist"
            info = plistlib.loads(info_path.read_bytes())
            info["CFBundleIdentifier"] = component["bundleId"]
            info["MinimumOSVersion"] = component["minOs"]
            info.setdefault("CFBundleSupportedPlatforms", ["iPhoneOS"])
            if "CFBundleShortVersionString" not in info and "CFBundleVersion" in info:
                info["CFBundleShortVersionString"] = info["CFBundleVersion"]
            info_path.write_bytes(plistlib.dumps(info))
            profile = (
                task["profiles"][component["bundleId"]]
                if component["kind"] != "framework"
                else task["profiles"][main["bundleId"]]
            )
            entpath = entdir / (str(index) + ".plist")
            entpath.write_bytes(plistlib.dumps(component["entitlements"]))
            os.chmod(entpath, 0o600)
            plan[relative] = {
                "bundleId": component["bundleId"],
                "kind": component["kind"],
                "applicationId": (main if component["kind"] == "framework" else component)[
                    "entitlements"
                ]["application-identifier"],
                "profileDigest": profile["cmsSha256"],
                "entitlementsPath": str(entpath),
            }
        plan_path.write_text(json.dumps(plan, sort_keys=True, separators=(",", ":")))
        os.chmod(plan_path, 0o600)
        e.validate_plan(task, grant, root, clock(), mapped=True)
        args = [
            str(zsign_path),
            "--isign-plan",
            str(plan_path),
            "-f",
            "-2",
            "-q",
            "-k",
            str(key),
            "--isign-password-stdin",
        ]
        supplied = set()
        for bundle in sorted(task["profiles"]):
            profile = task["profiles"][bundle]
            if profile["cmsSha256"] in supplied:
                continue
            supplied.add(profile["cmsSha256"])
            args += ["-m", str(e.guest_path(root, profile["materialPath"]))]
        e._analyzer.validate_grant(grant, now=clock())
        if validate_vm(vm_proof, grant) is not True:
            raise ValueError("LINUX_EXECUTION_CANCELLED")
        args.append(str(main_root))
        command_runner(args, cwd=str(root), timeout=120, input_bytes=(password + "\n").encode())
        e._analyzer.validate_grant(grant, now=clock())
        if validate_vm(vm_proof, grant) is not True:
            raise ValueError("LINUX_EXECUTION_CANCELLED")
        if (
            sum(p.stat().st_size for p in (root / "Payload").rglob("*") if p.is_file())
            > verifier.signed_unpacked_limit
        ):
            raise ValueError("SIGNED_TREE_LIMIT")
        with zipfile.ZipFile(
            output, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=6
        ) as archive:
            for path in sorted((root / "Payload").rglob("*")):
                if path.is_symlink():
                    raise ValueError("SIGNED_SYMLINK_REJECTED")
                if path.is_file():
                    archive.write(path, str(path.relative_to(root)))
        if output.stat().st_size > e._analyzer.MAX_INPUT:
            raise ValueError("ARTIFACT_LIMIT")
        if validate_vm(vm_proof, grant) is not True:
            raise ValueError("LINUX_EXECUTION_CANCELLED")
        archive_checks = e.verified(
            verifier.verify_archive(output, task, grant), e.REQUIRED_VERIFICATION
        )
        # The independent archive pass checks every planned component from the
        # exact output bytes. Its successful checks also supply component evidence.
        evidence = [
            {"path": component["path"], "checks": dict(archive_checks)} for component in ordered
        ]
        e._analyzer.validate_grant(grant, now=clock())
        e.validate_plan(task, grant, root, clock(), mapped=True)
        info = plistlib.loads((main_root / "Info.plist").read_bytes())
        verification = {"components": evidence, "archive": archive_checks, "archiveVerified": True}
        report = {
            **{k: grant[k] for k in e._analyzer.binding_fields(grant)},
            "protocolVersion": 1,
            "operation": "sign",
            "planDigest": e.canonical_digest(task),
            "artifactDigest": e._analyzer.bounded.digests(output)[0].hex(),
            "artifactSize": output.stat().st_size,
            "verification": verification,
            "verificationReportDigest": e.canonical_digest(verification),
            "executionAuthorized": False,
            "bundleId": main["bundleId"],
            "version": info["CFBundleShortVersionString"],
            "title": info.get("CFBundleDisplayName", info.get("CFBundleName", main["bundleId"])),
            "certificateExpiresAt": task["identity"]["expiresAt"],
            "profileExpiresAt": min(p["expiresAt"] for p in task["profiles"].values()),
            "checks": {
                k: True
                for k in (
                    "archive",
                    "components",
                    "signatures",
                    "profiles",
                    "device",
                    "entitlements",
                    "mapping",
                )
            },
        }
        report["reportDigest"] = e.canonical_digest(report)
        complete = True
        return report
    finally:
        password = None
        plan_path.unlink(missing_ok=True)
        shutil.rmtree(entdir, ignore_errors=True)
        for path in materials:
            path.unlink(missing_ok=True)
        if not complete:
            output.unlink(missing_ok=True)
