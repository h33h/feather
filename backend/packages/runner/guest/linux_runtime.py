"""Linux guest runtime composition using a digest-pinned strict-plan signer."""

import hashlib, hmac, importlib.util, pathlib, io, zipfile, plistlib, os


import guest.runtime as base
import guest.native as native
import guest.linux_executor as driver


class LinuxGuestRunner(native.NativeGuestRunner):
    def __init__(self, *args, zsign_path, zsign_digest, **kwargs):
        super().__init__(*args, **kwargs)
        self.zsign = str(pathlib.Path(zsign_path).resolve())
        self.digest = zsign_digest
        if hashlib.sha256(pathlib.Path(self.zsign).read_bytes()).hexdigest() != zsign_digest:
            raise ValueError("ZSIGN_BINARY_PIN_MISMATCH")

    def __call__(self, argv, *, cwd, timeout, input_bytes=None):
        if argv and argv[0] in ("/usr/bin/codesign", "/usr/bin/security", "/usr/bin/ditto"):
            raise ValueError("MACOS_TOOL_NOT_ALLOWED_ON_LINUX")
        if argv and argv[0] == self.zsign:
            if (
                self.validate(self.proof, self.grant) is not True
                or pathlib.Path(cwd).resolve() != self.root
                or not 0 < timeout <= 120
                or hashlib.sha256(pathlib.Path(self.zsign).read_bytes()).hexdigest() != self.digest
                or not isinstance(input_bytes, bytes)
                or not 1 < len(input_bytes) <= 1025
                or not input_bytes.endswith(b"\n")
                or b"\n" in input_bytes[:-1]
                or b"\r" in input_bytes
                or b"\0" in input_bytes
            ):
                raise ValueError("LINUX_SIGN_COMMAND_REJECTED")
            if (
                len(argv) < 12
                or argv[1:2] != ["--isign-plan"]
                or argv[3:7] != ["-f", "-2", "-q", "-k"]
                or argv[8] != "--isign-password-stdin"
                or (len(argv) - 10) % 2
            ):
                raise ValueError("LINUX_SIGN_COMMAND_REJECTED")
            self._path(argv[2])
            self._path(argv[7])
            self._path(argv[-1])
            for index in range(9, len(argv) - 1, 2):
                if argv[index] != "-m":
                    raise ValueError("LINUX_SIGN_COMMAND_REJECTED")
                self._path(argv[index + 1])
            return self.launch(
                argv,
                cwd=str(self.root),
                timeout=timeout,
                input_bytes=input_bytes,
                max_output=8 << 20,
            )
        if argv and argv[0] == self.openssl and "-noverify" in argv:
            if (
                len(argv) != 14
                or argv[1:7] != ["cms", "-verify", "-verify_retcode", "-inform", "DER", "-in"]
                or argv[8:10] != ["-binary", "-content"]
                or argv[11:13] != ["-noverify", "-signer"]
                or input_bytes is not None
                or self.validate(self.proof, self.grant) is not True
                or pathlib.Path(cwd).resolve() != self.root
                or not 0 < timeout <= 120
            ):
                raise ValueError("LINUX_CMS_COMMAND_REJECTED")
            for index in (7, 10, 13):
                self._path(argv[index])
            return self.launch(
                argv, cwd=str(self.root), timeout=timeout, input_bytes=None, max_output=8 << 20
            )
        return super().__call__(argv, cwd=cwd, timeout=timeout, input_bytes=input_bytes)


class LinuxGuestRuntime(base.GuestRuntime):
    def __init__(self, *args, zsign_path, zsign_digest, **kwargs):
        super().__init__(*args, **kwargs)
        os.chmod(self.root, 0o700)
        self.zsign = zsign_path
        self.zsign_digest = zsign_digest

    def validate_source_format(self, raw, analysis):
        source = io.BytesIO(raw) if isinstance(raw, bytes) else raw
        size = len(raw) if isinstance(raw, bytes) else pathlib.Path(raw).stat().st_size
        with zipfile.ZipFile(source) as archive:
            if (
                size > base.executor._analyzer.MAX_INPUT
                or sum(entry.file_size for entry in archive.infolist())
                > base.executor._analyzer.MAX_UNPACKED
            ):
                raise ValueError("LINUX_SOURCE_CAPACITY_UNSUPPORTED")
            for component in analysis["components"]:
                binary_path = component["path"]
                if component.get("kind") != "dylib":
                    info = plistlib.loads(archive.read(component["path"] + "/Info.plist"))
                    binary_path += "/" + info["CFBundleExecutable"]
                if archive.getinfo(binary_path).file_size > base.executor._analyzer.MAX_BINARY:
                    raise ValueError("BINARY_LIMIT")
                base.executor._analyzer.macho(
                    archive.read(binary_path),
                    required_filetype=6 if component.get("kind") == "dylib" else None,
                )

    def bootstrap_prepare(self, binding, payload, execution_grant, proof):
        original = payload["sealGrant"]
        delegation = {"binding": binding, "instanceId": payload["instanceId"], "grant": original}
        expected = hmac.new(
            self.key,
            b"isign-linux-seal-delegation-v1\0" + native.canonical(delegation),
            hashlib.sha256,
        ).hexdigest()
        if not isinstance(payload.get("sealAttestation"), str) or not hmac.compare_digest(
            expected, payload["sealAttestation"]
        ):
            raise ValueError("SEALED_BOOTSTRAP_DELEGATION_REQUIRED")
        self.seal_grant_authorizer = lambda grant: (
            native.canonical(grant) == native.canonical(original)
        )
        try:
            return super().bootstrap_prepare(
                binding,
                {k: v for k, v in payload.items() if k != "sealAttestation"},
                execution_grant,
                proof,
            )
        finally:
            self.seal_grant_authorizer = None

    def bind_grant(self, grant, proof):
        if self.validate_vm(proof, grant) is not True:
            raise ValueError("LINUX_PROOF_REJECTED")
        self.run.grant = dict(grant)
        self.run.proof = proof

    def execute(self, grant, task, proof):
        try:
            report = driver.execute_linux_task(
                grant=grant,
                task=task,
                workspace=self.root,
                vm_proof=proof,
                validate_vm=self.validate_vm,
                command_runner=self.run,
                verifier=self.verifier,
                zsign_path=self.zsign,
                zsign_digest=self.zsign_digest,
                material_password_provider=self.materials.password_provider,
            )
            result = self.signed(report)
            result["artifactRef"] = "signed_ipa"
            return result
        finally:
            self.materials.clear()
