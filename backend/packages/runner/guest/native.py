from protocol.proofs import (
    REQUIRED_ISOLATION,
    LINUX_ISOLATION,
    validated_isolation,
    canonical,
    validate_execution_grant,
    issue_vm_proof,
    vm_proof_validator,
)
from protocol import grants as analyzer

"""Trusted-controller VM proofs and bounded native execution inside a guest only."""
import hashlib, hmac, json, os, pathlib, re, signal, subprocess, tempfile, time, importlib.util, threading


def bounded_process(argv, *, cwd, timeout, input_bytes=None, max_output=8 << 20):
    """Never call directly for IPA tools; NativeGuestRunner validates before here."""
    if input_bytes is not None and (
        not isinstance(input_bytes, bytes) or len(input_bytes) > 8 << 20
    ):
        raise ValueError("NATIVE_INPUT_LIMIT")
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        child = subprocess.Popen(
            argv,
            cwd=cwd,
            stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
            stdout=out,
            stderr=err,
            shell=False,
            start_new_session=True,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
        if input_bytes is not None:

            def write_input():
                try:
                    child.stdin.write(input_bytes)
                    child.stdin.close()
                except (BrokenPipeError, OSError):
                    pass

            writer = threading.Thread(target=write_input, daemon=True)
            writer.start()
        deadline = time.monotonic() + timeout
        try:
            while child.poll() is None:
                if (
                    time.monotonic() > deadline
                    or os.fstat(out.fileno()).st_size + os.fstat(err.fileno()).st_size > max_output
                ):
                    raise ValueError("NATIVE_COMMAND_LIMIT")
                time.sleep(0.01)
            if child.returncode != 0:
                raise ValueError("NATIVE_COMMAND_FAILED")
            out.seek(0)
            err.seek(0)
            stdout = out.read(max_output + 1)
            stderr = err.read(max_output + 1)
            if len(stdout) + len(stderr) > max_output:
                raise ValueError("NATIVE_COMMAND_LIMIT")
            return {"stdout": stdout, "stderr": stderr}
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=5)


class NativeGuestRunner:
    def __init__(
        self,
        workspace,
        grant,
        proof,
        validate_proof,
        *,
        openssl_path="/opt/homebrew/opt/openssl@3/bin/openssl",
        trusted_paths=(),
        launch=bounded_process,
    ):
        if (
            os.environ.get("ISIGN_ISOLATED_EXECUTOR") != "1"
            or not callable(validate_proof)
            or validate_proof(proof, grant) is not True
        ):
            raise ValueError("TRUSTED_GUEST_REQUIRED")
        self.root = pathlib.Path(workspace).resolve()
        self.grant = dict(grant)
        self.proof = proof
        self.validate = validate_proof
        self.openssl = openssl_path
        self.trusted = {str(pathlib.Path(p).resolve()) for p in trusted_paths}
        self.launch = launch
        if not self.root.is_dir() or not pathlib.Path(openssl_path).is_absolute():
            raise ValueError("GUEST_CONFIGURATION_INVALID")

    def _path(self, value):
        path = pathlib.Path(value)
        if (
            not path.is_absolute()
            or path.resolve() != path.absolute()
            or (not path.is_relative_to(self.root) and str(path) not in self.trusted)
        ):
            raise ValueError("COMMAND_PATH_REJECTED")

    def __call__(self, argv, *, cwd, timeout, input_bytes=None):
        if self.validate(self.proof, self.grant) is not True:
            raise ValueError("GUEST_PROOF_EXPIRED")
        if (
            pathlib.Path(cwd).resolve() != self.root
            or type(timeout) not in (int, float)
            or not 0 < timeout <= 120
            or not isinstance(argv, list)
            or not argv
            or any(not isinstance(a, str) or "\0" in a for a in argv)
        ):
            raise ValueError("COMMAND_REJECTED")
        binary = argv[0]
        args = argv[1:]
        if binary == self.openssl:
            allowed = {
                "cms": {
                    "-verify",
                    "-verify_retcode",
                    "-inform",
                    "-in",
                    "-CAfile",
                    "-no-CApath",
                    "-no-CAstore",
                    "-purpose",
                    "-binary",
                    "-signer",
                },
                "pkcs12": {
                    "-certfile",
                    "-export",
                    "-inkey",
                    "-out",
                    "-passout",
                    "-in",
                    "-passin",
                    "-clcerts",
                    "-nokeys",
                    "-nocerts",
                    "-nodes",
                },
                "genpkey": {"-algorithm", "-pkeyopt", "-aes-256-cbc", "-pass", "-out"},
                "req": {
                    "-sha256",
                    "-new",
                    "-key",
                    "-passin",
                    "-subj",
                    "-verify",
                    "-noout",
                    "-outform",
                },
                "x509": {
                    "-issuer",
                    "-inform",
                    "-outform",
                    "-pubkey",
                    "-noout",
                    "-enddate",
                    "-startdate",
                    "-subject",
                    "-nameopt",
                },
                "pkey": {"-pubin", "-in", "-passin", "-pubout", "-outform"},
                "verify": {"-CAfile", "-untrusted", "-purpose", "-no-CApath", "-no-CAstore"},
            }
            if (
                not args
                or args[0] not in allowed
                or any(a.startswith("-") and a not in allowed[args[0]] for a in args[1:])
            ):
                raise ValueError("COMMAND_REJECTED")
            if (
                args[0] == "req"
                and "-outform" in args
                and args[args.index("-outform") + 1] != "PEM"
            ):
                raise ValueError("COMMAND_REJECTED")
            for i, a in enumerate(args):
                if a in (
                    "-in",
                    "-out",
                    "-inkey",
                    "-key",
                    "-certfile",
                    "-CAfile",
                    "-untrusted",
                    "-signer",
                ):
                    self._path(args[i + 1])
            if args[0] == "verify":
                self._path(args[-1])
            if args[0] == "pkcs12" and "-certfile" in args and "-export" not in args:
                raise ValueError("COMMAND_REJECTED")
            if args[0] == "pkcs12" and (
                "-passin" not in args or args[args.index("-passin") + 1] != "stdin"
            ):
                raise ValueError("COMMAND_REJECTED")
            for flag in ("-passin", "-passout", "-pass"):
                if flag in args and args[args.index(flag) + 1] != "stdin":
                    raise ValueError("COMMAND_REJECTED")
        else:
            raise ValueError("COMMAND_REJECTED")
        result = self.launch(
            argv, cwd=str(self.root), timeout=timeout, input_bytes=input_bytes, max_output=8 << 20
        )
        if (
            not isinstance(result, dict)
            or not isinstance(result.get("stdout"), bytes)
            or not isinstance(result.get("stderr"), bytes)
        ):
            raise ValueError("COMMAND_RESULT_INVALID")
        return result
