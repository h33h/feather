"""Installed pinned-image entry point. Starts no network listener."""

import base64, hashlib, importlib.util, io, json, os, pathlib, sys


import protocol.framing as channel
from protocol.codec import canonical
import guest.controller as controller
import guest.linux_runtime as linux
import guest.linux_verification as verify
import guest.linux_certificate_policy as policy
import guest.native as native


class RuntimeProxy:
    def __init__(self, config, identity, key):
        self.root = pathlib.Path("/job")
        self.config = config
        self.identity = identity
        self.key = key
        self.runtime = None
        self.validate_vm = native.vm_proof_validator(lambda _: key)

    def bind_grant(self, grant, proof):
        if self.validate_vm(proof, grant) is not True:
            raise ValueError("JOB_PROOF_REQUIRED")
        if self.runtime is None:
            cfg = self.config
            run = linux.LinuxGuestRunner(
                self.root,
                grant,
                proof,
                self.validate_vm,
                openssl_path=cfg["opensslPath"],
                zsign_path=cfg["zsignPath"],
                zsign_digest=cfg["zsignSha256"],
                trusted_paths=[cfg["caFile"], cfg["intermediateFile"]],
            )
            cert_policy = policy.LinuxCertificatePolicy(
                [pathlib.Path(path).read_bytes() for path in cfg["certificateChainDer"]]
            )
            verifier = verify.LinuxVerifier(
                self.root,
                run,
                openssl_path=cfg["opensslPath"],
                ca_file=cfg["caFile"],
                intermediate_file=cfg["intermediateFile"],
                cms_signer_fingerprints=cfg["cmsSignerSha256"],
                apple_certificate_policy=cert_policy,
            )
            self.runtime = linux.LinuxGuestRuntime(
                self.root,
                run,
                verifier,
                openssl_path=cfg["opensslPath"],
                validate_vm=self.validate_vm,
                proof_key=self.key,
                key_id="job",
                zsign_path=cfg["zsignPath"],
                zsign_digest=cfg["zsignSha256"],
            )
        self.runtime.bind_grant(grant, proof)

    def destroy(self):
        if self.runtime:
            self.runtime.destroy()

    def __getattr__(self, name):
        if self.runtime is None:
            raise ValueError("INITIALIZED_JOB_RUNTIME_REQUIRED")
        return getattr(self.runtime, name)


class FramedSource:
    def __init__(self, stream):
        self.stream = stream
        self.pending = b""
        self.eof = False
        self.total = 0

    def read(self, size):
        if self.eof:
            return b""
        data = channel.read_frame(self.stream)
        if not data:
            self.eof = True
            return b""
        self.total += len(data)
        if len(data) > 65536 or self.total > 1 << 30:
            raise ValueError("SOURCE_FRAME_LIMIT")
        return data


def serve(input_stream, output_stream, config, runtime_factory=RuntimeProxy):
    initial = json.loads(channel.read_frame(input_stream))
    key = base64.b64decode(initial["jobKey"], validate=True)
    if len(key) != 32:
        raise ValueError("JOB_KEY_REQUIRED")
    os.environ["ISIGN_ISOLATED_EXECUTOR"] = (
        "1"  # Additional switch; controller proof still mandatory.
    )
    runtime = runtime_factory(config, initial["identity"], key)
    app = controller.GuestController(
        runtime,
        identity=initial["identity"],
        evidence=initial["evidence"],
        validate_launcher_identity=lambda identity, evidence: (
            identity == initial["identity"]
            and native.validated_isolation(evidence)
            == native.validated_isolation(initial["evidence"])
        ),
        token=initial["token"],
        audience=initial["audience"],
        proof_key=key,
        transport_kind="stdio",
    )
    try:
        while True:
            message = json.loads(channel.read_frame(input_stream))
            headers = message["headers"]
            stream = (
                FramedSource(input_stream)
                if message["streaming"]
                else io.BytesIO(base64.b64decode(message["body"], validate=True))
            )
            status = []
            env = {
                "wsgi.url_scheme": "isign-stdio",
                "isign.transport": "authenticated-stdio",
                "REQUEST_METHOD": "POST",
                "PATH_INFO": message["path"],
                "wsgi.input": stream,
                "CONTENT_TYPE": headers.get("content-type", "application/json"),
            }
            for name, value in headers.items():
                env["HTTP_" + name.upper().replace("-", "_")] = value
            response = b"".join(app(env, lambda code, headers: status.append(code)))
            # Drain only the current bounded upload frames to preserve message boundaries.
            if message["streaming"] and not stream.eof:
                while stream.read(65536):
                    pass
            channel.write_frame(
                output_stream,
                canonical({"status": status[0], "body": base64.b64encode(response).decode()}),
            )
    finally:
        runtime.destroy()
        key = b""


if __name__ == "__main__":
    configuration = json.loads(pathlib.Path("/opt/isign/runner-config.json").read_text())
    serve(sys.stdin.buffer, sys.stdout.buffer, configuration)
