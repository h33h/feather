import base64, pathlib, secrets, subprocess
from protocol.stdio import StdioHTTP
from protocol.framing import write_frame
from protocol.codec import canonical
import protocol.https_transport as t


class DockerStdioGuestChannel:
    def __init__(self, docker_path, *, audience="isign-linux-guest-v1", start=None):
        if not pathlib.Path(docker_path).is_absolute():
            raise ValueError("DOCKER_BINARY_REQUIRED")
        self.docker = docker_path
        self.audience = audience
        self.start = start or self.start_process
        self.channels = {}

    @staticmethod
    def start_process(argv):
        return subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,  # Trusted guest diagnostics go to the broker journal, never protocol stdout.
            shell=False,
            start_new_session=True,
            env={"PATH": "/usr/bin:/bin", "LANG": "C"},
        )

    def authenticate(self, instance_id, request):
        identity = request["identity"]
        key = request["jobKey"]
        token = secrets.token_urlsafe(32)
        process = self.start(
            [
                self.docker,
                "exec",
                "-i",
                instance_id,
                "/usr/local/bin/python3",
                "/opt/isign/runner/guest_stdio.py",
            ]
        )
        http = StdioHTTP(process, identity, key, self.audience, token)
        delegate = t.HTTPSGuestChannel(lambda _: http, key)
        provisional = {
            "http": http,
            "stdioDelegate": delegate,
            "process": process,
            "instanceId": instance_id,
        }
        try:
            write_frame(
                process.stdin,
                canonical(
                    {
                        "identity": identity,
                        "evidence": request["evidence"],
                        "jobKey": base64.b64encode(key).decode(),
                        "token": token,
                        "audience": self.audience,
                    }
                ),
            )
            session = delegate.authenticate(instance_id, request)
            session["channel"]["stdioDelegate"] = delegate
            session["channel"]["process"] = process
            self.channels[instance_id] = session["channel"]
            return session
        except Exception:
            self.abort(provisional)
            raise

    def send_source(self, ch, *args, **kwargs):
        return ch["stdioDelegate"].send_source(ch, *args, **kwargs)

    def analyze(self, ch, *args):
        return ch["stdioDelegate"].analyze(ch, *args)

    def execute(self, ch, *args):
        return ch["stdioDelegate"].execute(ch, *args)

    def artifact(self, ch, *args):
        return ch["stdioDelegate"].artifact(ch, *args)

    def material_prepare(self, ch, *args):
        return ch["stdioDelegate"].material_prepare(ch, *args)

    def bootstrap_prepare(self, ch, *args):
        return ch["stdioDelegate"].bootstrap_prepare(ch, *args)

    def device_profile_verify(self, ch, *args):
        return ch["stdioDelegate"].device_profile_verify(ch, *args)

    def abort(self, ch):
        ch["revoked"] = True
        try:
            ch["process"].kill()
        except (OSError, ProcessLookupError):
            pass
        try:
            ch["process"].wait(timeout=5)
        except Exception as exc:
            raise ValueError("STDIO_PROCESS_CLEANUP_UNCONFIRMED") from exc
        self.channels.pop(ch.get("instanceId"), None)
        if ch.get("stdioDelegate"):
            ch["stdioDelegate"].key = b""
            ch["stdioDelegate"].resolve = lambda _: None
        if ch.get("http"):
            ch["http"].key = b""
            ch["http"].token = ""
            ch["http"].instance_binding = {}
        for stream in (ch["process"].stdin, ch["process"].stdout, ch["process"].stderr):
            if stream:
                try:
                    stream.close()
                except OSError:
                    pass

    def revoke(self, ch):
        try:
            return ch["stdioDelegate"].revoke(ch)
        finally:
            self.abort(ch)
