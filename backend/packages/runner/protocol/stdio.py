"""Persistent Docker exec stdin channel: bounded frames, no mounts or network."""

from runner_diagnostics import log_failure

import base64, hashlib, hmac, importlib.util, json, pathlib, secrets, select, subprocess, threading, time

from protocol.codec import canonical

from protocol.framing import (
    MAX_FRAME as MAX_FRAME,
    read_frame as read_frame,
    write_frame as write_frame,
)


class StdioHTTP:
    """Adapts framed authenticated messages to existing request envelope semantics."""

    def __init__(
        self, process, identity, key, audience, token, timeout=120, *, execute_timeout=900
    ):
        if not 0 < timeout <= 120 or not 0 < execute_timeout <= 900:
            raise ValueError("STDIO_TIMEOUT_INVALID")
        self.process = process
        self.instance_binding = dict(identity)
        self.key = key
        self.audience = audience
        self.token = token
        self.lock = threading.Lock()
        self.timeout = timeout
        self.execute_timeout = execute_timeout

    def _deadline(self, path, body):
        started = time.monotonic()
        if path != "/v1/guest/execute" or not isinstance(body, bytes):
            return started + self.timeout

        # Only this locally authenticated envelope authorizes a longer compute wait.
        # Its short request-binding TTL remains admission authority, not compute time.
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise ValueError("duplicate key")
                result[key] = value
            return result

        try:
            if len(body) > MAX_FRAME or len(self.key) < 32:
                raise ValueError("invalid envelope")
            envelope = json.loads(body, object_pairs_hook=pairs)
            request = envelope["request"]
            payload = envelope["payload"]
            identity = self.instance_binding
            now = time.time() * 1000
            if (
                set(envelope) != {"request", "attestation", "payload"}
                or set(request) != {"binding", "operation", "audience", "payloadDigest"}
                or request["operation"] != "execute"
                or request["audience"] != self.audience
            ):
                raise ValueError("invalid request")
            signature = hmac.new(
                self.key, b"isign-guest-request-v1\0" + canonical(request), hashlib.sha256
            ).hexdigest()
            if not isinstance(envelope["attestation"], str) or not hmac.compare_digest(
                signature, envelope["attestation"]
            ):
                raise ValueError("invalid MAC")
            binding = request["binding"]
            if (
                set(identity) != {"ownerId", "jobId", "instanceId", "expiresAt"}
                or type(identity["expiresAt"]) is not int
                or identity["expiresAt"] <= now
            ):
                raise ValueError("invalid identity")
            if (
                set(binding) != {"ownerId", "jobId", "instanceId", "nonce", "expiresAt"}
                or any(binding[k] != identity[k] for k in ("ownerId", "jobId", "instanceId"))
                or type(binding["expiresAt"]) is not int
                or not now < binding["expiresAt"] <= min(identity["expiresAt"], now + 120000)
                or not isinstance(binding["nonce"], str)
                or not 16 <= len(binding["nonce"]) <= 128
            ):
                raise ValueError("invalid binding")
            if (
                set(payload) != {"grant", "task", "proof"}
                or request["payloadDigest"] != hashlib.sha256(canonical(payload)).hexdigest()
            ):
                raise ValueError("invalid payload")
            grant = payload["grant"]
            # Reuse the guest's grant schema without relaxing any quotas or plan checks.
            from protocol import grants as analyzer

            analyzer.validate_grant(grant, now=now)
            if (
                any(grant[k] != identity[k] for k in ("ownerId", "jobId"))
                or grant["isolationInstanceId"] != identity["instanceId"]
                or grant["expiresAt"] > identity["expiresAt"]
                or not isinstance(payload["task"], dict)
                or grant.get("planDigest") != hashlib.sha256(canonical(payload["task"])).hexdigest()
            ):
                raise ValueError("invalid grant")
            return started + min(
                self.execute_timeout, (min(identity["expiresAt"], grant["expiresAt"]) - now) / 1000
            )
        except (ValueError, TypeError, KeyError, RecursionError) as exc:
            raise ValueError("STDIO_EXECUTE_AUTHORIZATION_REJECTED") from exc

    def _kill(self):
        try:
            self.process.kill()
        except (OSError, ProcessLookupError):
            pass

    def request(self, path, body, *, headers=None, **kwargs):
        streaming = not isinstance(body, bytes)
        cancel = getattr(body, "cancel", None)
        if streaming and not callable(cancel):
            raise ValueError("CANCELLABLE_SOURCE_REQUIRED")
        deadline = self._deadline(path, body)
        done = threading.Event()
        result = []
        reader = None
        acquired = False
        timer = threading.Timer(max(0, deadline - time.monotonic()), self._kill)

        def worker():
            try:
                result.append((True, self._request(path, body, headers=headers, **kwargs)))
            except BaseException as exc:
                result.append((False, exc))
            finally:
                done.set()

        timer.start()
        try:
            acquired = self.lock.acquire(timeout=max(0, deadline - time.monotonic()))
            if not acquired or time.monotonic() >= deadline:
                raise ValueError("STDIO_REQUEST_TIMEOUT")
            reader = threading.Thread(target=worker, name="isign-stdio-request")
            reader.start()
            if not done.wait(max(0, deadline - time.monotonic())) or time.monotonic() >= deadline:
                raise ValueError("STDIO_REQUEST_TIMEOUT")
            reader.join()
            valid, value = result[0]
            if not valid:
                raise value
            return value
        except BaseException as exc:
            log_failure(
                "runner_stdio_failed",
                exc,
                path=path,
                instanceId=self.instance_binding.get("instanceId"),
                jobId=self.instance_binding.get("jobId"),
                streaming=streaming,
                secrets=(self.token, self.key),
            )
            self._kill()
            try:
                if streaming:
                    cancel()
            finally:
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    raise ValueError("STDIO_PROCESS_CLEANUP_UNCONFIRMED")
                finally:
                    if reader is not None:
                        reader.join(5)
                        if reader.is_alive():
                            raise ValueError("CANCELLABLE_SOURCE_CONTRACT_FAILED")
            raise
        finally:
            timer.cancel()
            timer.join()
            if acquired:
                self.lock.release()

    def _request(self, path, body, *, headers=None, **kwargs):
        headers = headers or {}
        streaming = not isinstance(body, bytes)
        message = {
            "path": path,
            "headers": {
                "authorization": "Bearer " + self.token,
                "x-runner-audience": self.audience,
                **headers,
            },
            "streaming": streaming,
            "body": None if streaming else base64.b64encode(body).decode(),
        }
        write_frame(self.process.stdin, canonical(message))
        if streaming:
            for chunk in body:
                for offset in range(0, len(chunk), 65536):
                    write_frame(self.process.stdin, chunk[offset : offset + 65536])
            write_frame(self.process.stdin, b"")
        response = json.loads(read_frame(self.process.stdout))
        if (
            not isinstance(response, dict)
            or set(response) != {"status", "body"}
            or response["status"] != "200 OK"
            or not isinstance(response["body"], str)
        ):
            raise ValueError("GUEST_STDIO_RESPONSE_REJECTED")
        raw = base64.b64decode(response["body"], validate=True)
        if len(raw) > MAX_FRAME:
            raise ValueError("GUEST_STDIO_RESPONSE_LIMIT")
        return raw
