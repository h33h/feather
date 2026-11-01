"""Pinned HTTPS transport; no listener, discovery, provisioning or host parsing."""

import base64, hashlib, hmac, http.client, json, re, secrets, ssl, time, urllib.parse, importlib.util, pathlib, threading

import protocol.bounded_io as bounded_io
from protocol.errors import EXPECTED_IPA_FAILURES, ExpectedGuestFailure

from protocol.codec import canonical as canonical
from protocol.limits import (
    ARTIFACT_BATCH_LIMIT as ARTIFACT_BATCH_LIMIT,
    ARTIFACT_SLICE_BYTES as ARTIFACT_SLICE_BYTES,
)


class PinnedHTTPS:
    def __init__(
        self,
        url,
        *,
        token,
        audience,
        certificate_sha256,
        ssl_context=None,
        connection_factory=None,
        instance_binding=None,
        reuse_connections=False,
    ):
        parsed = urllib.parse.urlsplit(url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in ("", "/")
            or not re.fullmatch("[a-f0-9]{64}", certificate_sha256)
            or not isinstance(token, str)
            or len(token) < 32
            or not audience
        ):
            raise ValueError("PINNED_HTTPS_CONFIGURATION_REQUIRED")
        self.host = parsed.hostname
        self.port = parsed.port or 443
        self.token = token
        self.audience = audience
        self.pin = certificate_sha256
        self.context = ssl_context or ssl.create_default_context()
        self.factory = connection_factory or http.client.HTTPSConnection
        self.instance_binding = instance_binding
        self.reuse_connections = reuse_connections
        self._connection = None
        self._connection_used_at = 0
        self._connection_lock = threading.RLock()
        if self.context.verify_mode != ssl.CERT_REQUIRED or not self.context.check_hostname:
            raise ValueError("TLS_VERIFICATION_REQUIRED")

    def request(self, path, body, *, headers=None, max_response=8 << 20):
        if path != "/api/internal/runner/authorize" and not re.fullmatch(r"/v1/[a-z0-9_/-]+", path):
            raise ValueError("HTTPS_ROUTE_REJECTED")
        if self.reuse_connections:
            if path != "/api/internal/runner/authorize":
                raise ValueError("HTTPS_ROUTE_REJECTED")
            with self._connection_lock:
                return self._request(path, body, headers=headers, max_response=max_response)
        return self._request(path, body, headers=headers, max_response=max_response)

    def close(self):
        with self._connection_lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None

    def _request(self, path, body, *, headers, max_response):
        if self._connection is not None and time.monotonic() - self._connection_used_at >= 30:
            self.close()
        connection = self._connection or self.factory(
            self.host, self.port, context=self.context, timeout=120
        )
        reusable = False
        try:
            if connection.sock is None:
                connection.connect()
            if (
                hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest()
                != self.pin
            ):
                raise ValueError("TLS_PEER_PIN_MISMATCH")
            request_headers = {
                "authorization": "Bearer " + self.token,
                "x-runner-audience": self.audience,
                "content-type": "application/json",
                **(headers or {}),
            }
            connection.request(
                "POST",
                path,
                body=body,
                headers=request_headers,
                encode_chunked=not isinstance(body, bytes),
            )
            response = connection.getresponse()
            result = response.read(max_response + 1)
            if len(result) > max_response or response.status != 200:
                raise ValueError("HTTPS_RESPONSE_REJECTED")
            reusable = (
                self.reuse_connections and not response.will_close and connection.sock is not None
            )
            if reusable:
                self._connection = connection
                self._connection_used_at = time.monotonic()
            return result
        finally:
            if not reusable:
                connection.close()
                self._connection = None


class HttpBindingAuthorizer:
    """Fixed server DAL endpoint confirms current lease without trusting caller state."""

    def __init__(self, transport, proof_key, *, clock=lambda: int(time.time() * 1000)):
        if not isinstance(proof_key, bytes) or len(proof_key) < 32:
            raise ValueError("AUTHORIZER_KEY_REQUIRED")
        self.http = transport
        self.key = proof_key
        self.clock = clock

    def __call__(self, *args):
        if len(args) == 3:
            _, operation, binding = args
        elif len(args) == 2:
            operation, binding = args
        else:
            raise ValueError("AUTHORIZER_BINDING_REQUIRED")
        nonce = secrets.token_urlsafe(32)
        request = {
            "operation": operation,
            "binding": binding,
            "nonce": nonce,
            "audience": self.http.audience,
        }
        envelope = json.loads(
            self.http.request(
                "/api/internal/runner/authorize", canonical(request), max_response=65536
            )
        )
        report = envelope.get("report", {})
        signature = hmac.new(self.key, canonical(report), hashlib.sha256).hexdigest()
        expected = {
            "version": 1,
            "operation": "authorize-binding",
            "requestOperation": operation,
            "binding": binding,
            "nonce": nonce,
            "audience": self.http.audience,
            "authorized": True,
        }
        if (
            not isinstance(report, dict)
            or set(report) != set(expected) | {"checkedAt", "expiresAt"}
            or any(report[k] != v for k, v in expected.items())
            or type(report["checkedAt"]) is not int
            or type(report["expiresAt"]) is not int
            or not self.clock() - 30000 <= report["checkedAt"] <= self.clock() + 1000
            or not self.clock() < report["expiresAt"] <= report["checkedAt"] + 15000
            or not isinstance(envelope.get("attestation"), str)
            or not hmac.compare_digest(signature, envelope["attestation"])
        ):
            raise ValueError("BINDING_AUTHORIZATION_REJECTED")
        return True


class HTTPSGuestChannel:
    """Resolver is trusted deployment configuration for an already launched VM."""

    def __init__(self, resolve_transport, proof_key, *, clock=lambda: int(time.time() * 1000)):
        if (
            not callable(resolve_transport)
            or not isinstance(proof_key, bytes)
            or len(proof_key) < 32
        ):
            raise ValueError("GUEST_TRANSPORT_CONFIGURATION_REQUIRED")
        self.resolve = resolve_transport
        self.key = proof_key
        self.clock = clock

    def call(self, channel, operation, payload, *, source=None, digest=None, max_bytes=1 << 30):
        if channel.get("revoked") and operation != "destroy":
            raise ValueError("GUEST_CHANNEL_REVOKED")
        binding = {
            "ownerId": channel["ownerId"],
            "jobId": channel["jobId"],
            "instanceId": channel["instanceId"],
            "nonce": secrets.token_hex(24),
            "expiresAt": self.clock() + 30000
            if operation == "destroy"
            else min(channel["expiresAt"], self.clock() + 120000),
        }
        report = {
            "binding": binding,
            "operation": operation,
            "audience": channel["http"].audience,
            "payloadDigest": digest or hashlib.sha256(canonical(payload)).hexdigest(),
        }
        signature = hmac.new(
            self.key, b"isign-guest-request-v1\0" + canonical(report), hashlib.sha256
        ).hexdigest()
        if source is None:
            raw = channel["http"].request(
                "/v1/guest/" + operation,
                canonical({"request": report, "attestation": signature, "payload": payload}),
            )
        else:

            def bounded():
                size = 0
                for chunk in source:
                    if not isinstance(chunk, bytes) or not chunk or len(chunk) > 1 << 20:
                        raise ValueError("SOURCE_CHUNK_INVALID")
                    size += len(chunk)
                    if size > max_bytes:
                        raise ValueError("SOURCE_LIMIT")
                    yield chunk

            cancel = getattr(source, "cancel", None)
            if not callable(cancel) and isinstance(source, (list, tuple)):
                cancel = lambda: None
            body = bounded_io.CancellableIterator(bounded(), cancel)
            raw = channel["http"].request(
                "/v1/guest/source",
                body,
                headers={
                    "content-type": "application/octet-stream",
                    "x-guest-request": canonical(report).decode(),
                    "x-guest-attestation": signature,
                },
            )
        envelope = json.loads(raw)
        if not isinstance(envelope, dict):
            raise ValueError("GUEST_RESPONSE_UNTRUSTED")
        response = envelope.get("response")
        failed = "error" in envelope
        field = "error" if failed else "value"
        expected = {"request": report, field: envelope.get(field)}
        if (
            set(envelope) != {"response", field, "attestation"}
            or response != expected
            or not isinstance(envelope.get("attestation"), str)
            or not hmac.compare_digest(
                hmac.new(
                    self.key, b"isign-guest-response-v1\0" + canonical(response), hashlib.sha256
                ).hexdigest(),
                envelope["attestation"],
            )
        ):
            raise ValueError("GUEST_RESPONSE_UNTRUSTED")
        if failed:
            code = envelope["error"]
            if (
                operation not in ("source", "analyze", "execute")
                or not isinstance(code, str)
                or code not in EXPECTED_IPA_FAILURES
            ):
                raise ValueError("GUEST_RESPONSE_UNTRUSTED")
            raise ExpectedGuestFailure(code)
        return envelope["value"]

    def authenticate(self, instance_id, request):
        http = self.resolve(instance_id)
        identity = http.instance_binding
        if (
            not isinstance(identity, dict)
            or set(identity) != {"ownerId", "jobId", "instanceId", "expiresAt"}
            or identity["ownerId"] != request["ownerId"]
            or identity["jobId"] != request["jobId"]
            or identity["instanceId"] != instance_id
            or type(identity["expiresAt"]) is not int
            or not self.clock() < identity["expiresAt"] <= self.clock() + request["maxRuntimeMs"]
        ):
            raise ValueError("LAUNCHER_GUEST_BINDING_REQUIRED")
        channel = {"http": http, **identity, "revoked": False}
        value = self.call(channel, "authenticate", {})
        return {
            "channel": channel,
            "evidence": value["evidence"],
            "binding": {k: channel[k] for k in ("ownerId", "jobId", "instanceId")},
            "authenticated": True,
        }

    def send_source(self, channel, chunks, digest, *, max_bytes):
        return self.call(channel, "source", {}, source=chunks, digest=digest, max_bytes=max_bytes)

    def analyze(self, channel, grant, proof):
        return self.call(channel, "analyze", {"grant": grant, "proof": proof})

    def execute(self, channel, grant, task, proof):
        return self.call(channel, "execute", {"grant": grant, "task": task, "proof": proof})

    def material_prepare(self, channel, grant, payload, proof):
        return self.call(
            channel, "material-prepare", {"grant": grant, "payload": payload, "proof": proof}
        )

    def bootstrap_prepare(self, channel, binding, payload, grant, proof):
        return self.call(
            channel,
            "bootstrap-prepare",
            {"binding": binding, "payload": payload, "grant": grant, "proof": proof},
        )

    def device_profile_verify(self, channel, binding, payload, grant, proof):
        return self.call(
            channel,
            "device-profile-verify",
            {"binding": binding, "payload": payload, "grant": grant, "proof": proof},
        )

    def artifact(self, channel, ref):
        offset = 0

        def active():
            if channel.get("revoked"):
                raise ValueError("GUEST_CHANNEL_REVOKED")
            if channel["expiresAt"] <= self.clock():
                raise ValueError("GUEST_CHANNEL_EXPIRED")

        while True:
            active()
            value = self.call(
                channel,
                "artifact",
                {"ref": ref, "offset": offset, "maxBytes": ARTIFACT_BATCH_LIMIT},
            )
            if (
                not isinstance(value, dict)
                or set(value) != {"data", "offset", "done"}
                or type(value["offset"]) is not int
                or value["offset"] != offset
                or type(value["done"]) is not bool
                or not isinstance(value["data"], str)
                or len(value["data"]) > 4 * ((ARTIFACT_BATCH_LIMIT + 2) // 3)
            ):
                raise ValueError("ARTIFACT_CHUNK_INVALID")
            try:
                chunk = base64.b64decode(value["data"], validate=True)
            except ValueError as exc:
                raise ValueError("ARTIFACT_CHUNK_INVALID") from exc
            if len(chunk) > ARTIFACT_BATCH_LIMIT:
                raise ValueError("ARTIFACT_CHUNK_INVALID")
            # Keep broker authorization/cancellation at its existing 64 KiB
            # cadence. Do not fetch the next batch until every slice is consumed.
            for start in range(0, len(chunk), ARTIFACT_SLICE_BYTES):
                active()
                yield chunk[start : start + ARTIFACT_SLICE_BYTES]
            if chunk:
                offset += len(chunk)
            if value["done"] is True:
                break
            if not chunk:
                raise ValueError("ARTIFACT_STREAM_INVALID")

    def revoke(self, channel):
        if channel.get("revoked"):
            return True
        value = self.call(channel, "destroy", {})
        if value != {"destroyed": True}:
            raise ValueError("GUEST_DESTRUCTION_UNCONFIRMED")
        channel["revoked"] = True
        return True
