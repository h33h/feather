"""Authenticated bounded runner HTTP/WSGI composition. Import never opens a socket.

The host only streams opaque IPA bytes to/from a trusted guest channel. All static
analysis and signing stay in that guest. Deployment supplies trusted backend,
current-binding authorizer, TLS listener and explicitly enabled control bridges.
"""

from runner_diagnostics import log_failure

import base64, hashlib, hmac, importlib.util, json, os, pathlib, re, sqlite3, threading, time

import protocol.proofs as native
from protocol.bounded_io import CancellableIterator
from protocol.errors import ExpectedGuestFailure

canonical = native.canonical
REQUIRED_ISOLATION = native.REQUIRED_ISOLATION
REQUIRED_CHECKS = (
    "archive",
    "components",
    "signatures",
    "profiles",
    "device",
    "entitlements",
    "mapping",
)
MAX_JSON = 4 << 20
# Request-local polling applies only to opaque source uploads, never grants or signing.
SOURCE_AUTHORIZATION_INTERVAL = 1.0
SOURCE_AUTHORIZATION_BYTES = 1 << 20


class BrokerError(ValueError):
    def __init__(self, code, status=400):
        super().__init__(code)
        self.code = code
        self.status = status


class Response:
    def __init__(self, status, body=(), headers=None):
        self.status = status
        self.body = body
        self.headers = headers or {"content-type": "application/json", "cache-control": "no-store"}


class SQLiteBrokerState:
    """Persistent nonce consumption and recovery tombstones; no IPA/key storage."""

    def __init__(self, path):
        self.path = pathlib.Path(path).absolute()
        if self.path.is_symlink():
            raise BrokerError("STATE_PATH_REJECTED")
        self.db = sqlite3.connect(str(self.path), check_same_thread=False, isolation_level=None)
        os.chmod(self.path, 0o600)
        self.lock = threading.Lock()
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("CREATE TABLE IF NOT EXISTS consumed (nonce_hash TEXT PRIMARY KEY)")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS instances (id TEXT PRIMARY KEY, metadata TEXT NOT NULL, dead INTEGER NOT NULL DEFAULT 0)"
        )

    def consume(self, principal, operation, nonce):
        key = hashlib.sha256(canonical([principal, operation, nonce])).hexdigest()
        with self.lock:
            try:
                self.db.execute("INSERT INTO consumed VALUES (?)", (key,))
                return True
            except sqlite3.IntegrityError:
                return False

    def save(self, instance_id, metadata):
        with self.lock:
            self.db.execute(
                "INSERT INTO instances VALUES (?,?,0)",
                (instance_id, canonical(metadata).decode("utf8")),
            )

    def tombstone(self, instance_id):
        with self.lock:
            self.db.execute("UPDATE instances SET dead=1 WHERE id=?", (instance_id,))

    def pending(self):
        with self.lock:
            return [
                (row[0], json.loads(row[1]))
                for row in self.db.execute("SELECT id,metadata FROM instances WHERE dead=0")
            ]

    def close(self):
        self.db.close()


def strict_json(raw):
    def pairs(values):
        obj = {}
        for k, v in values:
            if k in obj:
                raise BrokerError("JSON_DUPLICATE_KEY")
            obj[k] = v
        return obj

    try:
        return json.loads(
            raw.decode("utf8"),
            object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(BrokerError("JSON_NUMBER_INVALID")),
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise BrokerError("JSON_INVALID") from exc


class BrokerController:
    def __init__(
        self,
        *,
        token,
        audience,
        proof_key,
        state,
        backend,
        authorize_binding,
        control_handlers=None,
        device_cms_verifier=None,
        sealed_materials_bridge=False,
        bootstrap_bridge=False,
        clock=lambda: int(time.time() * 1000),
    ):
        required = (
            "launch",
            "verify_instance",
            "upload_source",
            "analyze",
            "execute",
            "verify_guest_report",
            "artifact",
            "destroy",
        )
        if (
            not isinstance(token, str)
            or len(token) < 32
            or not isinstance(audience, str)
            or not audience
            or not isinstance(proof_key, bytes)
            or len(proof_key) < 32
            or not all(callable(getattr(backend, k, None)) for k in required)
            or not callable(authorize_binding)
        ):
            raise BrokerError("TRUSTED_BROKER_CONFIGURATION_REQUIRED", 503)
        self.token_hash = hashlib.sha256(token.encode()).digest()
        self.audience = audience
        self.key = proof_key
        self.state = state
        self.backend = backend
        self.authorize = authorize_binding
        self.controls = control_handlers or {}
        self.device_cms_verifier = device_cms_verifier
        self.sealed_bridge = sealed_materials_bridge
        self.bootstrap_bridge = bootstrap_bridge
        self.clock = clock
        self.instances = {}
        self.launching = {}
        self.retired_launches = set()
        self.lock = threading.Lock()
        self.principal = hashlib.sha256(token.encode()).hexdigest()
        self.recovery_ready = not bool(self.state.pending()) and not callable(
            getattr(backend, "recover_orphans", None)
        )

    def envelope(self, report, extra=None):
        body = {
            "report": report,
            "attestation": hmac.new(self.key, canonical(report), hashlib.sha256).hexdigest(),
            **(extra or {}),
        }
        data = canonical(body)
        if len(data) > MAX_JSON:
            raise BrokerError("RESPONSE_LIMIT", 502)
        return Response(200, [data])

    def json_body(self, chunks):
        data = bytearray()
        for chunk in chunks:
            if not isinstance(chunk, bytes):
                raise BrokerError("BODY_INVALID")
            data.extend(chunk)
            if len(data) > MAX_JSON:
                raise BrokerError("JSON_LIMIT", 413)
        value = strict_json(bytes(data))
        if not isinstance(value, dict):
            raise BrokerError("JSON_OBJECT_REQUIRED")
        return value

    def allowed(self, operation, binding):
        if self.authorize(self.principal, operation, binding) is not True:
            raise BrokerError("BINDING_NOT_CURRENT", 403)

    def consume(self, operation, nonce):
        if not isinstance(nonce, str) or not re.fullmatch("[A-Za-z0-9_-]{1,128}", nonce):
            raise BrokerError("NONCE_REQUIRED")
        if not self.state.consume(self.principal, operation, nonce):
            raise BrokerError("NONCE_REPLAY", 409)

    def resource(self, instance_id, *, for_destroy=False):
        with self.lock:
            resource = self.instances.get(instance_id)
        if resource is None:
            raise BrokerError("INSTANCE_UNAVAILABLE", 404)
        if resource["dead"] and not for_destroy:
            raise BrokerError("INSTANCE_DESTROYED", 410)
        if not for_destroy and resource["expiresAt"] <= self.clock():
            self.destroy(resource)
            raise BrokerError("INSTANCE_EXPIRED", 410)
        self.allowed(
            "destroy" if for_destroy else "instance",
            {
                "ownerId": resource["ownerId"],
                "jobId": resource["jobId"],
                "isolationInstanceId": instance_id,
            },
        )
        return resource

    def destroy(self, resource):
        with self.lock:
            resource["dead"] = True
            resource["busy"] = not resource.get("destroyed", False)
            resource.pop("artifact", None)
            destruction = resource.setdefault("destructionLock", threading.Lock())
        with destruction:
            if resource.get("destroyed"):
                return True
            if self.backend.destroy(resource["handle"]) is not True:
                raise BrokerError("DESTRUCTION_UNCONFIRMED", 503)
            self.state.tombstone(resource["id"])
            with self.lock:
                resource["destroyed"] = True
                resource["busy"] = False
            return True

    def grant(self, resource, grant):
        try:
            native.analyzer.validate_grant(grant, now=self.clock())
        except (ValueError, TypeError):
            raise BrokerError("GRANT_INVALID", 409)
        if (
            grant["ownerId"] != resource["ownerId"]
            or grant["jobId"] != resource["jobId"]
            or grant["isolationInstanceId"] != resource["id"]
            or grant["expiresAt"] > resource["expiresAt"]
            or grant["uploadDigest"] != resource.get("sourceDigest")
        ):
            raise BrokerError("GRANT_BINDING_MISMATCH", 403)
        self.allowed("grant", grant)

    def begin(self, resource, *, expected_artifact=None):
        with self.lock:
            if expected_artifact is not None and (
                resource.get("artifact") is not expected_artifact or expected_artifact["used"]
            ):
                raise BrokerError("ARTIFACT_UNAVAILABLE", 404)
            if resource["dead"]:
                raise BrokerError("INSTANCE_DESTROYED", 410)
            if resource.get("busy"):
                raise BrokerError("INSTANCE_BUSY", 409)
            resource["busy"] = True

    def end(self, resource):
        with self.lock:
            # An unconfirmed destroy must not release the active operation slot.
            if not resource["dead"] or resource.get("destroyed"):
                resource["busy"] = False

    def dispatch(self, method, path, headers, chunks, *, tls=False):
        try:
            headers = {str(k).lower(): v for k, v in headers.items()}
            if not tls:
                raise BrokerError("TLS_REQUIRED", 403)
            auth = headers.get("authorization", "")
            if (
                not isinstance(auth, str)
                or not auth.startswith("Bearer ")
                or not hmac.compare_digest(
                    hashlib.sha256(auth[7:].encode()).digest(), self.token_hash
                )
            ):
                raise BrokerError("AUTHENTICATION_REQUIRED", 401)
            if headers.get("x-runner-audience") != self.audience:
                raise BrokerError("AUDIENCE_MISMATCH", 403)
            if not self.recovery_ready:
                raise BrokerError("BROKER_RECOVERY_REQUIRED", 503)
            if method not in ("POST", "DELETE") or not re.fullmatch(r"/v1/[A-Za-z0-9_/-]+", path):
                raise BrokerError("ROUTE_INVALID", 404)
            is_source = path.endswith("/source")
            content = headers.get("content-type", "").split(";")[0].strip()
            if content != ("application/octet-stream" if is_source else "application/json"):
                raise BrokerError("CONTENT_TYPE_INVALID", 415)
            if path == "/v1/retire-launch" and method == "POST":
                return self.retire_launch(self.json_body(chunks))
            if path == "/v1/instances" and method == "POST":
                return self.launch(self.json_body(chunks))
            if path.startswith("/v1/control/") and method == "POST":
                return self.control(path.rsplit("/", 1)[1], self.json_body(chunks))
            parts = path.split("/")
            if len(parts) < 4 or parts[1:3] != ["v1", "instances"]:
                raise BrokerError("ROUTE_INVALID", 404)
            resource = self.resource(parts[3], for_destroy=method == "DELETE" and len(parts) == 4)
            if method == "DELETE" and len(parts) == 4:
                if self.json_body(chunks) != {}:
                    raise BrokerError("BODY_INVALID")
                self.destroy(resource)
                return Response(204)
            if method != "POST":
                raise BrokerError("ROUTE_INVALID", 404)
            if len(parts) == 5 and parts[4] == "source":
                return self.source(resource, headers, chunks)
            body = self.json_body(chunks)
            if len(parts) == 6 and parts[4] == "artifacts":
                return self.artifact(resource, parts[5], body, execution_source=chunks)
            if len(parts) == 5 and parts[4] in ("analyze", "execute"):
                return self.operation(resource, parts[4], body, execution_source=chunks)
            raise BrokerError("ROUTE_INVALID", 404)
        except (BrokerError, ExpectedGuestFailure) as exc:
            if isinstance(exc, ExpectedGuestFailure):
                exc = BrokerError(exc.code, 422)
            log_failure(
                "runner_broker_rejected",
                exc,
                method=method,
                path=path,
                status=exc.status,
                secrets=(headers.get("authorization", ""), self.key),
            )
            return Response(exc.status, [canonical({"error": exc.code})])
        except Exception as exc:
            log_failure(
                "runner_broker_failed",
                exc,
                method=method,
                path=path,
                secrets=(headers.get("authorization", ""), self.key),
            )
            return Response(503, [canonical({"error": "BROKER_OPERATION_FAILED"})])

    def launch(self, request):
        fields = {
            "ownerId",
            "jobId",
            "nonce",
            "audience",
            "maxRuntimeMs",
            "maxInputBytes",
            "maxUnpackedBytes",
            "maxEntries",
        }
        if (
            set(request) != fields
            or request["audience"] != self.audience
            or any(
                not isinstance(request[k], str)
                or not re.fullmatch("[A-Za-z0-9_-]{1,128}", request[k])
                for k in ("ownerId",)
            )
            or not isinstance(request["jobId"], str)
            or not re.fullmatch("[A-Za-z0-9_:-]{1,128}", request["jobId"])
            or type(request["maxRuntimeMs"]) is not int
            or not 1000 <= request["maxRuntimeMs"] <= 900000
            or any(
                type(request[k]) is not int or not 0 < request[k] <= limit
                for k, limit in (
                    ("maxInputBytes", 1 << 30),
                    ("maxUnpackedBytes", 4 << 30),
                    ("maxEntries", 20000),
                )
            )
        ):
            raise BrokerError("LAUNCH_INVALID")
        self.allowed("launch", request)
        self.consume("launch", request["nonce"])
        nonce = request["nonce"]
        entry = {"event": threading.Event(), "handle": None}
        with self.lock:
            if nonce in self.retired_launches:
                raise BrokerError("LAUNCH_RETIRED", 409)
            self.launching[nonce] = entry
        try:
            try:
                handle = self.backend.launch(request)
            except ValueError as error:
                if str(error) == "GLOBAL_EXECUTOR_SLOT_UNAVAILABLE":
                    raise BrokerError("RUNNER_BUSY", 409) from error
                raise
            entry["handle"] = handle
            if (
                not isinstance(handle, dict)
                or not re.fullmatch("[A-Za-z0-9_-]{1,128}", str(handle.get("id", "")))
                or type(handle.get("expiresAt")) is not int
                or not self.clock() < handle["expiresAt"] <= self.clock() + request["maxRuntimeMs"]
                or not isinstance(handle.get("evidence"), dict)
                or not native.validated_isolation(handle["evidence"])
                or self.backend.verify_instance(handle, request) is not True
            ):
                raise BrokerError("TRUSTED_VM_PROOF_REQUIRED", 503)
            report = {k: request[k] for k in ("ownerId", "jobId", "nonce", "audience")}
            report.update(id=handle["id"], disposable=True, expiresAt=handle["expiresAt"])
            resource = {
                **report,
                "handle": handle,
                "dead": False,
                "maxInputBytes": request["maxInputBytes"],
            }
            with self.lock:
                if nonce in self.retired_launches:
                    raise BrokerError("LAUNCH_RETIRED", 409)
                if handle["id"] in self.instances:
                    raise BrokerError("INSTANCE_ID_COLLISION", 409)
                self.state.save(handle["id"], report)
                self.instances[handle["id"]] = resource
            entry["handle"] = None
            return self.envelope(report)
        except Exception:
            if entry["handle"] is not None:
                if self.backend.destroy(entry["handle"]) is not True:
                    raise BrokerError("DESTRUCTION_UNCONFIRMED", 503)
                entry["handle"] = None
            raise
        finally:
            entry["event"].set()

    def retire_launch(self, request):
        if (
            set(request) != {"nonce"}
            or not isinstance(request["nonce"], str)
            or not re.fullmatch("[A-Za-z0-9_-]{1,128}", request["nonce"])
        ):
            raise BrokerError("LAUNCH_INVALID")
        nonce = request["nonce"]
        with self.lock:
            self.retired_launches.add(nonce)
            entry = self.launching.get(nonce)
        if entry and not entry["event"].wait(30):
            raise BrokerError("DESTRUCTION_UNCONFIRMED", 503)
        if entry and entry["handle"] is not None:
            if self.backend.destroy(entry["handle"]) is not True:
                raise BrokerError("DESTRUCTION_UNCONFIRMED", 503)
            entry["handle"] = None
        with self.lock:
            resources = [r for r in self.instances.values() if r["nonce"] == nonce]
        for resource in resources:
            self.destroy(resource)
        retire = getattr(self.backend, "retire_launch", None)
        if callable(retire) and retire(nonce) is not True:
            raise BrokerError("DESTRUCTION_UNCONFIRMED", 503)
        with self.lock:
            self.launching.pop(nonce, None)
        return Response(204, [])

    def source(self, resource, headers, chunks):
        digest = headers.get("x-source-digest")
        if (
            not isinstance(digest, str)
            or not re.fullmatch("[a-f0-9]{64}", digest)
            or resource.get("sourceDigest")
        ):
            raise BrokerError("SOURCE_INVALID", 409)
        self.begin(resource)
        hash_ = hashlib.sha256()
        size = 0
        complete = False
        binding = resource["handle"].get(
            "binding", {"ownerId": resource["ownerId"], "jobId": resource["jobId"]}
        )
        next_authorization = 0.0
        authorized_bytes = 0

        def authorize_source():
            nonlocal next_authorization, authorized_bytes
            checked_at = time.monotonic()
            self.allowed("source", binding)
            next_authorization = checked_at + SOURCE_AUTHORIZATION_INTERVAL
            authorized_bytes = size

        def stream():
            nonlocal size, complete
            for chunk in chunks:
                if not isinstance(chunk, bytes):
                    raise BrokerError("SOURCE_INVALID")
                if resource["dead"] or resource["expiresAt"] <= self.clock():
                    raise BrokerError("INSTANCE_EXPIRED", 410)
                if (
                    time.monotonic() >= next_authorization
                    or size + len(chunk) - authorized_bytes > SOURCE_AUTHORIZATION_BYTES
                ):
                    authorize_source()
                size += len(chunk)
                if size > resource["maxInputBytes"]:
                    raise BrokerError("SOURCE_LIMIT", 413)
                hash_.update(chunk)
                yield chunk
            complete = True

        try:
            authorize_source()
            source = stream()
            cancel = getattr(chunks, "cancel", None)
            if callable(cancel):
                source = CancellableIterator(source, cancel)
            result = self.backend.upload_source(resource["handle"], source, digest)
            if (
                not complete
                or not size
                or hash_.hexdigest() != digest
                or not isinstance(result, dict)
                or result.get("sha256") != digest
                or result.get("size") != size
            ):
                raise BrokerError("SOURCE_DIGEST_MISMATCH", 409)
            if resource["dead"]:
                raise BrokerError("INSTANCE_DESTROYED", 410)
            authorize_source()
            resource["sourceDigest"] = digest
            return Response(204)
        except Exception as exc:
            details = {
                "jobId": resource["jobId"],
                "instanceId": resource["id"],
                "bytesReceived": size,
                "complete": complete,
            }
            log_failure("runner_source_failed", exc, secrets=(self.key,), **details)
            try:
                self.destroy(resource)
            except Exception as cleanup_error:
                log_failure(
                    "runner_source_cleanup_failed", cleanup_error, secrets=(self.key,), **details
                )
                raise
            raise
        finally:
            self.end(resource)

    def operation(self, resource, operation, body, *, execution_source=None):
        if set(body) != ({"grant"} if operation == "analyze" else {"grant", "task"}):
            raise BrokerError("BODY_INVALID")
        grant = body["grant"]
        self.grant(resource, grant)
        if operation == "execute":
            if (
                not isinstance(body["task"], dict)
                or grant.get("planDigest") != hashlib.sha256(canonical(body["task"])).hexdigest()
            ):
                raise BrokerError("PLAN_DIGEST_MISMATCH", 409)
        self.begin(resource)
        execution = None
        compute_started = False
        try:
            self.consume(operation, grant["taskNonce"])
            authorize_execute = getattr(execution_source, "authorize_execute", None)
            if operation == "execute" and callable(authorize_execute):
                execution = authorize_execute(
                    min(grant["expiresAt"], resource["expiresAt"], self.clock() + 900000),
                    lambda: self.destroy(resource),
                )
                execution.check()
            compute_started = True
            result = (
                self.backend.analyze(resource["handle"], grant)
                if operation == "analyze"
                else self.backend.execute(resource["handle"], grant, body["task"])
            )
            report = result if operation == "analyze" else result.get("report")
            self.grant(resource, grant)
            if (
                not isinstance(report, dict)
                or any(report.get(k) != v for k, v in grant.items())
                or report.get("protocolVersion") != 1
                or report.get("operation") != ("analysis" if operation == "analyze" else "sign")
                or report.get("executionAuthorized") is not False
                or self.backend.verify_guest_report(report, grant, body.get("task")) is not True
            ):
                raise BrokerError("GUEST_REPORT_UNTRUSTED", 403)
            extra = None
            if operation == "analyze":
                analysis = report.get("analysis")
                if (
                    not isinstance(analysis, dict)
                    or analysis.get("sha256") != grant["uploadDigest"]
                ):
                    raise BrokerError("ANALYSIS_DIGEST_MISMATCH", 403)
            else:
                if (
                    any(report.get("checks", {}).get(k) is not True for k in REQUIRED_CHECKS)
                    or not re.fullmatch("[a-f0-9]{64}", str(report.get("artifactDigest", "")))
                    or type(report.get("artifactSize")) is not int
                    or not 0 < report["artifactSize"] <= 1 << 30
                    or not re.fullmatch("[A-Za-z0-9_-]{1,128}", str(result.get("artifactRef", "")))
                ):
                    raise BrokerError("ARTIFACT_REPORT_INVALID", 403)
                ref = result["artifactRef"]
                extra = {"artifactRef": ref}

            def publish():
                with self.lock:
                    if resource["dead"]:
                        raise BrokerError("INSTANCE_DESTROYED", 410)
                    response = self.envelope(report, extra)
                    if operation == "execute":
                        resource["artifact"] = {
                            "ref": ref,
                            "digest": report["artifactDigest"],
                            "size": report["artifactSize"],
                            "grant": dict(grant),
                            "used": False,
                        }
                    return response

            return execution.commit(publish) if execution is not None else publish()
        except Exception:
            if execution is not None:
                with self.lock:
                    resource["dead"] = True
                    resource.pop("artifact", None)
                execution.fail()
            elif operation == "execute" and compute_started:
                self.destroy(resource)
            raise
        finally:
            self.end(resource)

    def artifact(self, resource, ref, body, *, execution_source=None):
        artifact = resource.get("artifact")
        if body != {} or not artifact or ref != artifact["ref"] or artifact["used"]:
            raise BrokerError("ARTIFACT_UNAVAILABLE", 404)
        self.grant(resource, artifact["grant"])
        self.begin(resource, expected_artifact=artifact)
        execution = None
        try:
            authorize_transfer = getattr(execution_source, "authorize_execute", None)
            if callable(authorize_transfer):
                execution = authorize_transfer(
                    min(
                        artifact["grant"]["expiresAt"], resource["expiresAt"], self.clock() + 900000
                    ),
                    lambda: self.destroy(resource),
                )
                execution.check()
            with self.lock:
                if resource["dead"] or resource.get("artifact") is not artifact or artifact["used"]:
                    raise BrokerError("ARTIFACT_UNAVAILABLE", 404)
                artifact["used"] = True
        except Exception:
            if execution is not None:
                with self.lock:
                    resource["dead"] = True
                    resource.pop("artifact", None)
                execution.cancel()
            self.end(resource)
            raise

        def stream():
            size = 0
            hash_ = hashlib.sha256()
            complete = False
            try:
                # Enter the cleanup guard before headers are sent. The sentinel
                # is consumed below; no guest read or response bytes occur here.
                yield None
                for chunk in self.backend.artifact(resource["handle"], ref):
                    self.grant(resource, artifact["grant"])
                    if execution is not None:
                        execution.check()
                    if resource["dead"] or not isinstance(chunk, bytes):
                        raise BrokerError("ARTIFACT_CANCELLED", 410)
                    size += len(chunk)
                    if size > artifact["size"] or size > 1 << 30:
                        raise BrokerError("ARTIFACT_LIMIT", 502)
                    hash_.update(chunk)
                    yield chunk
                if size != artifact["size"] or hash_.hexdigest() != artifact["digest"]:
                    raise BrokerError("ARTIFACT_DIGEST_MISMATCH", 502)
                complete = True
            finally:
                if not complete and execution is not None:
                    with self.lock:
                        resource["dead"] = True
                        resource.pop("artifact", None)
                    execution.cancel()
                self.end(resource)

        response_body = stream()
        next(response_body)
        return Response(
            200,
            response_body,
            {
                "content-type": "application/octet-stream",
                "cache-control": "no-store",
                "content-length": str(artifact["size"]),
            },
        )

    def control(self, operation, body):
        if (
            set(body) != {"binding", "payload", "audience"}
            or body["audience"] != self.audience
            or not isinstance(body["binding"], dict)
            or not isinstance(body["payload"], dict)
        ):
            raise BrokerError("CONTROL_INVALID")
        binding = body["binding"]
        payload = body["payload"]
        self.allowed(operation, binding)
        nonce = binding.get("taskNonce", binding.get("nonce"))
        expiry = binding.get("expiresAt")
        if expiry is not None and (type(expiry) is not int or expiry <= self.clock()):
            raise BrokerError("CONTROL_BINDING_EXPIRED", 409)
        self.consume("control:" + operation, nonce)
        if operation == "capabilities":
            if not self.sealed_bridge or not callable(
                getattr(self.backend, "material_prepare", None)
            ):
                raise BrokerError("PRODUCTION_CAPABILITIES_UNAVAILABLE", 503)
            if (
                not callable(getattr(self.backend, "check_ready", None))
                or self.backend.check_ready() is not True
            ):
                raise BrokerError("EXECUTOR_NOT_READY", 503)
            value = {
                "executorReady": True,
                "runner": "isign-native-v1",
                "provisioning": "isign-provisioning-v1",
                "materials": "isign-sealed-materials-v1",
            }
        elif operation == "device-cms":
            if (
                not callable(self.device_cms_verifier)
                or set(binding) != {"nonce"}
                or set(payload) != {"cmsBase64", "policyId", "caSha256"}
                or not isinstance(payload["cmsBase64"], str)
                or len(payload["cmsBase64"]) > 87384
            ):
                raise BrokerError("DEVICE_CMS_UNAVAILABLE", 503)
            try:
                cms = base64.b64decode(payload["cmsBase64"], validate=True)
            except (ValueError, TypeError):
                raise BrokerError("DEVICE_CMS_INVALID")
            if not cms or len(cms) > 65536:
                raise BrokerError("DEVICE_CMS_LIMIT", 413)
            verifier = self.device_cms_verifier
            if payload["policyId"] != getattr(verifier, "policy_id", None) or payload[
                "caSha256"
            ] != getattr(verifier, "ca_sha256", None):
                raise BrokerError("DEVICE_CMS_POLICY_MISMATCH", 403)
            value = verifier(cms)
            if (
                not isinstance(value, dict)
                or not isinstance(value.get("challenge"), str)
                or any(value.get(k) is not True for k in ("signatureVerified", "issuerTrusted"))
                or not re.fullmatch("[a-f0-9]{64}", str(value.get("deviceCertificate", "")))
            ):
                raise BrokerError("DEVICE_CMS_PROOF_INVALID", 403)
            value = {
                "payload": value,
                "policyId": verifier.policy_id,
                "caSha256": verifier.ca_sha256,
            }
        elif operation == "material-prepare":
            if (
                not self.sealed_bridge
                or not callable(getattr(self.backend, "material_prepare", None))
                or set(payload) != {"sealedKey", "certificatePem", "profiles", "expected"}
            ):
                raise BrokerError("MATERIAL_GUEST_BRIDGE_UNAVAILABLE", 503)
            resource = self.resource(binding.get("isolationInstanceId", ""))
            self.grant(resource, binding)
            self.begin(resource)
            try:
                result = self.backend.material_prepare(resource["handle"], binding, payload)
                self.grant(resource, binding)
                report = result.get("report") if isinstance(result, dict) else None
                if (
                    resource["dead"]
                    or not isinstance(report, dict)
                    or report.get("version") != 1
                    or report.get("operation") != "material-prepare"
                    or report.get("binding") != binding
                    or report.get("instanceId") != resource["id"]
                    or report.get("expected") != payload["expected"]
                    or report.get("payloadDigest") != hashlib.sha256(canonical(payload)).hexdigest()
                ):
                    raise BrokerError("MATERIAL_REPORT_INVALID", 403)
                signature = hmac.new(self.key, canonical(report), hashlib.sha256).hexdigest()
                if not isinstance(result.get("attestation"), str) or not hmac.compare_digest(
                    signature, result["attestation"]
                ):
                    raise BrokerError("MATERIAL_REPORT_UNTRUSTED", 403)
                value = report.get("value")
                if (
                    not isinstance(value, dict)
                    or set(value) != {"identity", "profiles", "udid", "deviceOs"}
                    or value["udid"] != payload["expected"].get("udid")
                    or value["deviceOs"] != payload["expected"].get("deviceOs")
                    or value["identity"].get("ownerId") != binding["ownerId"]
                ):
                    raise BrokerError("MATERIAL_DESCRIPTOR_INVALID", 403)
            finally:
                self.end(resource)
        elif operation == "device-profile-verify":
            if (
                not callable(getattr(self.backend, "device_profile_verify", None))
                or set(binding)
                not in (
                    {"ownerId", "connectionId", "generation", "nonce", "expiresAt"},
                    {
                        "ownerId",
                        "connectionId",
                        "generation",
                        "nonce",
                        "expiresAt",
                        "connectionOwnerId",
                        "accessGrantId",
                        "accessGrantGeneration",
                    },
                )
                or set(payload) != {"instanceId", "cmsBase64", "expected"}
            ):
                raise BrokerError("DEVICE_PROFILE_GUEST_UNAVAILABLE", 503)
            resource = self.resource(payload["instanceId"])
            if (
                resource["ownerId"] != binding["ownerId"]
                or resource["jobId"] != "device-eligibility:" + binding["nonce"]
                or not isinstance(payload["expected"], dict)
                or not isinstance(payload["cmsBase64"], str)
                or len(payload["cmsBase64"]) > 87384
            ):
                raise BrokerError("DEVICE_PROFILE_INSTANCE_MISMATCH", 403)
            try:
                cms = base64.b64decode(payload["cmsBase64"], validate=True)
            except (ValueError, TypeError):
                raise BrokerError("DEVICE_PROFILE_CMS_INVALID")
            if not cms or len(cms) > 65536:
                raise BrokerError("DEVICE_PROFILE_CMS_LIMIT", 413)
            self.begin(resource)
            try:
                result = self.backend.device_profile_verify(resource["handle"], binding, payload)
                self.allowed(operation, binding)
                report = result.get("report") if isinstance(result, dict) else None
                if (
                    resource["dead"]
                    or not isinstance(report, dict)
                    or report.get("version") != 1
                    or report.get("operation") != "device-profile"
                    or report.get("binding") != binding
                    or report.get("instanceId") != resource["id"]
                    or report.get("expected") != payload["expected"]
                ):
                    raise BrokerError("DEVICE_PROFILE_REPORT_INVALID", 403)
                signature = hmac.new(self.key, canonical(report), hashlib.sha256).hexdigest()
                if not isinstance(result.get("attestation"), str) or not hmac.compare_digest(
                    signature, result["attestation"]
                ):
                    raise BrokerError("DEVICE_PROFILE_REPORT_UNTRUSTED", 403)
                value = report.get("value")
                if (
                    not isinstance(value, dict)
                    or value.get("digest") != hashlib.sha256(cms).hexdigest()
                    or value.get("profileType") != "ad-hoc"
                ):
                    raise BrokerError("DEVICE_PROFILE_PROOF_INVALID", 403)
            finally:
                self.end(resource)
        elif operation == "bootstrap-prepare":
            if (
                not self.bootstrap_bridge
                or not callable(getattr(self.backend, "bootstrap_prepare", None))
                or set(binding) != {"ownerId", "connectionId", "generation", "nonce", "expiresAt"}
                or set(payload) != {"instanceId", "sealGrant", "dataKey"}
            ):
                raise BrokerError("BOOTSTRAP_GUEST_BRIDGE_UNAVAILABLE", 503)
            resource = self.resource(payload["instanceId"])
            if (
                resource["ownerId"] != binding["ownerId"]
                or resource["jobId"] != "bootstrap:" + binding["nonce"]
            ):
                raise BrokerError("BOOTSTRAP_INSTANCE_BINDING_MISMATCH", 403)
            seal = payload["sealGrant"]
            if (
                not isinstance(seal, dict)
                or seal.get("lease") != binding
                or seal.get("instanceId") != resource["id"]
                or seal.get("audience") != self.audience
                or not isinstance(payload["dataKey"], str)
                or len(payload["dataKey"]) > 64
            ):
                raise BrokerError("BOOTSTRAP_SEAL_BINDING_MISMATCH", 403)
            try:
                data_key = base64.b64decode(payload["dataKey"], validate=True)
            except (ValueError, TypeError):
                raise BrokerError("BOOTSTRAP_DATA_KEY_INVALID")
            if len(data_key) != 32:
                raise BrokerError("BOOTSTRAP_DATA_KEY_INVALID")
            unsigned = {k: v for k, v in seal.items() if k != "signature"}
            signature = hmac.new(
                self.key, b"isign-bootstrap-grant-v1\0" + canonical(unsigned), hashlib.sha256
            ).hexdigest()
            if not isinstance(seal.get("signature"), str) or not hmac.compare_digest(
                signature, seal["signature"]
            ):
                raise BrokerError("BOOTSTRAP_SEAL_SIGNATURE_INVALID", 403)
            self.begin(resource)
            try:
                value = self.backend.bootstrap_prepare(resource["handle"], binding, payload)
                self.allowed(operation, binding)
                if (
                    resource["dead"]
                    or not isinstance(value, dict)
                    or not isinstance(value.get("report"), dict)
                    or value["report"].get("grant") != seal
                ):
                    raise BrokerError("BOOTSTRAP_RECEIPT_INVALID", 403)
                receipt_signature = hmac.new(
                    self.key,
                    b"isign-bootstrap-envelope-v1\0" + canonical(value["report"]),
                    hashlib.sha256,
                ).hexdigest()
                if not isinstance(value.get("attestation"), str) or not hmac.compare_digest(
                    receipt_signature, value["attestation"]
                ):
                    raise BrokerError("BOOTSTRAP_RECEIPT_UNTRUSTED", 403)
            finally:
                self.end(resource)
                data_key = b""
        else:
            handler = self.controls.get(operation)
            if (
                operation
                not in (
                    "provision",
                    "bundle-ownership",
                    "bootstrap-prepare",
                    "bootstrap-find-certificates",
                    "bootstrap-create-certificate",
                )
                or not callable(handler)
                or (operation.startswith("bootstrap-") and not self.bootstrap_bridge)
            ):
                raise BrokerError("CONTROL_UNAVAILABLE", 503)
            value = handler(binding, payload)
            self.allowed(operation, binding)
        return self.envelope(
            {"binding": binding, "operation": operation, "audience": self.audience, "value": value}
        )

    def recover(self):
        """Startup must run this before accepting requests after controller restart."""
        destroy = getattr(self.backend, "recover_destroy", None)
        pending = self.state.pending()
        if pending and not callable(destroy):
            raise BrokerError("RECOVERY_BACKEND_REQUIRED", 503)
        for instance_id, metadata in pending:
            if destroy(instance_id, metadata) is not True:
                raise BrokerError("RECOVERY_DESTRUCTION_UNCONFIRMED", 503)
            self.state.tombstone(instance_id)
        recover_orphans = getattr(self.backend, "recover_orphans", None)
        if callable(recover_orphans):
            recover_orphans()
        self.recovery_ready = True

    def wsgi(self, environ, start_response):
        # Arbitrary WSGI input has no trustworthy socket-cancellation contract.
        # The concrete http_host path calls dispatch with its owned SocketBody.
        start_response(
            "503 Service Unavailable",
            [("Content-Type", "application/json"), ("Connection", "close")],
        )
        return [b'{"error":"CANCELLABLE_HTTPS_HOST_REQUIRED"}']
