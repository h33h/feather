import math, re, time

BINDINGS = (
    "ownerId",
    "jobId",
    "leaseToken",
    "connectionId",
    "deviceId",
    "connectionGeneration",
    "uploadDigest",
    "taskNonce",
    "isolationInstanceId",
    "expiresAt",
)


def reject(code):
    raise ValueError(code)


OPTIONAL_BINDINGS = ("connectionOwnerId", "accessGrantId", "accessGrantGeneration")


def binding_fields(grant):
    return BINDINGS + tuple(k for k in OPTIONAL_BINDINGS if k in grant)


def validate_grant(grant, now=None):
    if not isinstance(grant, dict) or any(k not in grant for k in BINDINGS):
        reject("ISOLATION_GRANT_REQUIRED")
    for k in (
        "ownerId",
        "jobId",
        "leaseToken",
        "connectionId",
        "deviceId",
        "taskNonce",
        "isolationInstanceId",
    ):
        if not isinstance(grant[k], str) or not grant[k].strip():
            reject("GRANT_INVALID")
    if (
        type(grant["connectionGeneration"]) is not int
        or grant["connectionGeneration"] < 1
        or not re.fullmatch("[a-f0-9]{64}", str(grant["uploadDigest"]))
    ):
        reject("GRANT_INVALID")
    if any(k in grant for k in OPTIONAL_BINDINGS):
        if (
            not all(k in grant for k in OPTIONAL_BINDINGS)
            or not isinstance(grant["connectionOwnerId"], str)
            or not grant["connectionOwnerId"]
            or grant["connectionOwnerId"] == grant["ownerId"]
            or not isinstance(grant["accessGrantId"], str)
            or not grant["accessGrantId"]
            or type(grant["accessGrantGeneration"]) is not int
            or grant["accessGrantGeneration"] < 1
        ):
            reject("GRANT_ACCESS_INVALID")
    if (
        type(grant["expiresAt"]) is not int
        or not math.isfinite(grant["expiresAt"])
        or grant["expiresAt"] <= (time.time() * 1000 if now is None else now)
    ):
        reject("GRANT_EXPIRED")


def make_report(grant, analysis):
    validate_grant(grant)
    if analysis.get("sha256") != grant["uploadDigest"]:
        reject("UPLOAD_DIGEST_MISMATCH")
    return {
        **{k: grant[k] for k in binding_fields(grant)},
        "protocolVersion": 1,
        "operation": "analysis",
        "analysis": analysis,
        "executionAuthorized": False,
    }
