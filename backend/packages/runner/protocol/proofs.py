import hashlib, hmac, re, time
from protocol import grants as analyzer
from protocol.codec import canonical as canonical

REQUIRED_ISOLATION = (
    "freshVm",
    "diskEphemeral",
    "noHostShares",
    "networkPolicyEnforced",
    "oneJob",
    "guestChannelAuthenticated",
)
LINUX_ISOLATION = (
    "freshSandbox",
    "diskEphemeral",
    "noHostShares",
    "networkPolicyEnforced",
    "oneJob",
    "guestChannelAuthenticated",
    "runtimeVerified",
    "resourceLimitsEnforced",
)


def validated_isolation(evidence):
    if not isinstance(evidence, dict):
        raise ValueError("ISOLATION_EVIDENCE_REQUIRED")
    if evidence.get("type") == "gvisor":
        if (
            evidence.get("runtime") != "runsc"
            or evidence.get("freshVm") is not None
            or any(evidence.get(k) is not True for k in LINUX_ISOLATION)
        ):
            raise ValueError("GVISOR_ISOLATION_EVIDENCE_REQUIRED")
        return {"type": "gvisor", "runtime": "runsc", **{k: True for k in LINUX_ISOLATION}}
    if evidence.get("type") not in (None, "vm") or any(
        evidence.get(k) is not True for k in REQUIRED_ISOLATION
    ):
        raise ValueError("VM_ISOLATION_EVIDENCE_REQUIRED")
    return {k: True for k in REQUIRED_ISOLATION}


def validate_execution_grant(grant, now=None):
    if isinstance(grant, dict) and grant.get("operation") in (
        "bootstrap-request",
        "bootstrap-pkcs12",
        "device-profile-verify",
    ):
        fields = (
            "ownerId",
            "jobId",
            "leaseToken",
            "connectionId",
            "connectionGeneration",
            "taskNonce",
            "isolationInstanceId",
            "expiresAt",
            "operation",
        )
        if (
            any(k not in grant for k in fields)
            or any(
                not isinstance(grant[k], str) or not grant[k]
                for k in fields
                if k not in ("connectionGeneration", "expiresAt")
            )
            or type(grant["connectionGeneration"]) is not int
            or grant["connectionGeneration"] < 1
            or type(grant["expiresAt"]) is not int
            or grant["expiresAt"] <= (int(time.time() * 1000) if now is None else now)
        ):
            raise ValueError("CONTROL_EXECUTION_GRANT_INVALID")
        if any(k in grant for k in ("connectionOwnerId", "accessGrantId", "accessGrantGeneration")):
            if (
                not all(
                    k in grant
                    for k in ("connectionOwnerId", "accessGrantId", "accessGrantGeneration")
                )
                or not isinstance(grant["connectionOwnerId"], str)
                or not grant["connectionOwnerId"]
                or grant["connectionOwnerId"] == grant["ownerId"]
                or not isinstance(grant["accessGrantId"], str)
                or not grant["accessGrantId"]
                or type(grant["accessGrantGeneration"]) is not int
                or grant["accessGrantGeneration"] < 1
            ):
                raise ValueError("CONTROL_EXECUTION_ACCESS_INVALID")
        prefix = (
            "device-eligibility:" if grant["operation"] == "device-profile-verify" else "bootstrap:"
        )
        if grant["jobId"] != prefix + grant["taskNonce"]:
            raise ValueError("CONTROL_EXECUTION_SCOPE_MISMATCH")
    else:
        analyzer.validate_grant(grant, now=now)


def issue_vm_proof(grant, evidence, key, key_id):
    """Controller only: call after independent lifecycle/channel/policy evidence."""
    validate_execution_grant(grant)
    if not isinstance(key, bytes) or len(key) < 16:
        raise ValueError("ISOLATION_EVIDENCE_REQUIRED")
    claims = {**grant, "isolation": validated_isolation(evidence)}
    return {
        "claims": claims,
        "keyId": key_id,
        "signature": hmac.new(key, canonical(claims), hashlib.sha256).hexdigest(),
    }


def vm_proof_validator(key_provider, clock=lambda: int(time.time() * 1000)):
    def validate(proof, grant):
        try:
            validate_execution_grant(grant, now=clock())
            claims = proof["claims"]
            key = key_provider(proof["keyId"])
            if (
                not isinstance(key, bytes)
                or len(key) < 16
                or any(claims.get(k) != v for k, v in grant.items())
                or validated_isolation(claims["isolation"]) != claims["isolation"]
            ):
                return False
            return hmac.compare_digest(
                hmac.new(key, canonical(claims), hashlib.sha256).hexdigest(), proof["signature"]
            )
        except (ValueError, KeyError, TypeError):
            return False

    return validate
