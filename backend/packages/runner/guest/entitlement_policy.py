"""Bounded emitted entitlement schema and signed-profile authorization rules."""

import base64
import copy
import re

IDENTITY_KEYS = {
    "application-identifier",
    "com.apple.developer.team-identifier",
    "get-task-allow",
    "keychain-access-groups",
}
WILDCARD_KEYS = {
    "application-identifier",
    "keychain-access-groups",
    "com.apple.developer.ubiquity-kvstore-identifier",
    "com.apple.developer.icloud-container-identifiers",
    "com.apple.developer.ubiquity-container-identifiers",
    "com.apple.developer.associated-domains",
}
FORBIDDEN_KEYS = {"__proto__", "prototype", "constructor"}


def safe_string(value):
    return len(value.encode("utf-16-le", errors="surrogatepass")) // 2 <= 65536 and all(
        ord(c) in (9, 10, 13)
        or 32 <= ord(c) <= 0xD7FF
        or 0xE000 <= ord(c) <= 0xFFFD
        or 0x10000 <= ord(c) <= 0x10FFFF
        for c in value
    )


def safe_value(value, allow_data=False):
    remaining = 10000

    def valid(current, depth):
        nonlocal remaining
        remaining -= 1
        if remaining < 0 or depth > 16:
            return False
        if type(current) is bool:
            return True
        if type(current) is int:
            return abs(current) <= 9007199254740991
        if isinstance(current, str):
            return safe_string(current)
        if isinstance(current, list):
            return len(current) <= 1024 and all(valid(v, depth + 1) for v in current)
        if not isinstance(current, dict):
            return False
        if "$isignData" in current:
            raw = current["$isignData"]
            if (
                not allow_data
                or set(current) != {"$isignData"}
                or not isinstance(raw, str)
                or len(raw) > 65536
            ):
                return False
            try:
                return base64.b64encode(base64.b64decode(raw, validate=True)).decode("ascii") == raw
            except (ValueError, UnicodeError):
                return False
        return len(current) <= 1024 and all(
            isinstance(k, str)
            and 0 < len(k) <= 1024
            and safe_string(k)
            and k not in FORBIDDEN_KEYS
            and valid(v, depth + 1)
            for k, v in current.items()
        )

    return valid(value, 0)


def exact(left, right):
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return set(left) == set(right) and all(
            exact(value, right[key]) for key, value in left.items()
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(exact(a, b) for a, b in zip(left, right))
    return left == right


def permits(key, claim, ceiling):
    if (
        not isinstance(key, str)
        or not key
        or len(key) > 1024
        or not safe_string(key)
        or key in FORBIDDEN_KEYS
        or key == "$isignData"
        or not safe_value(claim)
        or not safe_value(ceiling, allow_data=True)
    ):
        return False

    def subset(value, permission):
        if type(value) is not type(permission):
            return False
        if isinstance(value, str):
            return (
                value == permission
                or (
                    key in WILDCARD_KEYS
                    # Associated domain host wildcards are literal requested values (TN3155).
                    and (key == "com.apple.developer.associated-domains" or "*" not in value)
                    and re.fullmatch(r"[^*]*\*", permission) is not None
                    and value.startswith(permission[:-1])
                    and len(value) > len(permission) - 1
                )
            )
        if isinstance(value, list):
            return all(any(subset(v, p) for p in permission) for v in value)
        if isinstance(value, dict):
            return "$isignData" not in permission and all(
                k in permission and subset(v, permission[k]) for k, v in value.items()
            )
        return value == permission

    return subset(claim, ceiling)


def profile_identifier_permits(pattern, prefix, bundle_id):
    if (
        not isinstance(pattern, str)
        or not isinstance(prefix, str)
        or not re.fullmatch(r"[A-Za-z0-9]+", prefix)
        or not isinstance(bundle_id, str)
        or not re.fullmatch(r"([A-Za-z0-9-]+\.)+[A-Za-z0-9-]+", bundle_id)
    ):
        return False
    appid = prefix + "." + bundle_id
    if not pattern.startswith(prefix + "."):
        return False
    if "*" not in pattern:
        return pattern == appid
    return re.fullmatch(
        r"(?:[A-Za-z0-9-]+\.)*\*", pattern[len(prefix) + 1 :]
    ) is not None and permits("application-identifier", appid, pattern)


def identity_entitlements(profile):
    ent = profile.get("entitlements")
    prefix, bid, team = profile["prefix"], profile["bundleId"], profile["teamId"]
    appid = prefix + "." + bid
    if (
        not isinstance(ent, dict)
        or not safe_value(ent, allow_data=True)
        or not profile_identifier_permits(ent.get("application-identifier"), prefix, bid)
        or ent.get("com.apple.developer.team-identifier") != team
        or ent.get("get-task-allow") is not False
    ):
        raise ValueError("PROFILE_ENTITLEMENTS_MISMATCH")
    emitted = {
        "application-identifier": appid,
        "com.apple.developer.team-identifier": team,
        "get-task-allow": False,
    }
    if "keychain-access-groups" in ent:
        groups = ent["keychain-access-groups"]
        if (
            not isinstance(groups, list)
            or not groups
            or any(not isinstance(v, str) or not v for v in groups)
            or len(groups) != len(set(groups))
            or not permits("keychain-access-groups", [appid], groups)
        ):
            raise ValueError("PROFILE_ENTITLEMENTS_MISMATCH")
        emitted["keychain-access-groups"] = [appid]
    return emitted


def normalized_entitlements(source, profile):
    if not isinstance(source, dict):
        raise ValueError("SOURCE_ENTITLEMENTS_INVALID")
    emitted = identity_entitlements(profile)
    for key, value in source.items():
        if key in IDENTITY_KEYS:
            continue
        ceiling = profile["entitlements"].get(key)
        if permits(key, value, ceiling):
            emitted[key] = copy.deepcopy(value)
        elif isinstance(value, list) and isinstance(ceiling, list) and safe_value(value):
            retained = [entry for entry in value if permits(key, [entry], ceiling)]
            if retained:
                emitted[key] = copy.deepcopy(retained)
    requested = source.get("keychain-access-groups")
    if isinstance(requested, list) and "keychain-access-groups" in emitted:
        groups = emitted["keychain-access-groups"]
        for group in requested:
            if (
                isinstance(group, str)
                and group != source.get("application-identifier")
                and group not in groups
                and permits(
                    "keychain-access-groups",
                    [group],
                    profile["entitlements"].get("keychain-access-groups"),
                )
            ):
                groups.append(group)
    return emitted
