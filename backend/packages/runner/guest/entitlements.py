"""Bounded entitlement decoding, independent of signing and capability policy.

Apple's older DER plist decoder accepts SET dictionaries in arbitrary order:
https://github.com/apple-oss-distributions/Security/blob/main/OSX/utilities/der_dictionary.c
CoreEntitlements uses application[16] with a version and context[16] dictionaries:
https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/CoreEntitlements/CoreEntitlementsPriv.h
Its supported types and signed integer semantics are declared in Serialization.h.
The pinned Linux signer also emits the context[16] dictionary without an envelope.
"""

import base64
import binascii
import plistlib
from xml.parsers import expat


MAX_SIZE = 4 << 20
MAX_DEPTH = 64
MAX_NODES = 65536
MAX_JSON_INTEGER = (1 << 53) - 1


def _invalid():
    raise ValueError("ENTITLEMENTS_INVALID")


class _DER:
    def __init__(self, data):
        if not data or len(data) > MAX_SIZE:
            _invalid()
        self.data = data
        self.nodes = 0
        self.dictionary_tag = 0x31 if data[0] == 0x31 else 0xB0

    def node(self, offset, limit):
        self.nodes += 1
        if self.nodes > MAX_NODES or offset + 2 > limit:
            _invalid()
        tag, length = self.data[offset : offset + 2]
        if tag & 0x1F == 0x1F:  # No supported entitlement tag uses high-tag form.
            _invalid()
        start = offset + 2
        if length & 0x80:
            count = length & 0x7F
            if not 1 <= count <= 4 or start + count > limit or self.data[start] == 0:
                _invalid()
            length = int.from_bytes(self.data[start : start + count], "big")
            start += count
            if length < 128:
                _invalid()
        end = start + length
        if end > limit:
            _invalid()
        return tag, start, end

    def value(self, offset, limit, depth=0):
        if depth > MAX_DEPTH:
            _invalid()
        tag, start, end = self.node(offset, limit)
        legacy = self.dictionary_tag == 0x31
        # Do not copy constructed payloads at each nesting level.
        body = self.data[start:end] if tag in (0x01, 0x02, 0x0C, 0x12, 0x04) else None
        if tag == 0x01:
            # Apple's legacy SET plist requires one byte and treats any nonzero
            # value as true; its own legacy encoder emits 01 rather than ff.
            # https://github.com/apple-oss-distributions/Security/blob/main/OSX/utilities/der_boolean.c#L47-L68
            if len(body) != 1 or (not legacy and body not in (b"\0", b"\xff")):
                _invalid()
            return body != b"\0", end
        if tag == 0x02:
            # The legacy decoder accepts 0..8 bytes, including empty zero and
            # redundant sign padding; modern DER requires the minimal integer.
            # https://github.com/apple-oss-distributions/Security/blob/main/OSX/utilities/der_number.c#L45-L78
            if not (0 if legacy else 1) <= len(body) <= 8:
                _invalid()
            if (
                not legacy
                and len(body) > 1
                and ((body[0] == 0 and body[1] < 0x80) or (body[0] == 0xFF and body[1] >= 0x80))
            ):
                _invalid()
            value = int.from_bytes(body, "big", signed=True)
            if abs(value) > MAX_JSON_INTEGER:
                raise ValueError("ENTITLEMENTS_VALUE_UNSUPPORTED")
            return value, end
        # Apple's legacy NumericString decoder validates UTF-8 like UTF8String.
        # https://github.com/apple-oss-distributions/Security/blob/main/OSX/utilities/der_string.c#L62-L86
        if tag == 0x0C or (legacy and tag == 0x12):
            try:
                return body.decode("utf-8"), end
            except UnicodeError:
                _invalid()
        if tag == 0x04:
            return body, end
        if tag == 0x30:
            result = []
            while start < end:
                value, start = self.value(start, end, depth + 1)
                result.append(value)
            return result, end
        if tag == self.dictionary_tag:
            result = {}
            previous = None
            while start < end:
                pair_tag, pair_value, pair_end = self.node(start, end)
                if pair_tag != 0x30:
                    _invalid()
                key, cursor = self.value(pair_value, pair_end, depth + 1)
                if type(key) is not str or key in result:
                    _invalid()
                value, cursor = self.value(cursor, pair_end, depth + 1)
                if cursor != pair_end:
                    _invalid()
                # Legacy SET decoding has no ordering restriction. Modern
                # CoreEntitlements context dictionaries order their UTF-8 keys.
                # https://github.com/apple-oss-distributions/Security/blob/main/OSX/utilities/der_dictionary.c#L90-L106
                if not legacy:
                    order = key.encode("utf-8")
                    if previous is not None and order <= previous:
                        _invalid()
                    previous = order
                result[key] = value
                start = pair_end
            return result, end
        _invalid()

    def decode(self):
        end = len(self.data)
        if self.data[0] == 0x70:
            _, start, outer_end = self.node(0, end)
            version, start = self.value(start, outer_end)
            if type(version) is not int or version != 1:
                _invalid()
            if start >= outer_end or self.data[start] != 0xB0:
                _invalid()
            result, cursor = self.value(start, outer_end)
            if cursor != outer_end or outer_end != end:
                _invalid()
        else:
            result, cursor = self.value(0, end)
            if cursor != end:
                _invalid()
        if not isinstance(result, dict):
            _invalid()
        return result


def decode_der(data):
    return _DER(data).decode()


class _UniqueDict(dict):
    def __setitem__(self, key, value):
        if key in self:
            _invalid()
        super().__setitem__(key, value)


def _check_xml(data):
    """Check XML structure before plistlib can ignore unknown elements/text."""
    parser = expat.ParserCreate()
    stack = []
    nodes = 0
    tags = {"plist", "dict", "array", "key", "string", "integer", "data", "true", "false"}
    scalars = {"key", "string", "integer", "data", "true", "false"}

    def start(tag, attrs):
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NODES or len(stack) > MAX_DEPTH + 1 or tag not in tags:
            _invalid()
        if attrs and (tag != "plist" or attrs != {"version": "1.0"}):
            _invalid()
        if not stack:
            if tag != "plist":
                _invalid()
        else:
            parent = stack[-1]
            if parent[0] in scalars or tag == "plist":
                _invalid()
            if parent[0] == "plist" and (tag != "dict" or parent[1]):
                _invalid()
            if parent[0] == "dict" and (tag == "key") != (parent[1] % 2 == 0):
                _invalid()
            if parent[0] == "array" and tag == "key":
                _invalid()
            parent[1] += 1
        stack.append([tag, 0, []])

    def text(value):
        if stack:
            if stack[-1][0] in {"key", "string", "integer", "data"}:
                stack[-1][2].append(value)
            elif value.strip():
                _invalid()
        elif value.strip():
            _invalid()

    def end(tag):
        current, count, contents = stack.pop()
        if tag != current or (tag == "dict" and count % 2) or (tag == "plist" and count != 1):
            _invalid()
        if tag == "data":
            try:
                base64.b64decode("".join("".join(contents).split()), validate=True)
            except (binascii.Error, ValueError):
                _invalid()

    def unsupported(*args):
        _invalid()

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = text
    parser.EntityDeclHandler = unsupported
    parser.ExternalEntityRefHandler = unsupported
    parser.ProcessingInstructionHandler = unsupported
    parser.Parse(data, True)


def decode_plist(data):
    if not data or len(data) > MAX_SIZE:
        _invalid()
    try:
        # Preserve binary plist compatibility, including duplicate-key checks.
        if not data.startswith(b"bplist00"):
            _check_xml(data)
        value = plistlib.loads(data, dict_type=_UniqueDict)
        json_entitlements(value)
        return value
    except (
        expat.ExpatError,
        plistlib.InvalidFileException,
        UnicodeError,
        RecursionError,
        OverflowError,
    ):
        _invalid()


def typed_equal(left, right):
    """Python equality would incorrectly equate true with INTEGER 1."""
    if isinstance(left, dict) and isinstance(right, dict):
        return left.keys() == right.keys() and all(typed_equal(left[k], right[k]) for k in left)
    if type(left) is not type(right):
        return False
    if isinstance(left, list):
        return len(left) == len(right) and all(typed_equal(a, b) for a, b in zip(left, right))
    return left == right


def json_entitlements(value):
    """Validate source values and represent plist data explicitly in JSON reports.

    $isignData is reserved for reporting. Capability policy must never emit a
    dictionary containing this key as a claim, including input dictionaries.
    """
    nodes = 0

    def convert(item, depth=0):
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            _invalid()
        if type(item) is bool:
            return item
        if type(item) is int:
            if abs(item) > MAX_JSON_INTEGER:
                raise ValueError("ENTITLEMENTS_VALUE_UNSUPPORTED")
            return item
        if type(item) is str:
            if len(item.encode("utf-8")) > MAX_SIZE:
                _invalid()
            return item
        if type(item) is bytes:
            if len(item) > MAX_SIZE:
                _invalid()
            return {"$isignData": base64.b64encode(item).decode("ascii")}
        if type(item) is list:
            return [convert(child, depth + 1) for child in item]
        if isinstance(item, dict):
            result = {}
            for key, child in item.items():
                if type(key) is not str:
                    _invalid()
                convert(key, depth + 1)
                result[key] = convert(child, depth + 1)
            return result
        raise ValueError("ENTITLEMENTS_VALUE_UNSUPPORTED")

    if not isinstance(value, dict):
        _invalid()
    return convert(value)
