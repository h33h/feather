"""Canonical JSON bytes shared by protocol peers and cryptographic proofs."""

import json


def canonical(value):
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode()
