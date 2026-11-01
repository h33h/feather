import hashlib

from protocol.codec import canonical


def canonical_digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()
