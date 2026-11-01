"""Bounded file operations for isolated archives; no arbitrary whole-file reads."""

import hashlib, os, pathlib, stat

CHUNK = 1 << 20


class CancellableIterator:
    def __init__(self, iterator, cancel):
        if not callable(cancel):
            raise ValueError("CANCELLABLE_SOURCE_REQUIRED")
        self.iterator = iter(iterator)
        self.cancel = cancel

    def __iter__(self):
        return self

    def __next__(self):
        return next(self.iterator)


def open_regular(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise ValueError("REGULAR_FILE_REQUIRED")
    return os.fdopen(fd, "rb")


def digests(path, algorithms=("sha256",)):
    hashes = [hashlib.new(name) for name in algorithms]
    with open_regular(path) as source:
        for block in iter(lambda: source.read(CHUNK), b""):
            for digest in hashes:
                digest.update(block)
    return tuple(digest.digest() for digest in hashes)


def read_bounded(path, limit):
    with open_regular(path) as source:
        if os.fstat(source.fileno()).st_size > limit:
            raise ValueError("FILE_LIMIT")
        data = source.read(limit + 1)
    if len(data) > limit:
        raise ValueError("FILE_LIMIT")
    return data


def copy_bounded(source, destination, limit):
    size = 0
    while True:
        block = source.read(min(CHUNK, limit - size + 1))
        if not block:
            return size
        size += len(block)
        if size > limit:
            raise ValueError("FILE_LIMIT")
        destination.write(block)
