"""Bounded length-prefixed byte frames, independent of process or HTTPS clients."""

import struct

MAX_FRAME = 8 << 20


def write_frame(stream, data):
    if not isinstance(data, bytes) or len(data) > MAX_FRAME:
        raise ValueError("STDIO_FRAME_LIMIT")
    stream.write(struct.pack(">I", len(data)) + data)
    stream.flush()


def read_frame(stream):
    def exact(size):
        data = b""
        while len(data) < size:
            chunk = stream.read(size - len(data))
            if not chunk:
                raise ValueError("STDIO_CHANNEL_CLOSED")
            data += chunk
        return data

    size = struct.unpack(">I", exact(4))[0]
    if size > MAX_FRAME:
        raise ValueError("STDIO_FRAME_LIMIT")
    return exact(size)
