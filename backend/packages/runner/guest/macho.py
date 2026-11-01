"""Select a bounded, unambiguous iPhone arm64 slice before parsing or signing."""

import struct


def arm64_slice(data):
    layouts = {
        b"\xca\xfe\xba\xbe": (">", False),
        b"\xbe\xba\xfe\xca": ("<", False),
        b"\xca\xfe\xba\xbf": (">", True),
        b"\xbf\xba\xfe\xca": ("<", True),
    }
    layout = layouts.get(data[:4])
    if layout is None:
        return data
    endian, wide = layout
    if len(data) < 8:
        raise ValueError("FAT_BOUNDS")
    count = struct.unpack_from(endian + "I", data, 4)[0]
    width = 32 if wide else 20
    table_end = 8 + count * width
    if not 1 <= count <= 32 or table_end > len(data):
        raise ValueError("FAT_BOUNDS")
    intervals = []
    architectures = set()
    choices = []
    for index in range(count):
        values = struct.unpack_from(
            endian + ("IIQQII" if wide else "IIIII"), data, 8 + index * width
        )
        cpu, subtype, offset, size, align = values[:5]
        if (
            align > 30
            or offset % (1 << align)
            or offset < table_end
            or size < 4
            or offset + size > len(data)
            or (wide and values[5] != 0)
            or any(offset < end and start < offset + size for start, end in intervals)
        ):
            raise ValueError("FAT_BOUNDS")
        intervals.append((offset, offset + size))
        if (cpu, subtype) in architectures:
            raise ValueError("FAT_ARCHITECTURE_DUPLICATE")
        architectures.add((cpu, subtype))
        # arm64e-only archives need device/ABI matching, not a claim of baseline arm64.
        if cpu == 0x100000C and subtype & 0xFFFFFF in (0, 1):
            if size < 32 or data[offset : offset + 4] != b"\xcf\xfa\xed\xfe":
                raise ValueError("FAT_ARCHITECTURE_MISMATCH")
            if struct.unpack_from("<II", data, offset + 4) != (cpu, subtype):
                raise ValueError("FAT_ARCHITECTURE_MISMATCH")
            choices.append((subtype & 0xFFFFFF, offset, size))
    if not choices:
        raise ValueError("ARCHITECTURE_UNSUPPORTED")
    _, offset, size = min(choices)
    return data[offset : offset + size]


def normalize_executables(root, components, bounded):
    """Called only after the independent verifier proved the original staged bytes."""
    import plistlib

    for component in components:
        path = root / component["path"]
        if component["kind"] != "dylib":
            info = plistlib.loads(bounded.read_bounded(path / "Info.plist", 4 << 20))
            path /= info["CFBundleExecutable"]
        raw = bounded.read_bounded(path, 512 << 20)
        selected = arm64_slice(raw)
        if selected is not raw:
            with path.open("wb") as target:
                target.write(selected)
