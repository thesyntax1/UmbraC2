"""Image helpers for the console.

The implant captures the screen as a BMP -- that is what GDI hands out, and
it costs nothing to copy -- and the console turns the file into a PNG when it
saves it: a PNG is what every viewer, every report and every chat client
expects.
"""

from __future__ import annotations

import struct
import zlib

__all__ = ["bmp_to_png", "png_size"]


def bmp_to_png(data: bytes) -> bytes:
    """Convert a 24-bit BMP into a PNG.

    The BMP is bottom-up, the PNG is top-down, and the BMP stores BGR while
    the PNG stores RGB: the conversion is a row reversal and a channel
    swap, both of which happen in one pass over the pixels.
    """
    if len(data) < 54 or data[:2] != b"BM":
        raise ValueError("not a BMP file")
    offset = int.from_bytes(data[10:14], "little")
    header = int.from_bytes(data[14:18], "little")
    if header < 40:
        raise ValueError("unsupported BMP header")
    width = int.from_bytes(data[18:22], "little", signed=True)
    height = int.from_bytes(data[22:26], "little", signed=True)
    depth = int.from_bytes(data[28:30], "little")
    if depth != 24:
        raise ValueError(f"unsupported BMP depth: {depth}")
    top_down = height < 0
    height = abs(height)
    if width <= 0 or height <= 0:
        raise ValueError("the BMP has no pixels")
    stride = ((width * 3 + 3) // 4) * 4
    rows = []
    for y in range(height):
        start = offset + y * stride
        line = data[start:start + width * 3]
        if len(line) < width * 3:
            break
        rgb = bytearray(width * 3)
        rgb[0::3] = line[2::3]
        rgb[1::3] = line[1::3]
        rgb[2::3] = line[0::3]
        rows.append(bytes(rgb))
    if top_down:
        rows.reverse()
    raw = b"".join(b"\x00" + row for row in rows)
    return _png(width, height, raw)


def png_size(data: bytes) -> tuple[int, int]:
    """The width and the height of a PNG."""
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a PNG file")
    width, height = struct.unpack(">II", data[16:24])
    return width, height


def _png(width: int, height: int, raw: bytes) -> bytes:
    """Wrap the raw scanlines in a PNG."""

    def chunk(tag: bytes, payload: bytes) -> bytes:
        return (struct.pack(">I", len(payload)) + tag + payload
                + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF))

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(raw, 6))
            + chunk(b"IEND", b""))
