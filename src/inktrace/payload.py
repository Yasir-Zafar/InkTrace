"""Payload layout and framing.

Bits (big-endian): version:4 | doc_id:32 | recipient_id:16 | tag:64  = 116 bits.
Frame: WJ + 116 zero-width data chars + WJ.
"""

import re
from dataclasses import dataclass

from inktrace import zw

VERSION = 1
TAG_BYTES = 8
BITS = 4 + 32 + 16 + TAG_BYTES * 8


@dataclass(frozen=True)
class Payload:
    version: int
    doc_id: int
    recipient_id: int
    tag: bytes


def pack(p: Payload) -> str:
    """Payload -> string of 116 '0'/'1'."""
    if not 0 <= p.version < 2**4:
        raise ValueError("version out of range")
    if not 0 <= p.doc_id < 2**32:
        raise ValueError("doc_id out of range")
    if not 0 <= p.recipient_id < 2**16:
        raise ValueError("recipient_id out of range")
    if len(p.tag) != TAG_BYTES:
        raise ValueError("tag must be 8 bytes")
    n = p.version << 112 | p.doc_id << 80 | p.recipient_id << 64 | int.from_bytes(p.tag, "big")
    return format(n, f"0{BITS}b")


def unpack(bits: str) -> Payload:
    """116 '0'/'1' -> Payload. Rejects wrong length or unknown version."""
    if len(bits) != BITS or not set(bits) <= {"0", "1"}:
        raise ValueError("bad payload length")
    n = int(bits, 2)
    version = n >> 112
    if version != VERSION:
        raise ValueError(f"unknown version {version}")
    return Payload(
        version=version,
        doc_id=(n >> 80) & 0xFFFFFFFF,
        recipient_id=(n >> 64) & 0xFFFF,
        tag=(n & (2**64 - 1)).to_bytes(TAG_BYTES, "big"),
    )
