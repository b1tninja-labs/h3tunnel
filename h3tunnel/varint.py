"""QUIC variable-length integers (RFC 9000 sec. 16, Appendix A.1).

The two most significant bits of the first byte give the length (1, 2, 4 or 8 bytes); the
rest is the value in network byte order, up to 2**62 - 1. A value need not use the shortest
form (sec. 16 paragraph 7), so decoding accepts ``4025`` for 37; encoding writes the shortest
form unless a length is asked for.
"""

from __future__ import annotations

from .errors import Incomplete

__all__ = [
    "MAX_VARINT",
    "decode_varint",
    "encode_varint",
]

MAX_VARINT = (1 << 62) - 1
_LENGTHS = (1, 2, 4, 8)


def encode_varint(value: int, length: int | None = None) -> bytes:
    """Encode ``value`` (RFC 9000 sec. 16).

    The shortest form by default; ``length`` (1, 2, 4 or 8) forces a longer one, which
    RFC 9000 sec. 16 paragraph 7 allows. Raises ``ValueError`` outside 0..2**62-1 or when the
    value does not fit the requested length.
    """
    if type(value) is not int or not 0 <= value <= MAX_VARINT:
        raise ValueError(f"{value!r} is not a QUIC variable-length integer (0..2**62-1)")
    needed = 1 if value < 1 << 6 else 2 if value < 1 << 14 else 4 if value < 1 << 30 else 8
    if length is None:
        length = needed
    elif length not in _LENGTHS or length < needed:
        raise ValueError(f"{value} does not fit in {length} bytes")
    prefix = _LENGTHS.index(length) << (8 * length - 2)
    return (prefix | value).to_bytes(length, "big")


def decode_varint(data: bytes | bytearray | memoryview, offset: int = 0) -> tuple[int, int]:
    """Read one integer at ``offset``; returns ``(value, new_offset)`` (RFC 9000 Appendix A.1).

    Raises :class:`~h3tunnel.errors.Incomplete` when the buffer ends inside the integer;
    never returns a partial value.
    """
    if offset < 0:
        raise ValueError("offset must not be negative")
    if offset >= len(data):
        raise Incomplete("no byte to read a variable-length integer from")
    first = data[offset]
    length = 1 << (first >> 6)
    end = offset + length
    if end > len(data):
        raise Incomplete(f"integer needs {length} bytes, {len(data) - offset} available")
    value = first & 0x3F
    for byte in data[offset + 1 : end]:
        value = (value << 8) | byte
    return value, end
