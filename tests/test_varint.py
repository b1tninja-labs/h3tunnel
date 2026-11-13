"""QUIC variable-length integers: the vectors of RFC 9000 Appendix A.1 and the edges of sec. 16."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from h3tunnel.errors import Incomplete
from h3tunnel.varint import MAX_VARINT, decode_varint, encode_varint

# RFC 9000 Appendix A.1 paragraph 5, read through rfclib.
A1 = [
    ("c2197c5eff14e88c", 151_288_809_941_952_652),
    ("9d7f3e7d", 494_878_333),
    ("7bbd", 15_293),
    ("25", 37),
    ("4025", 37),  # "as does the two-byte sequence 0x4025": not minimal, still valid
]


@pytest.mark.parametrize(("hex_bytes", "value"), A1)
def test_rfc9000_a1_vectors_decode(hex_bytes, value):
    data = bytes.fromhex(hex_bytes)
    assert decode_varint(data) == (value, len(data))


def test_rfc9000_a1_vectors_reencode_to_the_shortest_form():
    for hex_bytes, value in A1:
        if hex_bytes == "4025":
            assert encode_varint(value) == bytes.fromhex("25")
            assert encode_varint(value, 2) == bytes.fromhex("4025")
        else:
            assert encode_varint(value) == bytes.fromhex(hex_bytes)


def test_decode_nonminimal_accepted():
    # sec. 16 paragraph 7: values need not use the minimum number of bytes
    assert decode_varint(bytes.fromhex("4025")) == (37, 2)
    assert decode_varint(bytes.fromhex("80000025")) == (37, 4)
    assert decode_varint(bytes.fromhex("c000000000000025")) == (37, 8)


@pytest.mark.parametrize(
    ("value", "size"),
    [(0, 1), (63, 1), (64, 2), (16383, 2), (16384, 4), (2**30 - 1, 4), (2**30, 8), (MAX_VARINT, 8)],
)
def test_boundaries(value, size):
    # Table 4 of sec. 16
    encoded = encode_varint(value)
    assert len(encoded) == size
    assert decode_varint(encoded) == (value, size)


@pytest.mark.parametrize("value", [-1, 2**62, 2**64, True, 1.0, "1"])
def test_encode_out_of_range_raises(value):
    with pytest.raises(ValueError, match="variable-length"):
        encode_varint(value)


def test_encode_with_a_length_that_is_too_short_raises():
    with pytest.raises(ValueError, match="does not fit"):
        encode_varint(64, 1)
    with pytest.raises(ValueError, match="does not fit"):
        encode_varint(1, 3)


@pytest.mark.parametrize(("hex_bytes", "value"), A1)
def test_decode_truncated(hex_bytes, value):
    data = bytes.fromhex(hex_bytes)
    for cut in range(len(data)):
        with pytest.raises(Incomplete):
            decode_varint(data[:cut])


def test_decode_at_an_offset_and_reports_the_next_one():
    data = b"\xff" + bytes.fromhex("7bbd") + b"\x25"
    assert decode_varint(data, 1) == (15293, 3)
    assert decode_varint(data, 3) == (37, 4)
    with pytest.raises(Incomplete):
        decode_varint(data, 4)
    with pytest.raises(ValueError, match="negative"):
        decode_varint(data, -1)


def test_decode_accepts_bytearray_and_memoryview():
    assert decode_varint(bytearray(b"\x7b\xbd")) == (15293, 2)
    assert decode_varint(memoryview(b"\x7b\xbd")) == (15293, 2)


@settings(max_examples=200, deadline=None)
@given(st.integers(0, MAX_VARINT))
def test_roundtrip_property(value):
    encoded = encode_varint(value)
    assert decode_varint(encoded + b"tail") == (value, len(encoded))
