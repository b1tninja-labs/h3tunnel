"""Capsule framing (RFC 9297 sec. 3.2, 3.3, 3.5) and the Capsule-Protocol header (sec. 3.4)."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from h3tunnel.capsule import (
    DATAGRAM,
    Capsule,
    CapsuleParser,
    decode_capsule,
    encode_capsule,
    parse_capsule_protocol_header,
)
from h3tunnel.errors import CapsuleTooLarge, Incomplete, MalformedCapsule
from h3tunnel.varint import encode_varint


def test_encode_roundtrip():
    framed = encode_capsule(DATAGRAM, b"\x00hello")
    assert framed == b"\x00\x06\x00hello"  # Type 0x00, Length 6, Value (sec. 3.5)
    assert decode_capsule(framed) == (Capsule(0, b"\x00hello"), len(framed))


def test_encode_uses_variable_length_integers_for_type_and_length():
    framed = encode_capsule(0x1234, b"x" * 64)
    assert framed[:2] == b"\x52\x34"  # 0x1234 needs two bytes
    assert framed[2:4] == b"\x40\x40"  # length 64 needs two bytes
    assert decode_capsule(framed)[0] == Capsule(0x1234, b"x" * 64)


def test_zero_length_capsule():
    # sec. 3.2 paragraph 7: the Capsule Length can be zero
    assert encode_capsule(0x2A, b"") == b"\x2a\x00"
    assert decode_capsule(b"\x2a\x00") == (Capsule(0x2A, b""), 2)


def test_decode_capsule_leaves_trailing_bytes_to_the_caller():
    capsule, used = decode_capsule(b"\x00\x01a\x00\x01b")
    assert capsule == Capsule(0, b"a")
    assert used == 3


def test_decode_capsule_incomplete():
    framed = encode_capsule(1, b"abcdef")
    for cut in range(len(framed)):
        with pytest.raises(Incomplete):
            decode_capsule(framed[:cut])


def test_unknown_type_is_returned_not_dropped_by_codec():
    # sec. 3.2 paragraphs 10 and 11: dropping or forwarding is the policy of the caller
    parser = CapsuleParser()
    assert parser.feed(encode_capsule(0x7777, b"opaque")) == [Capsule(0x7777, b"opaque")]


STREAM = encode_capsule(0, b"one") + encode_capsule(0x2A, b"") + encode_capsule(9, b"x" * 300)


def test_parser_split_feed():
    whole = CapsuleParser().feed(STREAM)
    parser = CapsuleParser()
    dribbled: list[Capsule] = []
    for i in range(len(STREAM)):
        dribbled += parser.feed(STREAM[i : i + 1])
    assert dribbled == whole
    assert [c.type for c in whole] == [0, 0x2A, 9]
    parser.finish()


@settings(max_examples=100, deadline=None)
@given(
    st.lists(st.tuples(st.integers(0, 2**62 - 1), st.binary(max_size=40)), max_size=5),
    st.integers(1, 7),
)
def test_parser_roundtrip_property(capsules, chunk):
    stream = b"".join(encode_capsule(t, b) for t, b in capsules)
    parser = CapsuleParser()
    got: list[Capsule] = []
    for i in range(0, len(stream), chunk):
        got += parser.feed(stream[i : i + chunk])
    parser.finish()
    assert got == [Capsule(t, b) for t, b in capsules]


def test_value_length_cap_raises_before_buffering_the_value():
    parser = CapsuleParser(max_value_length=65_535)
    header = b"\x00" + encode_varint(2**40)  # Type 0, Length 2**40
    with pytest.raises(CapsuleTooLarge):
        parser.feed(header)
    assert parser.buffered <= len(header)
    # the value was never accepted: even one more chunk does not grow the buffer unboundedly
    assert isinstance(CapsuleTooLarge(), MalformedCapsule)


def test_value_at_the_cap_is_accepted_and_one_over_is_not():
    parser = CapsuleParser(max_value_length=10)
    assert parser.feed(encode_capsule(1, b"x" * 10)) == [Capsule(1, b"x" * 10)]
    with pytest.raises(CapsuleTooLarge):
        parser.feed(encode_capsule(1, b"x" * 11)[:4])


def test_waiting_for_the_rest_of_a_value_holds_only_what_arrived():
    parser = CapsuleParser(max_value_length=1000)
    framed = encode_capsule(1, b"y" * 1000)
    assert parser.feed(framed[:500]) == []
    assert parser.buffered <= 500
    assert parser.feed(framed[500:]) == [Capsule(1, b"y" * 1000)]
    assert parser.buffered == 0


def test_finish_with_partial_capsule():
    # sec. 3.3 paragraph 3: a truncated last capsule at a clean end of stream is malformed
    for cut in (1, 2, 5):
        parser = CapsuleParser()
        assert parser.feed(encode_capsule(1, b"abcdef")[:cut]) == []
        with pytest.raises(MalformedCapsule):
            parser.finish()


def test_finish_on_a_clean_boundary_is_quiet():
    parser = CapsuleParser()
    parser.feed(encode_capsule(1, b"abc"))
    parser.finish()
    CapsuleParser().finish()


def test_negative_cap_refused():
    with pytest.raises(ValueError, match="negative"):
        CapsuleParser(max_value_length=-1)


@pytest.mark.parametrize(
    ("lines", "expected"),
    [
        ("?1", True),
        ("?0", False),  # sec. 3.4 paragraph 2: false is the same as absent
        (b"?1", True),
        (["?1"], True),
        ("?1; unknown=3", True),  # paragraph 1: unknown parameters are ignored
        ([], False),  # the field is absent
        (["?1", "?1"], False),  # sent twice it becomes a List, which is ignored
        ("?1, ?1", False),
        ("1", False),  # an Integer is not a Boolean
        ('"?1"', False),
        ("?2", False),  # does not parse
        ("", False),
        ("(?1)", False),
        ("?1 ?1", False),
    ],
)
def test_capsule_protocol_header(lines, expected):
    assert parse_capsule_protocol_header(lines) is expected
