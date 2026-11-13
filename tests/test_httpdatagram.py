"""HTTP Datagram payloads, Quarter Stream IDs, Context IDs and payload limits
(RFC 9297 sec. 2.1, RFC 9298 sec. 4, 5 and 6.1).
"""

from __future__ import annotations

import pytest

from h3tunnel.ctx import ContextAllocator, allocate_context
from h3tunnel.errors import (
    ContextError,
    H3DatagramError,
    H3SettingsError,
    Incomplete,
    PayloadTooLarge,
)
from h3tunnel.httpdatagram import (
    MAX_QUARTER_STREAM_ID,
    decode_datagram,
    decode_h3_datagram,
    decode_udp_payload,
    encode_datagram,
    encode_h3_datagram,
    validate_h3_datagram_setting,
)
from h3tunnel.limits import MAX_UDP_PAYLOAD, check_udp_payload, clamp_payload
from h3tunnel.varint import encode_varint


def test_context_zero_roundtrip():
    assert encode_datagram(0, b"payload") == b"\x00payload"
    assert decode_datagram(b"\x00payload") == (0, b"payload")
    assert encode_datagram(0, b"") == b"\x00"  # sec. 5: the payload can be empty
    assert decode_datagram(b"\x00") == (0, b"")


def test_decode_datagram_needs_a_context_id():
    with pytest.raises(Incomplete):
        decode_datagram(b"")
    with pytest.raises(Incomplete):
        decode_datagram(b"\x40")  # a two-byte Context ID cut short


def test_context_nonzero_rejected_as_udp():
    # sec. 5 paragraph 5: only Context ID zero is a UDP payload
    assert decode_udp_payload(encode_datagram(4, b"x")) is None
    assert decode_udp_payload(encode_datagram(0, b"x")) == b"x"
    assert decode_udp_payload(b"\x01data") is None


def test_payload_65527_ok_65528_refused():
    assert MAX_UDP_PAYLOAD == 65527
    ok = b"a" * 65527
    assert encode_datagram(0, ok)[1:] == ok
    assert decode_udp_payload(b"\x00" + ok) == ok
    with pytest.raises(PayloadTooLarge, match="do not send"):
        encode_datagram(0, ok + b"a")
    with pytest.raises(PayloadTooLarge, match="abort"):
        decode_udp_payload(b"\x00" + ok + b"a")
    check_udp_payload(ok, receiving=False)


def test_larger_payload_allowed_for_nonzero_context():
    big = b"a" * 70000
    assert encode_datagram(4, big)[1:] == big  # the limit applies to Context ID zero only
    assert decode_udp_payload(encode_datagram(4, big)) is None


def test_quarter_stream_id_limits():
    # sec. 2.1 paragraphs 4 and 6
    assert MAX_QUARTER_STREAM_ID == 2**60 - 1
    frame = encode_varint(MAX_QUARTER_STREAM_ID) + b"\x00x"
    assert decode_h3_datagram(frame) == (MAX_QUARTER_STREAM_ID * 4, 0, b"x")
    with pytest.raises(H3DatagramError) as caught:
        decode_h3_datagram(encode_varint(2**60) + b"\x00x")
    assert caught.value.error_code == 0x33
    with pytest.raises(H3DatagramError) as caught:
        decode_h3_datagram(b"")
    assert caught.value.error_code == 0x33
    with pytest.raises(H3DatagramError):
        decode_h3_datagram(b"\x80\x00")  # a four-byte varint cut short


def test_h3_datagram_roundtrip_and_stream_id_rules():
    frame = encode_h3_datagram(8, 0, b"hi")
    assert frame == b"\x02\x00hi"  # Quarter Stream ID 2, Context ID 0
    assert decode_h3_datagram(frame) == (8, 0, b"hi")
    for stream_id in (3, 1, 6, -4):
        with pytest.raises(ValueError, match="client-initiated"):
            encode_h3_datagram(stream_id, 0, b"")
    with pytest.raises(ValueError, match="largest legal"):
        encode_h3_datagram(2**62, 0, b"")


def test_settings_h3_datagram():
    # sec. 2.1.1 paragraphs 2 and 4
    assert validate_h3_datagram_setting(1) is True
    assert validate_h3_datagram_setting(0) is False
    for bad in (2, -1, 100):
        with pytest.raises(H3SettingsError) as caught:
            validate_h3_datagram_setting(bad)
        assert caught.value.error_code == 0x109
    assert validate_h3_datagram_setting(1, stored=1) is True
    assert validate_h3_datagram_setting(1, stored=0) is True
    with pytest.raises(H3SettingsError):
        validate_h3_datagram_setting(0, stored=1)


def test_allocator_parity_and_no_reuse():
    client = ContextAllocator("client")
    proxy = ContextAllocator("proxy")
    mine = [client.allocate() for _ in range(200)]
    theirs = [proxy.allocate() for _ in range(200)]
    assert len(set(mine)) == 200
    assert all(c % 2 == 0 and c > 0 for c in mine)
    assert all(c % 2 == 1 for c in theirs)
    assert mine[:3] == [2, 4, 6]
    assert theirs[:3] == [1, 3, 5]
    proxy2 = ContextAllocator("proxy")
    proxy2.note_peer(3)
    proxy2.note_peer(7)
    assert [proxy2.allocate() for _ in range(4)] == [1, 5, 9, 11]
    assert allocate_context(ContextAllocator("client")) == 2


def test_allocator_refuses_zero_and_duplicates():
    allocator = ContextAllocator("client")
    first = allocator.allocate()
    with pytest.raises(ContextError, match="reserved"):
        allocator.note_peer(0)
    with pytest.raises(ContextError, match="already"):
        allocator.note_peer(first)
    with pytest.raises(ContextError):
        allocator.note_peer(2**62)
    assert allocator.is_allocated(first)
    with pytest.raises(ValueError, match="role"):
        ContextAllocator("server")


def test_allocator_exhaustion():
    allocator = ContextAllocator("proxy")
    allocator._next = 2**62 - 1  # the last odd value
    assert allocator.allocate() == 2**62 - 1
    with pytest.raises(ContextError, match="exhausted"):
        allocator.allocate()


def test_clamp_payload():
    # sec. 6.1: what fits in a QUIC DATAGRAM frame after the Quarter Stream ID and Context ID
    assert clamp_payload(1200, 2) == 1198
    assert clamp_payload(100_000, 2) == MAX_UDP_PAYLOAD
    assert clamp_payload(1, 2) == 0
    with pytest.raises(ValueError, match="negative"):
        clamp_payload(-1, 0)
    with pytest.raises(ValueError, match="negative"):
        clamp_payload(10, -1)
