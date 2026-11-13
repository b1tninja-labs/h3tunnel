"""RFC 9484 sec. 6 datagram payload, sec. 4.8 extension header walk, sec. 7.2 packet rules."""

from __future__ import annotations

import struct

import pytest

from h3tunnel.ip_datagram import (
    check_ipv6_link_mtu,
    decode_ip_datagram,
    decrement_hop_limit,
    encode_ip_datagram,
    ip_version,
    outermost_protocol,
)

H = bytes.fromhex


def _ipv4() -> bytes:
    """A 20-octet IPv4 header (UDP, TTL 64) with a correct RFC 1071 checksum, plus 4 payload octets."""
    header = bytearray(H("450000180000400040110000c0a80001c0a800c7"))
    total = sum(struct.unpack(">10H", bytes(header)))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    header[10:12] = struct.pack(">H", ~total & 0xFFFF)
    return bytes(header) + b"abcd"


IPV4 = _ipv4()


def v6(next_header: int, rest: bytes = b"", hop_limit: int = 64) -> bytes:
    return struct.pack(">IHBB", 6 << 28, len(rest), next_header, hop_limit) + bytes(32) + rest


def checksum_ok(header: bytes) -> bool:
    total = sum(struct.unpack(f">{len(header) // 2}H", header))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total == 0xFFFF


def test_datagram_payload_is_context_zero_then_the_packet():
    assert encode_ip_datagram(IPV4) == b"\x00" + IPV4
    assert decode_ip_datagram(b"\x00" + IPV4) == IPV4
    assert decode_ip_datagram(b"\x04" + IPV4) is None  # an unregistered Context ID, not a packet
    six = v6(17, b"x" * 8)
    assert decode_ip_datagram(encode_ip_datagram(six)) == six
    for bad in (b"", b"\x20abc", b"\x00"):
        with pytest.raises(ValueError, match="IP Version"):
            encode_ip_datagram(bad)
    # the receiver does not validate: that is a forwarding error, not a protocol violation
    assert decode_ip_datagram(b"\x00\x20junk") == b"\x20junk"
    assert ip_version(b"\x20junk") is None
    assert (ip_version(IPV4), ip_version(six)) == (4, 6)


def test_outermost_protocol_ipv4_and_plain_ipv6():
    assert outermost_protocol(IPV4) == 17
    assert outermost_protocol(IPV4[:19]) is None
    assert outermost_protocol(v6(6, b"tcp header....")) == 6
    assert outermost_protocol(v6(0)[:39]) is None


def test_ipv6_extension_header_chain_is_walked():
    hop_by_hop = bytes([43, 0]) + bytes(6)  # next: routing, length 0 -> 8 octets
    routing = bytes([60, 1]) + bytes(14)  # next: destination options, (1+1)*8 = 16 octets
    destination = bytes([6, 0]) + bytes(6)  # next: TCP
    assert outermost_protocol(v6(0, hop_by_hop + routing + destination + b"tcp")) == 6
    # a first fragment (offset 0) has an upper-layer header after the 8-octet fragment header
    first_fragment = bytes([17, 0]) + struct.pack(">HI", 0x0001, 7)
    assert outermost_protocol(v6(44, first_fragment + b"udp")) == 17
    # a non-first fragment carries no upper-layer header
    later = bytes([17, 0]) + struct.pack(">HI", 8 << 3, 7)
    assert outermost_protocol(v6(44, later + b"data")) is None
    # Authentication: (Payload Len + 2) * 4 octets
    auth = bytes([6, 1]) + bytes(2) + bytes(4) + bytes(4) + bytes(4)  # payload len 1 -> 12 octets
    assert outermost_protocol(v6(51, auth + b"tcp")) == 6
    # ESP hides what follows: the walk stops at it, and so does experimental 253
    assert outermost_protocol(v6(50, b"encrypted....")) == 50
    assert outermost_protocol(v6(253, b"experiment")) == 253
    # Mobility (135) and Shim6 (140) use the Hdr Ext Len form
    assert outermost_protocol(v6(135, bytes([59, 0]) + bytes(6))) == 59  # No Next Header
    assert outermost_protocol(v6(140, bytes([6, 0]) + bytes(6))) == 6


def test_hop_by_hop_zero_is_an_extension_header_not_the_wildcard():
    # RFC 9484 sec. 4.8: number 0 in a ROUTE_ADVERTISEMENT means "all protocols"; in a packet it is
    # the Hop-by-Hop header, so a packet whose next header is 0 is walked, not matched as 0.
    assert outermost_protocol(v6(0, bytes([17, 0]) + bytes(6) + b"udp")) == 17


def test_a_chain_cut_short_or_looping_gives_none():
    assert outermost_protocol(v6(43, bytes([6, 5]) + bytes(6))) is None  # claims 48 octets
    assert outermost_protocol(v6(43, b"\x06")) is None  # not even a length octet
    assert outermost_protocol(v6(44, bytes([6, 0]) + b"\x00")) is None
    assert outermost_protocol(v6(51, bytes([6, 200]) + bytes(6))) is None
    loop = bytes([60, 0]) + bytes(6)  # destination options pointing at themselves, forever
    assert outermost_protocol(v6(60, loop * 40)) is None


def test_decrement_hop_limit_on_encapsulation():
    six = v6(17, b"x" * 8, hop_limit=64)
    assert decrement_hop_limit(six) == v6(17, b"x" * 8, hop_limit=63)
    assert decrement_hop_limit(v6(17, b"", hop_limit=1)) is None
    assert decrement_hop_limit(v6(17, b"", hop_limit=0)) is None
    assert checksum_ok(IPV4[:20])  # the sample header is valid to begin with
    out = decrement_hop_limit(IPV4)
    assert out is not None
    assert out[8] == 0x3F
    assert out[:8] == IPV4[:8]
    assert out[12:] == IPV4[12:]  # addresses and payload untouched
    assert checksum_ok(out[:20])
    ttl_one = bytearray(IPV4)
    ttl_one[8] = 1
    assert decrement_hop_limit(bytes(ttl_one)) is None
    with pytest.raises(ValueError, match="IHL"):
        decrement_hop_limit(bytes([0x44]) + IPV4[1:])
    with pytest.raises(ValueError, match="IHL"):
        decrement_hop_limit(IPV4[:12])
    with pytest.raises(ValueError, match="40"):
        decrement_hop_limit(b"\x60" + bytes(10))
    with pytest.raises(ValueError, match="not an IP"):
        decrement_hop_limit(b"\x20abc")


def test_ipv6_link_mtu_minimum():
    check_ipv6_link_mtu(1280)
    check_ipv6_link_mtu(65535)
    with pytest.raises(ValueError, match="abort the stream"):
        check_ipv6_link_mtu(1279)
