"""The IP Proxying HTTP Datagram payload and the packet checks around it (RFC 9484 sec. 6, 4.8, 7.2).

RFC 9484 sec. 6: the HTTP Datagram Payload is ``Context ID (i)`` then a payload; Context ID zero
carries a full IP packet, from the IP Version field to the last octet of the IP payload; any other
Context ID is unknown unless registered, and the receiver drops it or buffers it for about a round
trip (that policy is :mod:`h3tunnel.sansio`).

Policy decisions, each pinned by a test in ``tests/test_connect_ip_datagram.py``:

* ``encode_ip_datagram`` sends the packet as given: no length rewriting, no checksum. It refuses an
  empty packet and one whose first nibble is neither 4 nor 6. RFC 9484 sec. 7.2 para 2 says a packet
  failing correctness checks is a forwarding error, not a protocol violation, so ``decode_ip_datagram``
  returns whatever Context ID zero carried and leaves classification to :func:`ip_version`.
* :func:`outermost_protocol` walks the IPv6 extension header chain (RFC 9484 sec. 4.8) to the first
  header that is not an extension header, the number scoping or routing by protocol matches
  against. The extension header numbers are the IANA "IPv6 Extension Header Types" registry (read raw
  on 2026-11-13, updated 2025-12-24): 0, 43, 44, 50, 51, 60, 135, 140, 253 and 254. Lengths: Hop-by-
  Hop, Routing, Destination Options, Mobility and Shim6 are ``(Hdr Ext Len + 1) * 8`` octets
  (RFC 8200 sec. 4), Fragment is 8, Authentication ``(Payload Len + 2) * 4`` (RFC 4302). The walk
  stops, returning that number, at ESP (50, nothing past it is readable) and at the experimental
  253 and 254 (no length format is defined); it returns ``None`` for a non-first fragment (no upper
  layer header is present) and for a chain the packet cuts short.
* :func:`decrement_hop_limit` is the RFC 9484 sec. 7.2 para 4 rule: decrement right before the
  packet goes into an HTTP Datagram. It returns ``None`` when the result would be zero (the packet is
  not forwarded); an IPv4 header checksum is updated.
* :func:`check_ipv6_link_mtu` is sec. 7.2 para 6 and 8: at least 1280 octets, otherwise abort.
"""

from __future__ import annotations

import struct

from .httpdatagram import decode_datagram, encode_datagram

__all__ = [
    "EXTENSION_HEADERS",
    "MIN_IPV6_LINK_MTU",
    "check_ipv6_link_mtu",
    "decode_ip_datagram",
    "decrement_hop_limit",
    "encode_ip_datagram",
    "ip_version",
    "outermost_protocol",
]

MIN_IPV6_LINK_MTU = 1280  # RFC 9484 sec. 7.2 para 6
# IANA IPv6 Extension Header Types registry.
EXTENSION_HEADERS = frozenset({0, 43, 44, 50, 51, 60, 135, 140, 253, 254})
_LEN8 = frozenset({0, 43, 60, 135, 140})  # (Hdr Ext Len + 1) * 8
_IPV6_FIXED = 40


def ip_version(packet: bytes) -> int | None:
    """4 or 6 from the IP Version field, else ``None`` (also for an empty packet)."""
    if not packet:
        return None
    version = packet[0] >> 4
    return version if version in (4, 6) else None


def encode_ip_datagram(packet: bytes) -> bytes:
    """The HTTP Datagram Payload for one IP packet: Context ID zero then the packet (sec. 6)."""
    if ip_version(packet) is None:
        raise ValueError("an IP packet starts with an IP Version of 4 or 6")
    return encode_datagram(0, packet)


def decode_ip_datagram(payload: bytes) -> bytes | None:
    """The IP packet of a received datagram, or ``None`` when it is not Context ID zero.

    The packet is not validated here (RFC 9484 sec. 7.2 para 2: that is a forwarding decision).
    """
    context_id, packet = decode_datagram(payload)
    return packet if context_id == 0 else None


def outermost_protocol(packet: bytes) -> int | None:
    """The Internet Protocol Number to match scoping against (RFC 9484 sec. 4.8).

    IPv4: the Protocol field. IPv6: the Next Header after walking the extension header chain, as
    the module docstring defines. ``None`` when no answer exists.
    """
    version = ip_version(packet)
    if version == 4:
        return packet[9] if len(packet) >= 20 else None
    if version != 6 or len(packet) < _IPV6_FIXED:
        return None
    number, at = packet[6], _IPV6_FIXED
    for _ in range(len(packet)):  # the chain cannot be longer than the packet
        if number not in EXTENSION_HEADERS:
            return number
        if number in (50, 253, 254):
            return number
        if at + 2 > len(packet):
            return None
        if number == 44:
            if at + 8 > len(packet):
                return None
            offset = struct.unpack_from(">H", packet, at + 2)[0] >> 3
            if offset:
                return None  # a non-first fragment has no upper-layer header
            length = 8
        elif number == 51:
            length = (packet[at + 1] + 2) * 4
        elif number in _LEN8:
            length = (packet[at + 1] + 1) * 8
        else:  # pragma: no cover - the registry set is covered above
            return None
        if at + length > len(packet):
            return None
        number, at = packet[at], at + length
    return None


def decrement_hop_limit(packet: bytes) -> bytes | None:
    """The packet with its TTL or Hop Limit decremented, or ``None`` if it would reach zero.

    RFC 9484 sec. 7.2 para 4. The IPv4 header checksum is recomputed (RFC 1071 sum over the
    header); a header shorter than its IHL, or a bad version, raises ``ValueError``.
    """
    version = ip_version(packet)
    if version == 6:
        if len(packet) < _IPV6_FIXED:
            raise ValueError("an IPv6 header is 40 octets")
        if packet[7] <= 1:
            return None
        return packet[:7] + bytes([packet[7] - 1]) + packet[8:]
    if version == 4:
        header_length = (packet[0] & 0x0F) * 4
        if header_length < 20 or len(packet) < header_length:
            raise ValueError("the IPv4 header is shorter than its IHL")
        if packet[8] <= 1:
            return None
        header = bytearray(packet[:header_length])
        header[8] -= 1
        header[10:12] = b"\x00\x00"
        total = sum(struct.unpack(f">{header_length // 2}H", bytes(header)))
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        header[10:12] = struct.pack(">H", ~total & 0xFFFF)
        return bytes(header) + packet[header_length:]
    raise ValueError("not an IP packet")


def check_ipv6_link_mtu(datagram_payload_capacity: int) -> None:
    """Raise ``ValueError`` unless an IPv6 tunnel can carry 1280-octet packets (RFC 9484 sec. 7.2).

    ``datagram_payload_capacity`` is the largest HTTP Datagram payload the connection can send. A
    smaller one means the endpoint MUST abort the IP proxying request stream (para 8).
    """
    if datagram_payload_capacity < MIN_IPV6_LINK_MTU:
        raise ValueError(
            f"the tunnel carries {datagram_payload_capacity} octets, below the IPv6 minimum "
            f"of {MIN_IPV6_LINK_MTU}: abort the stream"
        )
