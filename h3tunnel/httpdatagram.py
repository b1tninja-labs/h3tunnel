"""HTTP Datagram payloads: UDP Proxying framing and the HTTP/3 Quarter Stream ID.

RFC 9298 sec. 5: a UDP Proxying HTTP Datagram Payload is ``Context ID (i)`` then the payload.
RFC 9297 sec. 2.1: in a QUIC DATAGRAM frame a ``Quarter Stream ID (i)`` comes first.
"""

from __future__ import annotations

from .errors import H3DatagramError, H3SettingsError, Incomplete
from .limits import check_udp_payload
from .varint import decode_varint, encode_varint

__all__ = [
    "MAX_QUARTER_STREAM_ID",
    "decode_datagram",
    "decode_h3_datagram",
    "decode_udp_payload",
    "encode_datagram",
    "encode_h3_datagram",
    "validate_h3_datagram_setting",
]

# RFC 9297 sec. 2.1 paragraph 4: the largest stream ID is 2**62-1, divided by four.
MAX_QUARTER_STREAM_ID = (1 << 60) - 1


def encode_datagram(context_id: int, payload: bytes) -> bytes:
    """``Context ID (i)`` followed by ``payload`` (RFC 9298 sec. 5, Figure 7).

    The payload may be empty. A Context ID of zero carries a UDP payload, which must not exceed
    65527 octets (:func:`h3tunnel.limits.check_udp_payload`).
    """
    if context_id == 0:
        check_udp_payload(payload, receiving=False)
    return encode_varint(context_id) + bytes(payload)


def decode_datagram(data: bytes) -> tuple[int, bytes]:
    """Split an HTTP Datagram payload into ``(context_id, payload)`` (RFC 9298 sec. 5).

    Raises :class:`~h3tunnel.errors.Incomplete` if the Context ID is cut short. No policy is
    applied: an unknown Context ID is dropped or briefly buffered by the caller (sec. 5 paragraph
    4), and the 65527 limit belongs to :func:`decode_udp_payload`.
    """
    context_id, pos = decode_varint(data, 0)
    return context_id, bytes(data[pos:])


def decode_udp_payload(data: bytes) -> bytes | None:
    """The UDP payload of a received datagram, or ``None`` when it is not for Context ID zero.

    RFC 9298 sec. 5 paragraphs 5 and 6: Context ID zero carries the unmodified UDP payload, and
    one longer than 65527 octets is a :class:`~h3tunnel.errors.PayloadTooLarge` that the receiver
    answers by aborting the stream. Any other Context ID returns ``None``: it must never be
    surfaced as a UDP payload.
    """
    context_id, payload = decode_datagram(data)
    if context_id != 0:
        return None
    check_udp_payload(payload, receiving=True)
    return payload


def encode_h3_datagram(stream_id: int, context_id: int, payload: bytes) -> bytes:
    """Data of a QUIC DATAGRAM frame: Quarter Stream ID, Context ID, payload (RFC 9297 sec. 2.1).

    ``stream_id`` is the client-initiated bidirectional stream of the request, so it is a
    multiple of four.
    """
    if stream_id < 0 or stream_id % 4:
        raise ValueError(f"{stream_id} is not a client-initiated bidirectional stream ID")
    quarter = stream_id // 4
    if quarter > MAX_QUARTER_STREAM_ID:
        raise ValueError(f"stream ID {stream_id} is beyond the largest legal Quarter Stream ID")
    return encode_varint(quarter) + encode_datagram(context_id, payload)


def decode_h3_datagram(data: bytes) -> tuple[int, int, bytes]:
    """Parse the data of a QUIC DATAGRAM frame into ``(stream_id, context_id, payload)``.

    RFC 9297 sec. 2.1: a frame too short to hold the Quarter Stream ID, or one whose value
    exceeds 2**60 - 1, is an HTTP/3 connection error of type H3_DATAGRAM_ERROR (0x33),
    :class:`~h3tunnel.errors.H3DatagramError`. A Context ID that is cut short is ``Incomplete``.
    """
    try:
        quarter, pos = decode_varint(data, 0)
    except Incomplete as error:
        raise H3DatagramError("datagram too short to hold a Quarter Stream ID") from error
    if quarter > MAX_QUARTER_STREAM_ID:
        raise H3DatagramError(f"Quarter Stream ID {quarter} is larger than 2**60-1")
    context_id, payload = decode_datagram(data[pos:])
    return quarter * 4, context_id, payload


def validate_h3_datagram_setting(value: int, stored: int | None = None) -> bool:
    """Check a received SETTINGS_H3_DATAGRAM value; True when datagrams may be received.

    RFC 9297 sec. 2.1.1 paragraph 2: the value MUST be 0 or 1, otherwise H3_SETTINGS_ERROR.
    Paragraph 4: a client that stored the value of the server for 0-RTT MUST see a new value
    greater than or equal to it, otherwise H3_SETTINGS_ERROR
    (:class:`~h3tunnel.errors.H3SettingsError`, code 0x0109, RFC 9114 sec. 8.1).
    """
    if value not in (0, 1):
        raise H3SettingsError("SETTINGS_H3_DATAGRAM must be 0 or 1", 0x0109)
    if stored is not None and value < stored:
        raise H3SettingsError(
            "SETTINGS_H3_DATAGRAM is lower than the value stored for 0-RTT", 0x0109
        )
    return value == 1
