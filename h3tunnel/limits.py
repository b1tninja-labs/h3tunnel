"""payload limits and the optimistic-send rule (RFC 9298 sec. 5 and 6.1, RFC 9931 sec. 6.3)."""

from __future__ import annotations

from .errors import PayloadTooLarge

__all__ = [
    "MAX_UDP_PAYLOAD",
    "check_udp_payload",
    "clamp_payload",
    "optimistic_send_allowed",
]

# RFC 9298 sec. 5 paragraph 6: a UDP header cannot describe a payload longer than this.
MAX_UDP_PAYLOAD = 65527


def check_udp_payload(payload: bytes, *, receiving: bool) -> None:
    """Refuse a UDP Proxying Payload longer than 65527 octets on Context ID zero.

    RFC 9298 sec. 5 paragraph 6: an endpoint MUST NOT send one, and an endpoint that receives one
    MUST abort the stream. Both are a :class:`~h3tunnel.errors.PayloadTooLarge`; ``receiving``
    only changes the message, because the reaction of the caller (do not send, or abort) differs.
    """
    if len(payload) > MAX_UDP_PAYLOAD:
        action = "abort the stream" if receiving else "do not send"
        raise PayloadTooLarge(
            f"a UDP payload of {len(payload)} octets exceeds {MAX_UDP_PAYLOAD}: {action}"
        )


def clamp_payload(mtu: int, tunnel_overhead: int) -> int:
    """The largest UDP payload that fits one QUIC DATAGRAM frame, RFC 9298 sec. 6.1.

    ``mtu`` is the most that can go in the data of the frame (what the QUIC connection
    configuration and the path MTU allow) and ``tunnel_overhead`` the octets the tunnel adds in
    front of the UDP payload (the Quarter Stream ID and the Context ID). A larger payload is to
    be dropped, not re-encoded in a DATAGRAM capsule (sec. 6.1 paragraph 1). Never more than
    65527, never negative.
    """
    if mtu < 0 or tunnel_overhead < 0:
        raise ValueError("mtu and tunnel_overhead must not be negative")
    return max(0, min(MAX_UDP_PAYLOAD, mtu - tunnel_overhead))


def optimistic_send_allowed(http_version: str) -> bool:
    """May a CONNECT-UDP client send UDP packets before it has the response? RFC 9931 sec. 6.3.

    RFC 9931 sec. 6.3 replaces RFC 9298 sec. 5 paragraph 9: a client MAY do so "only if the HTTP
    version in use is HTTP/2 or later", and MUST NOT in HTTP/1.x because of the risk of Request
    Smuggling. ``http_version`` is "1.0", "1.1", "2" or "3".
    """
    if http_version in ("2", "3"):
        return True
    if http_version in ("1.0", "1.1"):
        return False
    raise ValueError(f"unknown HTTP version {http_version!r}")
