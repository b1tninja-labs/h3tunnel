"""The receive-side state machine: unknown contexts, buffering limits, the 65527 abort."""

from __future__ import annotations

import pytest

from h3tunnel.errors import PayloadTooLarge
from h3tunnel.httpdatagram import encode_datagram
from h3tunnel.sansio import Abort, Buffered, Deliver, Dropped, Tunnel, on_datagram


def datagram(context_id: int, payload: bytes) -> bytes:
    return context_id.to_bytes(1, "big") + payload  # a one-octet varint below 64


def test_context_zero_is_delivered_without_registration():
    tunnel = Tunnel("client")
    assert on_datagram(tunnel, datagram(0, b"hello"), 0.0) == [Deliver(0, b"hello")]
    assert on_datagram(tunnel, datagram(0, b""), 0.0) == [Deliver(0, b"")]  # an empty payload
    assert on_datagram(tunnel, encode_datagram(0, b"x" * 65527), 0.0) == [Deliver(0, b"x" * 65527)]


def test_oversize_udp_payload_aborts_the_stream():
    tunnel = Tunnel("client")
    events = on_datagram(tunnel, b"\x00" + b"x" * 65528, 0.0)
    assert len(events) == 1
    assert isinstance(events[0], Abort)
    assert "65527" in events[0].reason
    with pytest.raises(PayloadTooLarge):
        encode_datagram(0, b"x" * 65528)  # and the sender side refuses to send one


def test_link_mtu_may_discard_instead_of_aborting():
    tunnel = Tunnel("client", max_udp_payload=1200)
    assert on_datagram(tunnel, datagram(0, b"x" * 1201), 0.0) == [
        Dropped("larger than the link allows")
    ]
    assert on_datagram(tunnel, datagram(0, b"x" * 1200), 0.0) == [Deliver(0, b"x" * 1200)]


def test_unknown_context_is_buffered_then_released_on_registration():
    tunnel = Tunnel("client")
    assert on_datagram(tunnel, datagram(4, b"early"), 1.0) == [Buffered(4)]
    assert on_datagram(tunnel, datagram(6, b"other"), 1.1) == [Buffered(6)]
    assert tunnel.buffered == 2
    assert tunnel.register_context(4, 1.2) == [Deliver(4, b"early")]
    assert tunnel.buffered == 1  # context 6 is still waiting
    assert on_datagram(tunnel, datagram(4, b"later"), 1.3) == [Deliver(4, b"later")]


def test_buffered_datagrams_expire_after_about_a_round_trip():
    tunnel = Tunnel("client", buffer_window=0.5)
    on_datagram(tunnel, datagram(4, b"a"), 0.0)
    assert tunnel.tick(0.4) == []
    assert tunnel.tick(0.5) == [Dropped("buffered datagram expired")]
    assert tunnel.buffered == 0
    assert tunnel.register_context(4, 0.6) == []  # nothing is left to release
    on_datagram(tunnel, datagram(8, b"b"), 1.0)
    # an expired datagram is also reported when the next datagram arrives
    assert on_datagram(tunnel, datagram(0, b"z"), 2.0) == [
        Dropped("buffered datagram expired"),
        Deliver(0, b"z"),
    ]


def test_buffer_limits_drop_the_newest_not_the_oldest():
    by_count = Tunnel("client", max_buffered=2)
    assert on_datagram(by_count, datagram(4, b"1"), 0.0) == [Buffered(4)]
    assert on_datagram(by_count, datagram(4, b"2"), 0.0) == [Buffered(4)]
    assert on_datagram(by_count, datagram(4, b"3"), 0.0) == [Dropped("buffer full")]
    assert by_count.register_context(4, 0.1) == [Deliver(4, b"1"), Deliver(4, b"2")]
    by_size = Tunnel("client", max_buffered_bytes=10)
    assert on_datagram(by_size, datagram(4, b"x" * 6), 0.0) == [Buffered(4)]
    assert on_datagram(by_size, datagram(4, b"x" * 6), 0.0) == [Dropped("buffer full")]  # 6+6 > 10
    assert on_datagram(by_size, datagram(4, b"x" * 4), 0.0) == [Buffered(4)]  # 6+4 fits
    no_buffer = Tunnel("client", max_buffered=0)
    assert on_datagram(no_buffer, datagram(4, b"x"), 0.0) == [Dropped("buffer full")]


def test_proxy_buffers_until_the_request_arrives():
    tunnel = Tunnel("proxy")
    assert not tunnel.request_received
    assert on_datagram(tunnel, datagram(0, b"before"), 0.0) == [Buffered(0)]  # sec. 5 para 6
    assert tunnel.mark_request_received(0.2) == [Deliver(0, b"before")]
    assert on_datagram(tunnel, datagram(0, b"after"), 0.3) == [Deliver(0, b"after")]


def test_a_buffered_oversize_payload_aborts_when_released():
    tunnel = Tunnel("proxy")
    on_datagram(tunnel, b"\x00" + b"x" * 65528, 0.0)
    events = tunnel.mark_request_received(0.1)
    assert len(events) == 1
    assert isinstance(events[0], Abort)


def test_closed_receive_side_drops_silently_and_short_datagrams_are_dropped():
    tunnel = Tunnel("client")
    on_datagram(tunnel, datagram(4, b"held"), 0.0)
    tunnel.close_receive()
    assert tunnel.buffered == 0
    assert on_datagram(tunnel, datagram(0, b"late"), 0.1) == [Dropped("receive side closed")]
    fresh = Tunnel("client")
    assert on_datagram(fresh, b"", 0.0) == [Dropped("datagram too short for a Context ID")]
    assert on_datagram(fresh, b"\x40", 0.0) == [Dropped("datagram too short for a Context ID")]


def test_construction_is_checked():
    with pytest.raises(ValueError, match="role"):
        Tunnel("relay")
    with pytest.raises(ValueError, match="negative"):
        Tunnel("client", buffer_window=-1)
    with pytest.raises(ValueError, match="negative"):
        Tunnel("client").register_context(-1, 0.0)


def test_on_datagram():
    # the module-level function is the machine's method
    tunnel = Tunnel("client")
    assert on_datagram(tunnel, datagram(0, b"q"), 0.0) == tunnel.on_datagram(datagram(0, b"q"), 0.0)
