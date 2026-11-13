"""The sans-IO UDP proxy rules of RFC 9298 sec. 3.1 and the Proxy-Status of RFC 9209."""

from __future__ import annotations

import pytest

from h3tunnel import proxy
from h3tunnel.proxy import (
    CloseStream,
    Discard,
    Forward,
    NeedResolution,
    ProxySession,
    Target,
)


def test_a_name_must_be_resolved_before_the_reply_and_a_literal_need_not():
    # RFC 9298 sec. 3.1 para 3
    assert proxy.plan_target("example.com", 443) == NeedResolution("example.com", 443)
    assert proxy.plan_target("192.0.2.7", 53) == Target("192.0.2.7", 53)
    assert proxy.plan_target("2001:db8::1", 53) == Target("2001:db8::1", 53)
    assert proxy.plan_target("2001:0DB8:0:0:0:0:0:1", 53) == Target("2001:db8::1", 53)
    for host, port in (("", 1), ("example.com", 0), ("example.com", 65536), ("example.com", True)):
        with pytest.raises(ValueError, match="target_"):
            proxy.plan_target(host, port)


def test_resolution_failures_are_rejected_with_proxy_status():
    # RFC 9209 sec. 2.3.2 and sec. 2.3.1: dns_error is 502 and dns_timeout is 504
    error = proxy.reject_dns_error("proxy.example", rcode="NXDOMAIN")
    assert error.status == 502
    assert error.proxy_status == 'proxy.example; error=dns_error; rcode="NXDOMAIN"'
    detailed = proxy.reject_dns_error("proxy.example", rcode="SERVFAIL", info_code=23)
    assert detailed.proxy_status.endswith('rcode="SERVFAIL"; info-code=23')
    timeout = proxy.reject_dns_timeout("proxy.example")
    assert (timeout.status, timeout.proxy_status) == (504, "proxy.example; error=dns_timeout")
    prohibited = proxy.reject_prohibited("proxy.example")
    assert (prohibited.status, prohibited.proxy_status) == (
        502,
        "proxy.example; error=destination_ip_prohibited",
    )


def test_proxy_status_serialisation():
    # a Token identity stays bare, anything else becomes a String (RFC 9209 sec. 2 paragraph 7)
    assert proxy.proxy_status("ExampleCDN", "connection_timeout") == (
        "ExampleCDN; error=connection_timeout"
    )
    assert proxy.proxy_status("my proxy 3", "dns_error") == '"my proxy 3"; error=dns_error'
    assert proxy.proxy_status('a"b', "dns_error", rcode='x"y') == (
        '"a\\"b"; error=dns_error; rcode="x\\"y"'
    )
    for bad_error in ("", "9x", "has space"):
        with pytest.raises(ValueError, match="Token"):
            proxy.proxy_status("p", bad_error)
    with pytest.raises(ValueError, match="empty"):
        proxy.proxy_status("", "dns_error")
    with pytest.raises(ValueError, match="ASCII"):
        proxy.proxy_status("pröxy", "dns_error")


def session(**options):
    return ProxySession(Target("192.0.2.7", 53), now=0.0, **options)


def test_source_validation_discards_packets_that_do_not_match_the_request():
    # RFC 9298 sec. 3.1 para 4
    proxied = session()
    assert proxied.on_target_packet("192.0.2.7", 53, b"answer", 1.0) == Forward(b"answer")
    for address, port in (("192.0.2.8", 53), ("192.0.2.7", 54), ("2001:db8::7", 53), ("junk", 53)):
        assert isinstance(proxied.on_target_packet(address, port, b"spoof", 1.0), Discard)
    assert proxied.dropped_source == 4
    # a dual-stack socket reports an IPv4 peer as an IPv4-mapped IPv6 address
    assert proxied.on_target_packet("::ffff:192.0.2.7", 53, b"m", 1.0) == Forward(b"m")
    # a connected socket lets the kernel filter, so the proxy does not
    kernel = session(connected=True)
    assert kernel.on_target_packet("198.51.100.1", 99, b"x", 1.0) == Forward(b"x")
    v6 = ProxySession(Target("2001:db8::7", 53), now=0.0)
    assert v6.on_target_packet("2001:DB8:0:0:0:0:0:7", 53, b"y", 1.0) == Forward(b"y")


def test_oversize_datagrams_are_dropped_not_fragmented():
    # RFC 9298 sec. 3.1 para 7: 1280 less 20 (IPv4) and 8 (UDP), or less 40 (IPv6)
    v4 = session()
    assert v4.max_payload == 1252
    assert v4.set_df
    assert v4.on_client_datagram(bytes(1252), 1.0) == Forward(bytes(1252))
    assert isinstance(v4.on_client_datagram(bytes(1253), 1.0), Discard)
    assert v4.dropped_oversize == 1
    v6 = ProxySession(Target("2001:db8::7", 53), now=0.0, path_mtu=1500)
    assert v6.max_payload == 1452
    assert not v6.set_df
    jumbo = ProxySession(Target("192.0.2.7", 53), now=0.0, path_mtu=1_000_000)
    assert jumbo.max_payload == 65527  # never above the payload cap of sec. 5 para 6
    with pytest.raises(ValueError, match="smallest"):
        ProxySession(Target("192.0.2.7", 53), now=0.0, path_mtu=10)


def test_idle_close_floor_and_socket_errors():
    # RFC 9298 sec. 3.1 para 5: two minutes is the floor for an idle close
    assert proxy.MIN_IDLE_SECONDS == 120.0
    with pytest.raises(ValueError, match="two minutes"):
        session(idle_timeout=30.0)
    short = session(idle_timeout=30.0, allow_short_idle=True)
    assert short.tick(29.9) is None
    assert short.tick(30.0) == CloseStream("idle timeout")
    default = session()
    assert default.tick(119.9) is None
    # traffic in either direction counts as use
    default.on_client_datagram(b"x", 100.0)
    assert default.tick(219.0) is None
    default.on_target_packet("192.0.2.7", 53, b"y", 200.0)
    assert default.tick(319.0) is None
    assert default.tick(320.0) == CloseStream("idle timeout")
    assert default.closed
    assert isinstance(default.on_client_datagram(b"z", 321.0), Discard)
    # the OS reports the socket unusable (ICMP Destination Unreachable): close the stream
    broken = session()
    assert isinstance(broken.on_socket_error(), CloseStream)
    assert broken.closed
    assert isinstance(broken.on_target_packet("192.0.2.7", 53, b"w", 1.0), Discard)
    ended = session()
    ended.on_stream_closed()
    assert ended.closed
    with pytest.raises(ValueError, match="positive"):
        session(idle_timeout=0.0, allow_short_idle=True)


def test_proxy_rules():
    # the umbrella row: one stream from request to idle close
    plan = proxy.plan_target("example.com", 53)
    assert isinstance(plan, NeedResolution)  # resolve first, then answer
    proxied = ProxySession(Target("192.0.2.7", 53), now=0.0)
    assert proxied.on_client_datagram(b"query", 0.5) == Forward(b"query")
    assert proxied.on_target_packet("192.0.2.7", 53, b"reply", 0.6) == Forward(b"reply")
    assert isinstance(proxied.on_target_packet("203.0.113.9", 53, b"spoof", 0.7), Discard)
    assert proxied.tick(120.6) == CloseStream("idle timeout")
