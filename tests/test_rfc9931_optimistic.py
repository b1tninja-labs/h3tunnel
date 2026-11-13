"""Hostile test: RFC 9931 sec. 6.3 replaces RFC 9298 sec. 5 paragraph 9.

RFC 9298 sec. 5 paragraph 9 said a client MAY optimistically send UDP packets in HTTP Datagrams
before the response. RFC 9931 sec. 6.3 (2026-03, current, updates RFC 9298) quotes that sentence and
replaces it: only if the HTTP version in use is HTTP/2 or later; clients MUST NOT do so in HTTP/1.x
because the UDP payload is untrusted and could be read as a smuggled HTTP request.

An implementation that follows the older text would put the first UDP packet straight after the
Upgrade request on the same connection. These tests are the guard: the HTTP/1.1 request builder
emits the request and nothing else, and the one rule every sender consults says no.
"""

from __future__ import annotations

import pytest

from h3tunnel.capsule import DATAGRAM, encode_capsule
from h3tunnel.connect_udp import build_request, serialize_http11
from h3tunnel.httpdatagram import encode_datagram
from h3tunnel.limits import optimistic_send_allowed

TEMPLATE = "https://example.org/.well-known/masque/udp/{target_host}/{target_port}/"

# A UDP payload an attacker on the client device controls, shaped as the second request of a
# request-smuggling attack against whatever HTTP/1.1 parser sits in front of the proxy.
SMUGGLED = b"\r\n\r\nGET /admin HTTP/1.1\r\nHost: example.org\r\n\r\n"


@pytest.mark.parametrize("version", ["1.0", "1.1"])
def test_http1_clients_must_not_send_optimistically(version):
    assert optimistic_send_allowed(version) is False


@pytest.mark.parametrize("version", ["2", "3"])
def test_http2_and_later_may(version):
    assert optimistic_send_allowed(version) is True


def test_unknown_versions_are_refused_rather_than_guessed():
    for version in ("", "0.9", "1", "4", "HTTP/1.1"):
        with pytest.raises(ValueError, match="unknown HTTP version"):
            optimistic_send_allowed(version)


def test_http11_request_bytes_end_at_the_blank_line():
    # the builder carries no payload: nothing can follow the request until the 101 arrives
    request = build_request(TEMPLATE, "192.0.2.6", 443, "1.1")
    wire = serialize_http11(request)
    assert wire.endswith(b"\r\n\r\n")
    assert wire.count(b"\r\n\r\n") == 1
    assert not request.optimistic_send_allowed


def test_a_datagram_capsule_carrying_a_smuggled_request_is_what_the_rule_guards_against():
    capsule = encode_capsule(DATAGRAM, encode_datagram(0, SMUGGLED))
    # The codec happily frames it: framing is not the defence, the send rule is.
    assert b"GET /admin HTTP/1.1" in capsule
    request = build_request(TEMPLATE, "192.0.2.6", 443, "1.1")
    assert request.optimistic_send_allowed is False, "this capsule must wait for the 101 response"


def test_the_text_replaced_is_the_text_the_rfc_quotes():
    # Recorded so that a reader can find the sentence: RFC 9931 sec. 6.3 paragraph 4 and
    # RFC 9298 sec. 5 paragraph 9. The rule exposed by the code is the replacement, not the
    # original MAY.
    assert optimistic_send_allowed("1.1") is False
