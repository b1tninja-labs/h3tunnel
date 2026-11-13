"""CONNECT-UDP: the URI Template, request shapes and responses (RFC 9298 sec. 2, 3.2 to 3.5),
the optimistic-send rule (RFC 9931 sec. 6.3) and the template subset of RFC 6570.
"""

from __future__ import annotations

import pytest

from h3tunnel.connect_udp import (
    build_request,
    check_response,
    default_template,
    expand,
    serialize_http11,
    validate_target,
    validate_template,
)
from h3tunnel.errors import TemplateError, TunnelRefused
from h3tunnel.template import parse_template

TEMPLATE = "https://example.org/.well-known/masque/udp/{target_host}/{target_port}/"


def test_default_template_example():
    # RFC 9298 sec. 3.2 and Figure 3, byte for byte
    request = build_request(TEMPLATE, "192.0.2.6", 443, "1.1")
    assert serialize_http11(request) == (
        b"GET https://example.org/.well-known/masque/udp/192.0.2.6/443/ HTTP/1.1\r\n"
        b"Host: example.org\r\n"
        b"Connection: Upgrade\r\n"
        b"Upgrade: connect-udp\r\n"
        b"Capsule-Protocol: ?1\r\n"
        b"\r\n"
    )
    assert expand(TEMPLATE, "192.0.2.6", 443) == (
        "https://example.org/.well-known/masque/udp/192.0.2.6/443/"
    )


@pytest.mark.parametrize("version", ["2", "3"])
def test_request_shapes_h2_h3(version):
    # RFC 9298 sec. 3.4, Figure 5
    request = build_request(TEMPLATE, "192.0.2.6", 443, version)
    assert request.method == "CONNECT"
    assert request.headers == (
        (":method", "CONNECT"),
        (":protocol", "connect-udp"),
        (":scheme", "https"),
        (":path", "/.well-known/masque/udp/192.0.2.6/443/"),
        (":authority", "example.org"),
        ("capsule-protocol", "?1"),
    )
    with pytest.raises(ValueError, match="text serialisation"):
        serialize_http11(request)


def test_default_template_for_a_proxy_known_by_host_and_port():
    # sec. 2 paragraph 13
    template = default_template("proxy.example", 4433)
    assert (
        template == "https://proxy.example:4433/.well-known/masque/udp/{target_host}/{target_port}/"
    )
    assert build_request(template, "a.example", 53, "3").headers[4] == (
        ":authority",
        "proxy.example:4433",
    )


@pytest.mark.parametrize(
    ("template", "path"),
    [
        (  # Figure 1 of sec. 2
            "https://proxy.example.org:4443/masque?h={target_host}&p={target_port}",
            "/masque?h=h.example&p=53",
        ),
        (
            "https://proxy.example.org:4443/masque{?target_host,target_port}",
            "/masque?target_host=h.example&target_port=53",
        ),
        (
            "https://p.example/m{?target_port,target_host}{&x}",
            "/m?target_port=53&target_host=h.example",
        ),
    ],
)
def test_the_other_templates_of_figure_1(template, path):
    assert build_request(template, "h.example", 53, "2").headers[3] == (":path", path)


@pytest.mark.parametrize(
    "template",
    [
        "https://example.org/{+target_host}/{target_port}/",  # reserved expansion
        "https://example.org/{#target_host}/{target_port}/",  # fragment expansion
        "https://example.org/x{.target_host}/{target_port}/",  # label expansion
        "https://example.org/{/target_host}/{target_port}/",  # path segment expansion
        "https://example.org/x{;target_host}/{target_port}/",  # path-style parameters
        "https://example.org/{target_host*}/{target_port}/",  # level 4: explode
        "https://example.org/{target_host:3}/{target_port}/",  # level 4: prefix
        "https://example.org/{=target_host}/{target_port}/",  # reserved operator
        "https://example.org/{target_host}/",  # target_port missing
        "https://example.org/{target_port}/",  # target_host missing
        "/udp/{target_host}/{target_port}/",  # relative
        "//example.org/{target_host}/{target_port}/",  # no scheme
        "https:///udp/{target_host}/{target_port}/",  # empty authority
        "https://{target_host}.example.org/{target_port}/",  # variable in the authority
        "https://example.org{?target_host,target_port}",  # path does not start with a slash
        "https://example.org",  # no path
        "https://example.org/x#{target_host}/{target_port}",  # variable in the fragment
        "https://example.org/café/{target_host}/{target_port}/",  # non-ASCII
        "https://example.org/a b/{target_host}/{target_port}/",  # a space
        "https://example.org/{target_host}/{target_port}/\n",  # a control character
        "https://example.org/{target_host}/{target_port}/{",  # unclosed
        "https://example.org/{target_host}/{target_port}/}",  # stray brace
        "https://example.org/{}/{target_host}/{target_port}/",  # empty expression
        "https://example.org/{target_host,}/{target_port}/",  # empty variable name
        "https://example.org/{ta rget}/{target_host}/{target_port}/",  # bad variable name
        "https://example.org/100%/{target_host}/{target_port}/",  # bare percent
        'https://example.org/"/{target_host}/{target_port}/',  # DQUOTE is not a literal
    ],
)
def test_template_rejections(template):
    # sec. 2 paragraph 12: the client MUST reject the configuration and not send the request
    with pytest.raises(TemplateError):
        validate_template(template)
    with pytest.raises(TemplateError):
        build_request(template, "192.0.2.6", 443, "3")


def test_template_literal_percent_triplet_and_apostrophe_are_allowed():
    # RFC 6570 sec. 2.1 as corrected by erratum 6937: the apostrophe is a literal
    validate_template("https://example.org/it's%20here/{target_host}/{target_port}/")


def test_ipv6_target_is_percent_encoded():
    # sec. 3 paragraph 5
    assert expand(TEMPLATE, "2001:db8::42", 443).endswith("/udp/2001%3Adb8%3A%3A42/443/")


@pytest.mark.parametrize(
    "host",
    ["a/../b?x=1#y", "a b", "a\r\nHost: evil", "a%2Fb", "", "fe80::1%eth0", "::g", "[::1]", "aé"],
)
def test_host_cannot_inject_path_or_headers(host):
    with pytest.raises(ValueError, match=r"target_host|IPv"):
        build_request(TEMPLATE, host, 443, "1.1")


def test_expansion_encodes_every_reserved_character_in_a_value():
    # the second line of defence, below validate_target: the engine alone never emits syntax
    out = parse_template("https://p/{a}").expand({"a": "a/../b?x=1#y%"})
    assert out == "https://p/a%2F..%2Fb%3Fx%3D1%23y%25"
    assert parse_template("https://p/{a}").expand({"a": "é"}) == "https://p/%C3%A9"


def test_undefined_variables_are_skipped():
    template = parse_template("https://p/m{?a,b,c}")
    assert template.expand({"b": "2"}) == "https://p/m?b=2"
    assert template.expand({}) == "https://p/m"
    assert parse_template("https://p/{a,b}").expand({"b": "x", "a": "y"}) == "https://p/y,x"


@pytest.mark.parametrize("port", [0, 65536, -1, True, "443", 1.5])
def test_port_range(port):
    with pytest.raises(ValueError, match="target_port"):
        validate_target("example.org", port)


def test_port_edges_accepted():
    validate_target("example.org", 1)
    validate_target("example.org", 65535)


def test_unsupported_http_version():
    with pytest.raises(ValueError, match="unsupported"):
        build_request(TEMPLATE, "example.org", 443, "0.9")


def test_path_may_start_with_two_slashes():
    # RFC 9114 erratum 7014 (sec. 4.3.1): :path is an absolute-path, which may begin with "//"
    template = "https://example.org//masque/{target_host}/{target_port}/"
    assert build_request(template, "a.example", 1, "3").target == "//masque/a.example/1/"


def test_fragment_is_not_part_of_the_path():
    template = "https://example.org/m/{target_host}/{target_port}/#frag"
    assert build_request(template, "a.example", 1, "3").target == "/m/a.example/1/"


def test_http11_never_optimistic():
    # RFC 9931 sec. 6.3: HTTP/1.x MUST NOT send UDP packets before the response; HTTP/2 or later MAY
    assert build_request(TEMPLATE, "a.example", 1, "1.1").optimistic_send_allowed is False
    assert build_request(TEMPLATE, "a.example", 1, "2").optimistic_send_allowed is True
    assert build_request(TEMPLATE, "a.example", 1, "3").optimistic_send_allowed is True


def test_response_http11():
    good = [("Connection", "Upgrade"), ("Upgrade", "connect-udp"), ("Capsule-Protocol", "?1")]
    check_response("1.1", 101, good)
    check_response("1.1", 101, [("connection", "upgrade"), ("UPGRADE", "CONNECT-UDP")])
    bad_cases = [
        (200, good),
        (101, [("Upgrade", "connect-udp")]),
        (101, [("Connection", "Upgrade")]),
        (101, [("Connection", "Upgrade"), ("Upgrade", "websocket")]),
        (101, [("Connection", "Upgrade"), ("Upgrade", "connect-udp"), ("Upgrade", "connect-udp")]),
        (101, [*good, ("Content-Length", "0")]),
        (101, [*good, ("Transfer-Encoding", "chunked")]),
        (101, [*good, ("Content-Type", "text/plain")]),
    ]
    for status, headers in bad_cases:
        with pytest.raises(TunnelRefused):
            check_response("1.1", status, headers)


@pytest.mark.parametrize("version", ["2", "3"])
def test_response_h2_h3(version):
    check_response(version, 200, [("capsule-protocol", "?1")])
    check_response(version, 299, [])
    for status in (101, 199, 300, 404, 204, 205, 206):
        with pytest.raises(TunnelRefused):
            check_response(version, status, [])
    with pytest.raises(TunnelRefused):
        check_response(version, 200, [("content-length", "5")])
    with pytest.raises(ValueError, match="unsupported"):
        check_response("0.9", 200, [])
