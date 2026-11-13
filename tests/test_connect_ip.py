"""CONNECT-IP: scope variables with erratum 8444 and the three IP capsules (RFC 9484 sec. 4.6, 4.7).

The capsule byte strings below are written out from the field layouts of Figures 7 to 12 (they
are not byte vectors printed in the RFC, which has none); each is annotated field by field.
"""

from __future__ import annotations

import ipaddress as ip

import pytest

from h3tunnel.capsule import CapsuleParser, encode_capsule
from h3tunnel.connect_ip import (
    ADDRESS_ASSIGN,
    ADDRESS_REQUEST,
    ROUTE_ADVERTISEMENT,
    AddressEntry,
    RouteRange,
    decode_address_assign,
    decode_address_request,
    decode_route_advertisement,
    encode_address_assign,
    encode_address_request,
    encode_route_advertisement,
    target_uri,
    validate_routes,
    validate_template,
)
from h3tunnel.errors import MalformedCapsule, TemplateError

DEFAULT = "https://example.org/.well-known/masque/ip/{target}/{ipproto}/"
QUERY = "https://proxy.example.org:4443/masque/ip?t={target}&i={ipproto}"
FORM = "https://proxy.example.org:4443/masque/ip{?target,ipproto}"


def test_wildcard_percent_encoded():
    # RFC 9484 erratum 8444: the wildcard MUST be percent-encoded and travels as %2A. The examples
    # of sec. 4.2 and 4.4 print a raw "*" (/ip/*/*/); the corrected path is /ip/%2A/%2A/.
    for target, ipproto in [(None, None), ("*", "*"), (None, "*"), ("*", None)]:
        out = target_uri(DEFAULT, target, ipproto)
        assert out == "https://example.org/.well-known/masque/ip/%2A/%2A/"
        assert "*" not in out
    assert target_uri(QUERY) == "https://proxy.example.org:4443/masque/ip?t=%2A&i=%2A"
    assert target_uri(FORM) == "https://proxy.example.org:4443/masque/ip?target=%2A&ipproto=%2A"


def test_scoped_requests():
    assert target_uri(DEFAULT, "192.0.2.6", 17).endswith("/ip/192.0.2.6/17/")
    assert target_uri(DEFAULT, "example.com", "6").endswith("/ip/example.com/6/")
    assert target_uri(DEFAULT, "192.0.2.0/24", 0).endswith("/ip/192.0.2.0%2F24/0/")


def test_ipv6_prefix_encoding():
    # sec. 4.6 paragraphs 6 and 7: colons are %3A and the slash before the length is %2F
    assert target_uri(DEFAULT, "2001:db8::42", None).endswith("/ip/2001%3Adb8%3A%3A42/%2A/")
    assert target_uri(DEFAULT, "2001:db8::/32", None).endswith("/ip/2001%3Adb8%3A%3A%2F32/%2A/")
    assert target_uri(DEFAULT, "::/0", None).endswith("/ip/%3A%3A%2F0/%2A/")


@pytest.mark.parametrize(
    "target",
    [
        "192.0.2.6/24",  # bits below the prefix are not zero
        "2001:db8::1/32",
        "192.0.2.0/33",
        "2001:db8::/129",
        "192.0.2.0/-1",
        "192.0.2.0/",
        "192.0.2.0/024",  # three digits for an IPv4 prefix length
        "fe80::1%eth0",  # a zone identifier
        "example.com/24",  # a hostname has no prefix length
        "a b",
        "a/b/c",
        "",
        "http://x",
    ],
)
def test_target_refusals(target):
    with pytest.raises(ValueError, match=r"."):
        target_uri(DEFAULT, target, None)


def test_prefix_low_bits_must_be_zero_edges():
    assert target_uri(DEFAULT, "192.0.2.6/32", None).endswith("192.0.2.6%2F32/%2A/")
    assert target_uri(DEFAULT, "0.0.0.0/0", None).endswith("0.0.0.0%2F0/%2A/")


@pytest.mark.parametrize(
    "ipproto", [-1, 256, "256", "1000", "-1", "x", "", "1.5", True, 1.5, chr(0x661)]
)
def test_ipproto_range(ipproto):
    with pytest.raises((ValueError, TypeError)):
        target_uri(DEFAULT, None, ipproto)


def test_ipproto_edges():
    assert target_uri(DEFAULT, None, 0).endswith("/%2A/0/")
    assert target_uri(DEFAULT, None, 255).endswith("/%2A/255/")
    assert target_uri(DEFAULT, None, "007").endswith("/%2A/7/")


def test_template_rules_shared_with_connect_udp():
    # sec. 3 paragraphs 6 to 13: the variables are optional, the rest of the rules are not
    assert validate_template("https://masque.example.org/?user=bob")
    assert (
        target_uri("https://masque.example.org/?user=bob") == "https://masque.example.org/?user=bob"
    )
    for bad in (
        "https://example.org/{+target}/",
        "https://example.org/{/target}",
        "https://example.org/{target*}/",
        "/relative/{target}",
        "https://{target}.example.org/",
    ):
        with pytest.raises(TemplateError):
            validate_template(bad)


V4 = ip.IPv4Address
V6 = ip.IPv6Address


def test_assign_roundtrip_and_empty_means_remove():
    entries = [
        AddressEntry(0, V4("192.0.2.5"), 32),
        AddressEntry(7, V6("2001:db8::"), 64),
    ]
    value = encode_address_assign(entries)
    # Request ID (i) | IP Version (8) | IP Address | IP Prefix Length (8), Figure 8
    assert value == (
        b"\x00"
        + b"\x04"
        + bytes([192, 0, 2, 5])
        + b"\x20"
        + b"\x07"
        + b"\x06"
        + bytes.fromhex("20010db8000000000000000000000000")
        + b"\x40"
    )
    assert decode_address_assign(value) == entries
    assert encode_address_assign([]) == b""
    assert decode_address_assign(b"") == []  # sec. 4.7.1 paragraph 13: all addresses removed


def test_request_roundtrip():
    entries = [AddressEntry(1, V4("0.0.0.0"), 32), AddressEntry(2, V6("::"), 128)]
    value = encode_address_request(entries)
    assert decode_address_request(value) == entries  # all-zero means no preference (para 12)
    assert value[0] == 1
    assert value[1] == 4


def test_request_zero_entries_aborts():
    # sec. 4.7.2 paragraph 15
    with pytest.raises(MalformedCapsule, match="abort"):
        decode_address_request(b"")
    with pytest.raises(ValueError, match="at least one"):
        encode_address_request([])


def test_request_id_zero_refused():
    # paragraph 8: Request IDs MUST NOT be zero and MUST NOT be reused
    with pytest.raises(ValueError, match="zero"):
        encode_address_request([AddressEntry(0, V4("0.0.0.0"), 32)])
    with pytest.raises(MalformedCapsule, match="zero"):
        decode_address_request(b"\x00\x04\x00\x00\x00\x00\x20")
    with pytest.raises(ValueError, match="repeated"):
        encode_address_request([AddressEntry(5, V4("0.0.0.0"), 32)] * 2)
    twice = b"\x05\x04\x00\x00\x00\x00\x20" * 2
    with pytest.raises(MalformedCapsule, match="repeated"):
        decode_address_request(twice)


@pytest.mark.parametrize(
    "value",
    [
        b"\x00\x05\x01\x02\x03\x04\x20",  # IP Version 5
        b"\x00\x04\x01\x02\x03\x04\x21",  # prefix length 33 for IPv4
        b"\x00\x04\x01\x02\x03\x05\x1f",  # /31 with a low bit set
        b"\x00\x06" + bytes(16) + b"\x81",  # prefix length 129 for IPv6
    ],
)
def test_assign_malformed_fields(value):
    with pytest.raises(MalformedCapsule):
        decode_address_assign(value)


def test_truncated_address_malformed():
    good = encode_address_assign([AddressEntry(0, V4("192.0.2.5"), 32)])
    for cut in range(1, len(good)):
        with pytest.raises(MalformedCapsule):
            decode_address_assign(good[:cut])


def test_trailing_bytes_malformed():
    # RFC 9297 sec. 3.3 paragraph 2: exactly the identified fields
    good = encode_address_assign([AddressEntry(0, V4("192.0.2.5"), 32)])
    with pytest.raises(MalformedCapsule):
        decode_address_assign(good + b"\x00")
    with pytest.raises(MalformedCapsule):
        decode_address_request(
            encode_address_request([AddressEntry(1, V4("0.0.0.0"), 32)]) + b"\x01"
        )
    route = encode_route_advertisement([RouteRange(V4("10.0.0.0"), V4("10.255.255.255"))])
    with pytest.raises(MalformedCapsule):
        decode_route_advertisement(route + b"\x04")


def test_encode_refuses_what_a_receiver_must_refuse():
    with pytest.raises(ValueError, match="below the prefix"):
        encode_address_assign([AddressEntry(0, V4("192.0.2.5"), 24)])
    with pytest.raises(ValueError, match="out of range"):
        encode_address_assign([AddressEntry(0, V4("192.0.2.5"), 33)])


def r4(a, b, proto=0):
    return RouteRange(V4(a), V4(b), proto)


def r6(a, b, proto=0):
    return RouteRange(V6(a), V6(b), proto)


def test_route_roundtrip():
    ranges = [
        r4("10.0.0.0", "10.255.255.255"),
        r4("192.0.2.0", "192.0.2.255", 6),
        r6("2001:db8::", "2001:db8::ffff", 17),
    ]
    value = encode_route_advertisement(ranges)
    assert value[:10] == b"\x04" + bytes([10, 0, 0, 0]) + bytes([10, 255, 255, 255]) + b"\x00"
    assert decode_route_advertisement(value) == ranges
    assert encode_route_advertisement([]) == b""
    assert decode_route_advertisement(b"") == []


@pytest.mark.parametrize(
    "ranges",
    [
        [r6("::", "::1"), r4("10.0.0.0", "10.0.0.1")],  # version of A greater than B
        [r4("10.0.0.0", "10.0.0.1", 17), r4("10.0.0.2", "10.0.0.3", 6)],  # protocol of A greater
        [
            r4("10.0.0.0", "10.0.0.5"),
            r4("10.0.0.5", "10.0.0.9"),
        ],  # End(A) not strictly below Start(B)
        [r4("10.0.0.5", "10.0.0.9"), r4("10.0.0.0", "10.0.0.1")],  # out of address order
        [r4("10.0.0.9", "10.0.0.5")],  # start after end
        [
            r4("10.0.0.0", "10.0.0.255", 0),
            r4("10.0.0.128", "10.0.0.130", 6),
        ],  # proto 0 overlaps proto 6
        [
            r4("10.0.0.0", "10.0.0.255", 6),
            r4("10.0.0.0", "10.0.0.255", 17),
            r4("10.0.0.0", "10.0.0.9", 0),
        ][::-1],  # proto 0 first then overlapping others
    ],
)
def test_route_order_violations(ranges):
    with pytest.raises(ValueError, match=r"."):
        validate_routes(ranges)
    with pytest.raises(ValueError, match=r"."):
        encode_route_advertisement(ranges)


def test_route_order_violations_on_the_wire_abort_the_stream():
    def wire(*ranges):
        return b"".join(
            bytes([r.start.version]) + r.start.packed + r.end.packed + bytes([r.ipproto])
            for r in ranges
        )

    for bad in (
        wire(r6("::", "::1"), r4("10.0.0.0", "10.0.0.1")),
        wire(r4("10.0.0.0", "10.0.0.5"), r4("10.0.0.5", "10.0.0.9")),
        wire(r4("10.0.0.0", "10.0.0.255", 0), r4("10.0.0.128", "10.0.0.130", 6)),
        wire(r4("10.0.0.9", "10.0.0.5")),
    ):
        with pytest.raises(MalformedCapsule, match="abort"):
            decode_route_advertisement(bad)
    with pytest.raises(MalformedCapsule):
        decode_route_advertisement(b"\x07" + bytes(9))  # IP Version 7
    with pytest.raises(MalformedCapsule):
        decode_route_advertisement(b"\x04" + bytes(5))  # truncated


def test_overlap_between_protocol_zero_and_nonzero_is_detected_only_when_asked():
    ranges = [r4("10.0.0.0", "10.0.0.255", 0), r4("10.0.0.128", "10.0.0.130", 6)]
    validate_routes(ranges, check_overlap=False)  # detection is OPTIONAL for a receiver (para 19)
    with pytest.raises(ValueError, match="overlaps"):
        validate_routes(ranges)
    # protocol 0 and non-zero that do not overlap are fine, and so are different versions
    validate_routes(
        [r4("10.0.0.0", "10.0.0.9", 0), r4("10.0.0.10", "10.0.0.20", 6), r6("::", "::5", 17)]
    )


def test_capsules_ride_the_capsule_codec():
    value = encode_address_assign([AddressEntry(0, V4("192.0.2.5"), 32)])
    stream = (
        encode_capsule(ADDRESS_ASSIGN, value)
        + encode_capsule(ADDRESS_REQUEST, b"")
        + encode_capsule(ROUTE_ADVERTISEMENT, b"")
    )
    capsules = CapsuleParser().feed(stream)
    assert [c.type for c in capsules] == [1, 2, 3]
    assert decode_address_assign(capsules[0].value) == [AddressEntry(0, V4("192.0.2.5"), 32)]
