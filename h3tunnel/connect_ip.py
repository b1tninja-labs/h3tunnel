"""CONNECT-IP: the scope variables of the URI Template and the three IP capsules (RFC 9484).

Only the wire formats and the rules a receiver must enforce are here. Address negotiation policy,
forwarding and routing tables are not (see the non-goals in README.md): a capsule that breaks a rule
in RFC 9484 sec. 4.7 is a :class:`~h3tunnel.errors.MalformedCapsule`, which RFC 9297 sec. 3.3 turns
into a malformed or incomplete message, and which the sections below also turn into an aborted
request stream.

Each ``encode_*`` returns the Capsule Value; wrap it with ``encode_capsule(TYPE, value)`` and read
one with ``decode_*`` on the ``value`` of a parsed :class:`~h3tunnel.capsule.Capsule`.
"""

from __future__ import annotations

import ipaddress
import re
from bisect import bisect_right
from collections.abc import Iterable
from dataclasses import dataclass
from itertools import pairwise

from .errors import Incomplete, MalformedCapsule
from .template import Template, validate_absolute
from .varint import decode_varint, encode_varint

__all__ = [
    "ADDRESS_ASSIGN",
    "ADDRESS_REQUEST",
    "ROUTE_ADVERTISEMENT",
    "AddressEntry",
    "RouteRange",
    "decode_address_assign",
    "decode_address_request",
    "decode_route_advertisement",
    "encode_address_assign",
    "encode_address_request",
    "encode_route_advertisement",
    "target_uri",
    "validate_routes",
    "validate_template",
]

ADDRESS_ASSIGN = 0x01
ADDRESS_REQUEST = 0x02
ROUTE_ADVERTISEMENT = 0x03

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
_REG_NAME = re.compile(r"[A-Za-z0-9\-._~!$&'()*+,;=]+")


def validate_template(template: str) -> Template:
    """Validate a CONNECT-IP URI Template, RFC 9484 sec. 3 paragraphs 6 to 13.

    The same shape rules as CONNECT-UDP (level 3 or lower, none of the operators ``+ # . / ;``,
    absolute, path starting with a slash, variables in the path or query, ASCII 0x21-0x7E), except
    that ``target`` and ``ipproto`` are optional.
    """
    return validate_absolute(template)


def _bits(address: IPAddress) -> int:
    return address.max_prefixlen


def _check_prefix(address: IPAddress, prefix_len: int, what: str) -> None:
    """RFC 9484 sec. 4.6 paragraphs 7 and 8: 0..bits, and the lower bits must be zero."""
    if not 0 <= prefix_len <= _bits(address):
        raise ValueError(f"{what}: prefix length {prefix_len} is out of range for {address}")
    network = int(address) >> (_bits(address) - prefix_len) << (_bits(address) - prefix_len)
    if network != int(address):
        raise ValueError(
            f"{what}: bits of {address} below the prefix length {prefix_len} are not 0"
        )


def _target_value(target: str | None) -> str:
    """Validate a ``target`` value (RFC 9484 sec. 4.6, Figure 6); None is the wildcard."""
    if target is None or target == "*":
        return "*"
    if not target:
        raise ValueError("target must not be empty")
    address_text, slash, length_text = target.partition("/")
    if not slash and ":" not in target and _REG_NAME.fullmatch(target):
        return target  # an IPv4 address or a registered name
    if "%" in address_text:
        raise ValueError("IPv6 zone identifiers are not supported")
    try:
        address = ipaddress.ip_address(address_text)
    except ValueError as error:
        if slash or ":" in target:
            raise ValueError(f"{target!r} is not an IP address or prefix") from error
        raise ValueError(f"{target!r} is not a hostname, IP address or prefix") from error
    if slash:
        digits = 3 if address.version == 6 else 2
        if not length_text.isascii() or not length_text.isdigit() or len(length_text) > digits:
            raise ValueError(f"{length_text!r} is not a prefix length")
        _check_prefix(address, int(length_text), "target")
    return target


def _ipproto_value(ipproto: int | str | None) -> str:
    """Validate an ``ipproto`` value: 0..255 or the wildcard (RFC 9484 sec. 4.6 paragraph 9)."""
    if ipproto is None or ipproto == "*":
        return "*"
    if type(ipproto) not in (int, str):
        raise ValueError("ipproto must be an integer from 0 to 255 or '*'")
    if isinstance(ipproto, str):
        if not ipproto.isascii() or not ipproto.isdigit() or len(ipproto) > 3:
            raise ValueError(f"{ipproto!r} is not an IP protocol number")
        ipproto = int(ipproto)
    if not 0 <= ipproto <= 255:
        raise ValueError(f"ipproto {ipproto} is outside 0..255")
    return str(ipproto)


def target_uri(template: str, target: str | None = None, ipproto: int | str | None = None) -> str:
    """Expand a CONNECT-IP template for the scope of a request, RFC 9484 sec. 4.6.

    ``target`` is a hostname, an IP address or a prefix such as ``2001:db8::/32``; ``ipproto`` an
    integer or digit string from 0 to 255. ``None`` and ``"*"`` are the wildcard. The expansion is
    RFC 6570 simple or form-style expansion, so the colons of IPv6 become ``%3A``, the slash before
    a prefix length ``%2F`` and the wildcard ``%2A``: verified erratum 8444 of RFC 9484 sec. 4.6
    says the wildcard MUST be percent-encoded, and the examples of sec. 4.2 and 4.4 that show a raw
    ``*`` are wrong. Variables the template does not have are simply not sent.
    """
    parsed = validate_template(template)
    values = {"target": _target_value(target), "ipproto": _ipproto_value(ipproto)}
    return parsed.expand(
        {name: value for name, value in values.items() if name in parsed.variables}
    )


@dataclass(frozen=True)
class AddressEntry:
    """One Assigned Address (RFC 9484 sec. 4.7.1) or Requested Address (sec. 4.7.2)."""

    request_id: int
    address: IPAddress
    prefix_len: int


@dataclass(frozen=True)
class RouteRange:
    """One IP Address Range of a ROUTE_ADVERTISEMENT (RFC 9484 sec. 4.7.3); protocol 0 is all."""

    start: IPAddress
    end: IPAddress
    ipproto: int = 0


def _encode_entry(entry: AddressEntry, what: str) -> bytes:
    _check_prefix(entry.address, entry.prefix_len, what)
    return (
        encode_varint(entry.request_id)
        + bytes([entry.address.version])
        + entry.address.packed
        + bytes([entry.prefix_len])
    )


def _decode_entries(value: bytes, what: str) -> list[AddressEntry]:
    entries: list[AddressEntry] = []
    pos = 0
    while pos < len(value):
        try:
            request_id, pos = decode_varint(value, pos)
        except Incomplete as error:
            raise MalformedCapsule(f"{what}: truncated Request ID") from error
        if pos >= len(value):
            raise MalformedCapsule(f"{what}: truncated before the IP Version")
        version = value[pos]
        pos += 1
        if version not in (4, 6):
            raise MalformedCapsule(f"{what}: IP Version {version} is neither 4 nor 6")
        size = 4 if version == 4 else 16
        if pos + size + 1 > len(value):
            raise MalformedCapsule(f"{what}: truncated address")
        address: IPAddress = (
            ipaddress.IPv4Address(value[pos : pos + size])
            if version == 4
            else ipaddress.IPv6Address(value[pos : pos + size])
        )
        prefix_len = value[pos + size]
        pos += size + 1
        try:
            _check_prefix(address, prefix_len, what)
        except ValueError as error:
            raise MalformedCapsule(str(error)) from error
        entries.append(AddressEntry(request_id, address, prefix_len))
    return entries


def encode_address_assign(addresses: Iterable[AddressEntry]) -> bytes:
    """Value of an ADDRESS_ASSIGN capsule, type 0x01 (RFC 9484 sec. 4.7.1). May be empty."""
    return b"".join(_encode_entry(entry, "ADDRESS_ASSIGN") for entry in addresses)


def decode_address_assign(value: bytes) -> list[AddressEntry]:
    """Parse the value of an ADDRESS_ASSIGN capsule, which must be consumed exactly.

    RFC 9484 sec. 4.7.1 and RFC 9297 sec. 3.3 paragraph 2: a truncated entry, trailing bytes, an
    IP Version other than 4 or 6, a prefix length beyond the address or non-zero bits below the
    prefix are malformed. An empty capsule is valid and means every address was removed.
    """
    return _decode_entries(value, "ADDRESS_ASSIGN")


def encode_address_request(requests: Iterable[AddressEntry]) -> bytes:
    """Value of an ADDRESS_REQUEST capsule, type 0x02 (RFC 9484 sec. 4.7.2).

    At least one request; Request IDs are not zero and not repeated.
    """
    entries = list(requests)
    if not entries:
        raise ValueError("an ADDRESS_REQUEST carries at least one Requested Address")
    _check_request_ids(entries)
    return b"".join(_encode_entry(entry, "ADDRESS_REQUEST") for entry in entries)


def _check_request_ids(entries: list[AddressEntry]) -> None:
    seen: set[int] = set()
    for entry in entries:
        if entry.request_id == 0:
            raise ValueError("a Request ID in an ADDRESS_REQUEST must not be zero")
        if entry.request_id in seen:
            raise ValueError(f"Request ID {entry.request_id} is repeated")
        seen.add(entry.request_id)


def decode_address_request(value: bytes) -> list[AddressEntry]:
    """Parse the value of an ADDRESS_REQUEST capsule (RFC 9484 sec. 4.7.2).

    Zero entries MUST abort the request stream (paragraph 15), so they raise
    :class:`~h3tunnel.errors.MalformedCapsule`, as do a zero or repeated Request ID.
    """
    entries = _decode_entries(value, "ADDRESS_REQUEST")
    if not entries:
        raise MalformedCapsule("an ADDRESS_REQUEST without Requested Addresses: abort the stream")
    try:
        _check_request_ids(entries)
    except ValueError as error:
        raise MalformedCapsule(f"ADDRESS_REQUEST: {error}") from error
    return entries


def validate_routes(ranges: Iterable[RouteRange], *, check_overlap: bool = True) -> None:
    """Check the ordering rules of RFC 9484 sec. 4.7.3 paragraphs 14 to 19; raise ``ValueError``.

    For range A before range B: version of A at most that of B; with equal versions, protocol of A
    at most that of B; with both equal, End of A strictly less than Start of B. Each range has
    Start no greater than End and both of one version. ``check_overlap`` also refuses a range for
    protocol 0 that overlaps a range for a non-zero protocol (paragraph 19, which makes detection
    optional for a receiver and a sender MUST NOT send it).
    """
    items = list(ranges)
    for r in items:
        if r.start.version != r.end.version:
            raise ValueError("a range has one IP version")
        if not 0 <= r.ipproto <= 255:
            raise ValueError(f"IP protocol {r.ipproto} is outside 0..255")
        if int(r.start) > int(r.end):
            raise ValueError(f"range start {r.start} is after its end {r.end}")
    for a, b in pairwise(items):
        va, vb = a.start.version, b.start.version
        if va > vb:
            raise ValueError("ranges are not ordered by IP version")
        if va == vb:
            if a.ipproto > b.ipproto:
                raise ValueError("ranges are not ordered by IP protocol")
            if a.ipproto == b.ipproto and int(a.end) >= int(b.start):
                raise ValueError(
                    f"range ending {a.end} is not strictly before the next start {b.start}"
                )
    if check_overlap:
        for version in (4, 6):
            zero = [r for r in items if r.start.version == version and r.ipproto == 0]
            starts = [int(r.start) for r in zero]
            for r in items:
                if r.start.version != version or r.ipproto == 0:
                    continue
                i = bisect_right(starts, int(r.end)) - 1
                if i >= 0 and int(zero[i].end) >= int(r.start):
                    raise ValueError(
                        f"a range for protocol {r.ipproto} overlaps a range for all protocols"
                    )


def encode_route_advertisement(ranges: Iterable[RouteRange]) -> bytes:
    """Value of a ROUTE_ADVERTISEMENT capsule, type 0x03 (RFC 9484 sec. 4.7.3). May be empty.

    The ranges are validated first, so a sender cannot emit what a receiver must abort on.
    """
    items = list(ranges)
    validate_routes(items)
    return b"".join(
        bytes([r.start.version]) + r.start.packed + r.end.packed + bytes([r.ipproto]) for r in items
    )


def decode_route_advertisement(value: bytes) -> list[RouteRange]:
    """Parse the value of a ROUTE_ADVERTISEMENT capsule, consumed exactly.

    Truncation, trailing bytes, a bad IP Version, Start after End, and any breach of the ordering
    rules raise :class:`~h3tunnel.errors.MalformedCapsule` (the receiver MUST abort the stream,
    sec. 4.7.3 paragraph 18). Overlap between protocol 0 and a non-zero protocol is detected too.
    """
    ranges: list[RouteRange] = []
    pos = 0
    while pos < len(value):
        version = value[pos]
        if version not in (4, 6):
            raise MalformedCapsule(f"ROUTE_ADVERTISEMENT: IP Version {version} is neither 4 nor 6")
        size = 4 if version == 4 else 16
        end_of_entry = pos + 1 + 2 * size + 1
        if end_of_entry > len(value):
            raise MalformedCapsule("ROUTE_ADVERTISEMENT: truncated IP Address Range")
        cls = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
        start = cls(value[pos + 1 : pos + 1 + size])
        end = cls(value[pos + 1 + size : pos + 1 + 2 * size])
        ranges.append(RouteRange(start, end, value[end_of_entry - 1]))
        pos = end_of_entry
    try:
        validate_routes(ranges)
    except ValueError as error:
        raise MalformedCapsule(f"ROUTE_ADVERTISEMENT: {error}: abort the stream") from error
    return ranges
