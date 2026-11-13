"""CONNECT-UDP template validation, request construction and response checks (RFC 9298 sec. 2, 3).

Everything here is data in, data out: the request is described, not sent, so any HTTP stack (or the
sans-IO machine, later) can put it on the wire.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass

from .errors import TemplateError, TunnelRefused
from .limits import optimistic_send_allowed
from .template import Template, validate_absolute

__all__ = [
    "Request",
    "build_request",
    "check_response",
    "default_template",
    "expand",
    "serialize_http11",
    "validate_target",
    "validate_template",
]

_URL = re.compile(r"([A-Za-z][A-Za-z0-9+.\-]*)://([^/?#]*)(.*)", re.DOTALL)
# RFC 3986 reg-name without pct-encoded: unreserved / sub-delims. A "%" is refused because
# RFC 6570 expansion would turn it into "%25" (sec. 3.2.1 paragraph 3), so a caller supplies the
# decoded host.
_REG_NAME = re.compile(r"[A-Za-z0-9\-._~!$&'()*+,;=]+")
_FORBIDDEN_RESPONSE_FIELDS = ("content-length", "content-type", "transfer-encoding")


def default_template(proxy_host: str, proxy_port: int) -> str:
    """The default template of RFC 9298 sec. 2 paragraph 13 for a proxy known only by host and port.

    ``https://$PROXY_HOST:$PROXY_PORT/.well-known/masque/udp/{target_host}/{target_port}/``;
    an IPv6 proxy host is passed already in brackets.
    """
    template = (
        f"https://{proxy_host}:{proxy_port}/.well-known/masque/udp/{{target_host}}/{{target_port}}/"
    )
    validate_template(template)
    return template


def validate_template(template: str) -> Template:
    """Validate a CONNECT-UDP URI Template; raise ``TemplateError`` if the client must reject it.

    RFC 9298 sec. 2 paragraphs 5 to 11, which the client MUST enforce before sending anything
    (paragraph 12): level 3 or lower; no operator among ``+ # . / ;``; absolute form with a
    non-empty scheme, authority and path; the path starts with ``/``; every variable lies in the
    path or query; both ``target_host`` and ``target_port`` are present; only ASCII 0x21-0x7E.
    """
    parsed = validate_absolute(template)
    missing = {"target_host", "target_port"} - set(parsed.variables)
    if missing:
        raise TemplateError("the template lacks the variable(s) " + ", ".join(sorted(missing)))
    return parsed


def validate_target(target_host: str, target_port: int) -> None:
    """Check the variable values against RFC 9298 sec. 3 Figure 2 and paragraphs 4 to 6.

    Neither may be empty; the host is an IPv4 address, an IPv6 literal without a zone identifier
    or a registered name; the port is an integer from 1 to 65535.
    """
    if not target_host:
        raise ValueError("target_host must not be empty")
    if type(target_port) is not int or not 1 <= target_port <= 65535:
        raise ValueError(f"target_port {target_port!r} is not an integer from 1 to 65535")
    if ":" in target_host:
        try:
            address = ipaddress.IPv6Address(target_host)
        except ValueError as error:
            raise ValueError(f"{target_host!r} is not an IPv6 literal") from error
        if address.scope_id:
            raise ValueError("IPv6 zone identifiers are not supported")
    elif _REG_NAME.fullmatch(target_host) is None:
        raise ValueError(f"{target_host!r} is not an IPv4 address or a registered name")


def expand(template: str, target_host: str, target_port: int) -> str:
    """Validate ``template`` and the target, then expand the template (RFC 9298 sec. 3 paragraph 9).

    Every value is percent-encoded with only the unreserved characters left alone, so the colons of
    an IPv6 literal become ``%3A`` as sec. 3 paragraph 5 requires, and a host such as
    ``a/../b?x=1#y`` cannot reach the path or query as syntax.
    """
    parsed = validate_template(template)
    validate_target(target_host, target_port)
    return parsed.expand({"target_host": target_host, "target_port": str(target_port)})


@dataclass(frozen=True)
class Request:
    """A UDP proxying request, ready to be put on the wire.

    HTTP/1.1: ``target`` is the absolute-form URI of the request line (as in RFC 9298 Figure 3)
    and ``headers`` are the header fields. HTTP/2 and HTTP/3: ``target`` is the ``:path`` value and
    ``headers`` begin with the pseudo-header fields.
    """

    http_version: str
    method: str
    target: str
    headers: tuple[tuple[str, str], ...]

    @property
    def optimistic_send_allowed(self) -> bool:
        """RFC 9931 sec. 6.3: false on HTTP/1.x, true on HTTP/2 and later."""
        return optimistic_send_allowed(self.http_version)


def build_request(template: str, target_host: str, target_port: int, http_version: str) -> Request:
    """Build the proxying request for ``http_version`` ("1.1", "2" or "3"), RFC 9298 sec. 3.2 and 3.4.

    HTTP/1.1: method GET, one Host, ``Connection: Upgrade``, ``Upgrade: connect-udp``. HTTP/2 and
    HTTP/3: ``:method`` CONNECT, ``:protocol`` connect-udp, ``:scheme``, ``:path`` and
    ``:authority`` from the expanded template, none of them empty. Both carry
    ``Capsule-Protocol: ?1`` (RFC 9297 sec. 3.4). The template and the target are validated first.
    """
    if http_version not in ("1.1", "2", "3"):
        raise ValueError(f"unsupported HTTP version {http_version!r}")
    url = expand(template, target_host, target_port)
    match = _URL.fullmatch(url)
    if match is None:  # pragma: no cover - validate_template guarantees the shape
        raise TemplateError("the expanded template is not an absolute URI")
    scheme, authority, rest = match.groups()
    path = rest.split("#", 1)[0]
    if http_version == "1.1":
        return Request(
            "1.1",
            "GET",
            f"{scheme}://{authority}{path}",
            (
                ("Host", authority),
                ("Connection", "Upgrade"),
                ("Upgrade", "connect-udp"),
                ("Capsule-Protocol", "?1"),
            ),
        )
    return Request(
        http_version,
        "CONNECT",
        path,
        (
            (":method", "CONNECT"),
            (":protocol", "connect-udp"),
            (":scheme", scheme),
            (":path", path),
            (":authority", authority),
            ("capsule-protocol", "?1"),
        ),
    )


def serialize_http11(request: Request) -> bytes:
    """The octets of an HTTP/1.1 request (RFC 9298 sec. 3.2, Figure 3), ending at the blank line."""
    if request.http_version != "1.1":
        raise ValueError("only an HTTP/1.1 request has a text serialisation")
    lines = [f"{request.method} {request.target} HTTP/1.1"]
    lines += [f"{name}: {value}" for name, value in request.headers]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")


def check_response(http_version: str, status: int, headers: Iterable[tuple[str, str]]) -> None:
    """Raise :class:`~h3tunnel.errors.TunnelRefused` unless the response establishes the tunnel.

    HTTP/1.1 (RFC 9298 sec. 3.3): status 101, a Connection field with the Upgrade option, a single
    Upgrade field with the value connect-udp. HTTP/2 and HTTP/3 (sec. 3.5): a 2xx status. Both
    also meet the requirements of a response that starts the Capsule Protocol (RFC 9297 sec. 3.2
    paragraph 16): no Content-Length, Content-Type or Transfer-Encoding, and none of 204, 205
    or 206. Header names are matched case-insensitively. A client that gets a refusal MUST abort.
    """
    fields = [(name.lower(), value.strip()) for name, value in headers]
    if http_version == "1.1":
        if status != 101:
            raise TunnelRefused(f"status {status} is not 101 Switching Protocols")
        options = {
            option.strip().lower()
            for name, value in fields
            if name == "connection"
            for option in value.split(",")
        }
        if "upgrade" not in options:
            raise TunnelRefused("the response has no Connection: Upgrade")
        upgrades = [value for name, value in fields if name == "upgrade"]
        if len(upgrades) != 1 or upgrades[0].lower() != "connect-udp":
            raise TunnelRefused("the response needs exactly one Upgrade: connect-udp")
    elif http_version in ("2", "3"):
        if not 200 <= status <= 299:
            raise TunnelRefused(f"status {status} is not a 2xx")
    else:
        raise ValueError(f"unsupported HTTP version {http_version!r}")
    if status in (204, 205, 206):
        raise TunnelRefused(f"status {status} must not be used with the Capsule Protocol")
    for name, _ in fields:
        if name in _FORBIDDEN_RESPONSE_FIELDS:
            raise TunnelRefused(f"{name} must not appear on a response using the Capsule Protocol")
