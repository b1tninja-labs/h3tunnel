"""The UDP proxy's own rules, sans-IO (RFC 9298 sec. 3.1).

The state machine here owns what RFC 9298 sec. 3.1 asks of the proxy that opens the UDP socket,
and does no I/O: the caller resolves names, owns the socket and the clock and feeds the results in.
Each rule is pinned by a test in ``tests/test_proxy_rules.py``.

* **DNS before the reply** (para 3): when ``target_host`` is a name, the proxy MUST resolve it
  before it answers the HTTP request, and MUST reject the request if resolution fails.
  :func:`plan_target` says whether resolution is needed; :func:`reject_dns_error` and
  :func:`reject_dns_timeout` build the rejection with a ``Proxy-Status`` field (RFC 9209
  sec. 2.3.2 and sec. 2.3.1: ``dns_error`` with 502, ``dns_timeout`` with 504, the recommended
  status codes). An address the operator prohibits is rejected the same way
  (:func:`reject_prohibited`, ``destination_ip_prohibited``, 502).
* **Source validation** (para 4): with a non-connected socket the proxy MUST check the source
  address and port of every received packet against the request, and MUST discard the rest.
  :meth:`ProxySession.on_target_packet`. An IPv4-mapped IPv6 source (``::ffff:a.b.c.d``) is
  compared as the IPv4 address it carries, because a dual-stack socket reports it that way; that
  mapping is this library's reading, not the RFC's.
* **Socket lifetime** (para 5): the socket lives as long as the request stream. A socket error
  (the ICMP Destination Unreachable case) closes the stream (:meth:`ProxySession.on_socket_error`),
  and so does an idle close; the idle period SHOULD NOT be under two minutes, so a shorter one
  needs ``allow_short_idle=True`` and the default is exactly two minutes.
* **No fragmentation** (para 7): an HTTP Datagram that would not fit one IP packet at the path MTU
  is silently dropped, never fragmented (:meth:`ProxySession.on_client_datagram`); the Don't
  Fragment bit is to be set on IPv4 "if possible" (:attr:`ProxySession.set_df`).
* The payload cap of 65527 octets (sec. 5 para 6) is :mod:`h3tunnel.limits`.

Idle time counts packets in both directions: a proxy that only counted one direction would close a
socket that is in use.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .limits import MAX_UDP_PAYLOAD

if TYPE_CHECKING:
    from sfields.model import BareItem

__all__ = [
    "MIN_IDLE_SECONDS",
    "CloseStream",
    "Discard",
    "Forward",
    "NeedResolution",
    "ProxySession",
    "Rejection",
    "Target",
    "plan_target",
    "proxy_status",
    "reject_dns_error",
    "reject_dns_timeout",
    "reject_prohibited",
]

MIN_IDLE_SECONDS = (
    120.0  # RFC 9298 sec. 3.1 para 5: "SHOULD NOT use a period lower than two minutes"
)
_IPV4_HEADER = 20  # no options: the smallest header, so the largest payload that can fit
_IPV6_HEADER = 40
_UDP_HEADER = 8


@dataclass(frozen=True)
class Target:
    """The address the UDP socket is opened to."""

    address: str
    port: int

    @property
    def version(self) -> int:
        return ipaddress.ip_address(self.address).version


@dataclass(frozen=True)
class NeedResolution:
    """``host`` is a name: resolve it, and only then answer the request (sec. 3.1 para 3)."""

    host: str
    port: int


@dataclass(frozen=True)
class Rejection:
    """Answer the request with ``status`` and the ``Proxy-Status`` field value, then stop."""

    status: int
    proxy_status: str


@dataclass(frozen=True)
class Forward:
    """Hand ``payload`` to the other side: the UDP socket, or the client."""

    payload: bytes


@dataclass(frozen=True)
class Discard:
    """Silently drop the packet; ``reason`` is for logs and counters, never for the peer."""

    reason: str


@dataclass(frozen=True)
class CloseStream:
    """Close the socket and the request stream together (sec. 3.1 para 5)."""

    reason: str


def _sf():
    """The sibling ``sfields`` project, by path in development (see pyproject.toml)."""
    try:
        import sfields
        from sfields import model, serialize
    except ImportError as error:  # pragma: no cover - the sibling is on the test path
        raise ImportError(
            "h3tunnel serialises Proxy-Status with sfields (RFC 9651); put ../sfields on the path"
        ) from error
    return sfields, model, serialize


def proxy_status(
    identity: str, error: str, *, rcode: str | None = None, info_code: int | None = None
) -> str:
    """A ``Proxy-Status`` field value ``identity; error=TYPE[; rcode="..."][; info-code=N]``.

    RFC 9209 sec. 2: a List member that is a Token or String, with the ``error`` parameter a
    Token (sec. 2.1.1) and, for ``dns_error``, the String ``rcode`` and Integer ``info-code``
    (sec. 2.3.2). Serialization is RFC 9651 sec. 4, done by :mod:`sfields`; a Token identity stays
    bare and anything else becomes a String.
    """
    sfields, model, serialize = _sf()
    if not identity:
        raise ValueError("the proxy identity must not be empty")
    if not identity.isascii() or any(ord(c) < 0x20 or ord(c) == 0x7F for c in identity):
        raise ValueError("the proxy identity must be printable ASCII")
    try:
        name: BareItem = model.Token(identity)
        serialize.serialize_bare_item(name)
    except sfields.SerializeError:
        name = model.String(identity)
    params: list[tuple[str, BareItem]] = []
    try:
        error_token = model.Token(error)
        serialize.serialize_bare_item(error_token)
    except sfields.SerializeError as exc:
        raise ValueError("the error parameter is a Token") from exc
    params.append(("error", error_token))
    if rcode is not None:
        params.append(("rcode", model.String(rcode)))
    if info_code is not None:
        params.append(("info-code", model.Integer(int(info_code))))
    try:
        return serialize.serialize_item(model.Item(name, model.Params(params)))
    except sfields.SerializeError as exc:
        raise ValueError(str(exc)) from exc


def reject_dns_error(
    identity: str, *, rcode: str = "SERVFAIL", info_code: int | None = None
) -> Rejection:
    """RFC 9209 sec. 2.3.2: the resolver answered with an error; recommended status 502."""
    return Rejection(502, proxy_status(identity, "dns_error", rcode=rcode, info_code=info_code))


def reject_dns_timeout(identity: str) -> Rejection:
    """RFC 9209 sec. 2.3.1: the resolver did not answer in time; recommended status 504."""
    return Rejection(504, proxy_status(identity, "dns_timeout"))


def reject_prohibited(identity: str) -> Rejection:
    """RFC 9209 sec. 2.3.5: the operator forbids that address; recommended status 502."""
    return Rejection(502, proxy_status(identity, "destination_ip_prohibited"))


def plan_target(target_host: str, target_port: int) -> Target | NeedResolution:
    """Decide whether the request can be answered now or only after a name lookup.

    An IP literal is a :class:`Target` at once. A name is a :class:`NeedResolution`: the caller
    resolves it, picks an address, and builds a :class:`Target` from it (sec. 3.1 para 3). The
    variables are those of ``connect_udp.validate_target``, already percent-decoded.
    """
    if not target_host:
        raise ValueError("target_host must not be empty")
    if type(target_port) is not int or not 1 <= target_port <= 65535:
        raise ValueError(f"target_port {target_port!r} is not an integer from 1 to 65535")
    try:
        address = ipaddress.ip_address(target_host)
    except ValueError:
        return NeedResolution(target_host, target_port)
    return Target(str(address), target_port)


def _normal(address: str) -> str:
    parsed = ipaddress.ip_address(address)
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        return str(parsed.ipv4_mapped)
    return str(parsed)


class ProxySession:
    """One proxied stream: a target, a clock for idleness and the rules above, with no I/O.

    ``connected`` says the socket is a connected UDP socket, so the kernel already filters by
    5-tuple and the proxy need not (sec. 3.1 para 4); by default it is not and every packet is
    checked. ``path_mtu`` is the IP MTU toward the target, and a datagram too big for it is
    dropped. Time is the ``now`` the caller passes.
    """

    def __init__(
        self,
        target: Target,
        *,
        now: float,
        path_mtu: int = 1280,
        connected: bool = False,
        idle_timeout: float = MIN_IDLE_SECONDS,
        allow_short_idle: bool = False,
    ) -> None:
        if idle_timeout < MIN_IDLE_SECONDS and not allow_short_idle:
            raise ValueError(
                "an idle period under two minutes needs allow_short_idle=True "
                "(RFC 9298 sec. 3.1 para 5: SHOULD NOT)"
            )
        if idle_timeout <= 0:
            raise ValueError("idle_timeout must be positive")
        if path_mtu < 68:
            raise ValueError("path_mtu is below the smallest IPv4 datagram")
        self.target = target
        self.path_mtu = path_mtu
        self.connected = connected
        self.idle_timeout = idle_timeout
        self._last_activity = now
        self.closed = False
        self.dropped_source = 0
        self.dropped_oversize = 0

    @property
    def set_df(self) -> bool:
        """Set Don't Fragment on the socket "if possible" for IPv4 targets (sec. 3.1 para 7)."""
        return self.target.version == 4

    @property
    def max_payload(self) -> int:
        """The largest UDP payload that fits one IP packet at ``path_mtu``, never over 65527."""
        header = _IPV4_HEADER if self.target.version == 4 else _IPV6_HEADER
        return max(0, min(MAX_UDP_PAYLOAD, self.path_mtu - header - _UDP_HEADER))

    def on_client_datagram(self, payload: bytes, now: float) -> Forward | Discard | CloseStream:
        """A UDP payload from the client, bound for the target.

        Dropped, silently, when it would need IP fragmentation (para 7); a payload over 65527
        octets is the caller's abort case (:func:`h3tunnel.limits.check_udp_payload`).
        """
        if self.closed:
            return Discard("the stream is closed")
        if len(payload) > self.max_payload:
            self.dropped_oversize += 1
            return Discard("would need IP fragmentation")
        self._last_activity = now
        return Forward(payload)

    def on_target_packet(
        self, source_address: str, source_port: int, payload: bytes, now: float
    ) -> Forward | Discard | CloseStream:
        """A UDP packet that arrived on the socket: forward it only if it came from the target."""
        if self.closed:
            return Discard("the stream is closed")
        if not self.connected:
            try:
                same = _normal(source_address) == _normal(self.target.address)
            except ValueError:
                same = False
            if not same or source_port != self.target.port:
                self.dropped_source += 1
                return Discard("source address or port does not match the request")
        self._last_activity = now
        return Forward(payload)

    def on_socket_error(self) -> CloseStream:
        """The OS says the socket is unusable (ICMP Destination Unreachable): close the stream."""
        self.closed = True
        return CloseStream("the UDP socket is no longer usable")

    def tick(self, now: float) -> CloseStream | None:
        """Close both the socket and the stream once idle for ``idle_timeout`` (sec. 3.1 para 5)."""
        if not self.closed and now - self._last_activity >= self.idle_timeout:
            self.closed = True
            return CloseStream("idle timeout")
        return None

    def on_stream_closed(self) -> None:
        """The request stream ended: the socket's life ends with it."""
        self.closed = True
