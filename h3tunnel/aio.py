"""asyncio client for CONNECT-UDP over HTTP/1.1 Upgrade (RFC 9298 sec. 3.2, sec. 3.3), standard library only.

``open_udp_tunnel`` connects with ``ssl``, sends the Upgrade request of
:func:`h3tunnel.connect_udp.build_request`, checks the 101 response with
:func:`~h3tunnel.connect_udp.check_response`, and then carries UDP payloads as DATAGRAM capsules
(RFC 9297 sec. 3.5) in the Capsule Protocol on the upgraded connection. Received datagrams go
through :class:`h3tunnel.sansio.Tunnel`, so the Context ID rules, the 65527-octet limit and the
buffering limits are the machine's.

HTTP/1.1 is the only transport built here. QUIC and HTTP/3 are ``[no]``: neither the standard
library nor ``cryptography`` carries a QUIC stack. Because the client is on HTTP/1.1,
``optimistic_send_allowed("1.1")`` is False (RFC 9931 sec. 6.3) and nothing is sent before the 101.

Policies, each pinned by a test in ``tests/test_aio.py``:

* The response header is read up to 16384 octets; more is refused. Obsolete line folding and a
  response header without the blank line are refused.
* Any capsule type but DATAGRAM is skipped silently (RFC 9297 sec. 3.2 para 11); a capsule whose
  value is over 65535 octets raises, before it is buffered (the parser's cap).
* A Context ID other than zero is not registered by this client, so such a datagram is buffered
  briefly and then dropped by the machine.
* ``serve_proxy`` is still a loud stub (M4).
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
from collections import deque
from typing import TYPE_CHECKING

from .capsule import DATAGRAM, CapsuleParser, encode_capsule
from .connect_udp import build_request, check_response, default_template, serialize_http11
from .errors import TunnelRefused
from .httpdatagram import encode_datagram
from .sansio import Abort, Deliver, Tunnel

if TYPE_CHECKING:
    from typing import Any

    ProxyPolicy = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "UdpTunnel",
    "open_udp_tunnel",
    "serve_proxy",
]

_MAX_RESPONSE_HEADER = 16384


class UdpTunnel:
    """An established CONNECT-UDP tunnel: ``send`` a UDP payload, ``recv`` the next one."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        first: bytes = b"",
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._parser = CapsuleParser()
        self._tunnel = Tunnel("client")
        self._ready: deque[bytes] = deque()
        self._pending = first
        self._closed = False

    async def send(self, payload: bytes) -> None:
        """Send one UDP payload as a DATAGRAM capsule on Context ID zero (RFC 9298 sec. 5)."""
        if self._closed:
            raise ConnectionError("the tunnel is closed")
        datagram = encode_datagram(0, payload)  # refuses more than 65527 octets
        self._writer.write(encode_capsule(DATAGRAM, datagram))
        await self._writer.drain()

    def _absorb(self, data: bytes) -> None:
        now = asyncio.get_running_loop().time()
        for capsule in self._parser.feed(data):
            if capsule.type != DATAGRAM:
                continue  # RFC 9297 sec. 3.2 para 11: unknown capsule types are dropped
            for event in self._tunnel.on_datagram(capsule.value, now):
                if isinstance(event, Abort):
                    raise ConnectionError(f"tunnel aborted: {event.reason}")
                if isinstance(event, Deliver):
                    self._ready.append(event.payload)

    async def recv(self) -> bytes | None:
        """The next UDP payload, or ``None`` when the proxy closed the tunnel cleanly."""
        if self._pending:
            data, self._pending = self._pending, b""
            self._absorb(data)
        while not self._ready:
            data = await self._reader.read(65536)
            if not data:
                self._parser.finish()  # a truncated capsule at the end is an error
                self._closed = True
                return None
            self._absorb(data)
        return self._ready.popleft()

    async def close(self) -> None:
        """Close the connection."""
        self._closed = True
        self._writer.close()
        with contextlib.suppress(ConnectionError, ssl.SSLError):
            await self._writer.wait_closed()


def _split_proxy(proxy: str) -> tuple[str, int]:
    host, sep, port = proxy.rpartition(":")
    if not sep or not host or not port.isdigit():
        return proxy, 443
    return host, int(port)


def _parse_head(head: bytes) -> tuple[int, list[tuple[str, str]]]:
    lines = head.decode("iso-8859-1").split("\r\n")
    parts = lines[0].split(" ", 2)
    if len(parts) < 2 or parts[0] != "HTTP/1.1" or not parts[1].isdigit() or len(parts[1]) != 3:
        raise TunnelRefused("the response is not an HTTP/1.1 status line")
    fields: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line:
            continue
        if line[0] in " \t":
            raise TunnelRefused("obsolete line folding in the response")
        name, sep, value = line.partition(":")
        if not sep or not name or name != name.strip():
            raise TunnelRefused("a malformed header line in the response")
        fields.append((name, value.strip()))
    return int(parts[1]), fields


async def open_udp_tunnel(
    proxy: str,
    target: tuple[str, int],
    *,
    template: str | None = None,
    ssl_context: ssl.SSLContext | None = None,
    timeout: float = 10.0,
) -> UdpTunnel:
    """Open a CONNECT-UDP tunnel to ``target`` through ``proxy`` over HTTP/1.1 Upgrade (RFC 9298).

    ``proxy`` is ``host`` or ``host:port`` (port 443 by default); ``target`` is ``(host, port)``.
    ``template`` defaults to the well-known one of RFC 9298 sec. 2 para 13 for that proxy. The
    connection uses TLS with ``ssl_context`` or the default verifying context, and
    ``server_hostname`` is the proxy host. Raises :class:`~h3tunnel.errors.TunnelRefused` if the
    proxy does not answer 101 with the Upgrade headers, ``TimeoutError`` after ``timeout``.
    """
    host, port = _split_proxy(proxy)
    context = ssl_context or ssl.create_default_context()
    uri_template = template or default_template(host, port)
    request = build_request(uri_template, target[0], target[1], "1.1")

    async def establish() -> UdpTunnel:
        reader, writer = await asyncio.open_connection(
            host, port, ssl=context, server_hostname=host
        )
        try:
            writer.write(serialize_http11(request))
            await writer.drain()
            buffer = b""
            while b"\r\n\r\n" not in buffer:
                if len(buffer) > _MAX_RESPONSE_HEADER:
                    raise TunnelRefused("the response header is larger than 16384 octets")
                chunk = await reader.read(4096)
                if not chunk:
                    raise TunnelRefused("the connection closed before the response header ended")
                buffer += chunk
            head, _, rest = buffer.partition(b"\r\n\r\n")
            if len(head) > _MAX_RESPONSE_HEADER:
                raise TunnelRefused("the response header is larger than 16384 octets")
            status, fields = _parse_head(head)
            check_response("1.1", status, fields)
        except BaseException:
            writer.close()
            raise
        return UdpTunnel(reader, writer, rest)

    return await asyncio.wait_for(establish(), timeout)


async def serve_proxy(host: str, port: int, policy: ProxyPolicy) -> None:
    """Pending behaviour defined by RFC 9298 sec. 3.1.

    Not implemented yet. See the ``aio.serve_proxy()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("serve_proxy() is not implemented: RFC 9298 sec. 3.1")
