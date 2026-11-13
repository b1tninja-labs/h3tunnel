"""The transport-neutral state machine for received HTTP Datagrams (RFC 9298 sec. 5, RFC 9297 sec. 2.1).

``Tunnel`` owns what the RFCs leave to the receiver: which Context IDs are registered, and what to
do with a datagram that cannot be delivered yet. Time is the ``now`` the caller passes, so a test
runs a round trip in a loop. Every method returns events; none does I/O.

Reading of the RFC text, each point pinned by a test in ``tests/test_sansio.py``:

* RFC 9298 sec. 5 para 3 and para 6: a datagram with an unknown Context ID, or (for a proxy) one
  that arrives before the request, is either dropped silently or buffered "on the order of a round
  trip". This machine buffers for ``buffer_window`` seconds (default 1.0) and drops after that.
* Sec. 5 para 7: buffering "SHOULD" be limited. Both the datagram count (default 16) and the
  cumulative size (default 65536 octets) are bounded per tunnel; a datagram that does not fit is
  dropped (the newest, not the oldest: an attacker that fills the buffer cannot evict what is
  already waiting for a registration).
* Sec. 5 para 5: a Context ID zero payload longer than 65527 octets MUST abort the stream: an
  ``Abort`` event. Buffered datagrams are checked the same way when they are released.
* Context ID zero is always registered; it needs no registration (sec. 5 para 4).
* A datagram too short to hold its Context ID is not specified by RFC 9298; it is dropped as
  malformed. This is a policy of this library, not of the RFC.
* RFC 9297 sec. 2.1 para 5: a datagram that arrives after the stream's receive side closed is
  silently dropped (``close_receive``). Para 6 (a stream not created yet) is the proxy buffering
  above, ``mark_request_received`` releasing it.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from .errors import Incomplete, PayloadTooLarge
from .httpdatagram import decode_datagram
from .limits import check_udp_payload

__all__ = [
    "Abort",
    "Buffered",
    "Deliver",
    "Dropped",
    "Tunnel",
    "on_datagram",
]


@dataclass(frozen=True)
class Deliver:
    """Hand ``payload`` to the application (``context_id`` 0 is a UDP payload)."""

    context_id: int
    payload: bytes


@dataclass(frozen=True)
class Buffered:
    """The datagram waits for a registration or for the request."""

    context_id: int


@dataclass(frozen=True)
class Dropped:
    """The datagram was discarded; ``reason`` says why."""

    reason: str


@dataclass(frozen=True)
class Abort:
    """The stream must be aborted (RFC 9298 sec. 5 para 5)."""

    reason: str


Event = Deliver | Buffered | Dropped | Abort


class Tunnel:
    """Receive-side state of one CONNECT-UDP or CONNECT-IP request.

    ``role`` is "proxy" or "client". A proxy starts with ``request_received`` False and buffers
    datagrams until :meth:`mark_request_received`; a client starts with it True.
    """

    def __init__(
        self,
        role: str = "client",
        *,
        buffer_window: float = 1.0,
        max_buffered: int = 16,
        max_buffered_bytes: int = 65536,
        max_udp_payload: int | None = None,
    ) -> None:
        if role not in ("client", "proxy"):
            raise ValueError("role is 'client' or 'proxy'")
        if buffer_window < 0 or max_buffered < 0 or max_buffered_bytes < 0:
            raise ValueError("buffer limits must not be negative")
        self.role = role
        self.buffer_window = buffer_window
        self.max_buffered = max_buffered
        self.max_buffered_bytes = max_buffered_bytes
        self.request_received = role == "client"
        self.receive_open = True
        self._registered: set[int] = {0}
        self._buffer: deque[tuple[float, int, bytes]] = deque()
        self._buffered_bytes = 0
        self._udp_limit = max_udp_payload

    @property
    def buffered(self) -> int:
        """Datagrams waiting."""
        return len(self._buffer)

    def _expire(self, now: float) -> list[Event]:
        events: list[Event] = []
        while self._buffer and now - self._buffer[0][0] >= self.buffer_window:
            _, _, payload = self._buffer.popleft()
            self._buffered_bytes -= len(payload)
            events.append(Dropped("buffered datagram expired"))
        return events

    def _release(self, now: float) -> list[Event]:
        events = self._expire(now)
        if not self.request_received:
            return events
        keep: deque[tuple[float, int, bytes]] = deque()
        while self._buffer:
            arrived, context_id, payload = self._buffer.popleft()
            if context_id in self._registered:
                self._buffered_bytes -= len(payload)
                events.extend(self._deliver(context_id, payload))
            else:
                keep.append((arrived, context_id, payload))
        self._buffer = keep
        return events

    def _deliver(self, context_id: int, payload: bytes) -> list[Event]:
        if context_id == 0:
            try:
                check_udp_payload(payload, receiving=True)
            except PayloadTooLarge as error:
                return [Abort(str(error))]
            if self._udp_limit is not None and len(payload) > self._udp_limit:
                return [Dropped("larger than the link allows")]  # sec. 5 para 5: may discard
        return [Deliver(context_id, payload)]

    def _hold(self, now: float, context_id: int, payload: bytes) -> list[Event]:
        if (
            len(self._buffer) >= self.max_buffered
            or self._buffered_bytes + len(payload) > self.max_buffered_bytes
        ):
            return [Dropped("buffer full")]
        self._buffer.append((now, context_id, payload))
        self._buffered_bytes += len(payload)
        return [Buffered(context_id)]

    def register_context(self, context_id: int, now: float) -> list[Event]:
        """A Context ID was registered: release the datagrams that were waiting for it."""
        if context_id < 0:
            raise ValueError("a Context ID is not negative")
        self._registered.add(context_id)
        return self._release(now)

    def mark_request_received(self, now: float) -> list[Event]:
        """The proxy has the request: release what arrived before it (sec. 5 para 6)."""
        self.request_received = True
        return self._release(now)

    def close_receive(self) -> None:
        """The stream's receive side closed: later datagrams are dropped (RFC 9297 sec. 2.1 para 5)."""
        self.receive_open = False
        self._buffer.clear()
        self._buffered_bytes = 0

    def tick(self, now: float) -> list[Event]:
        """Expire buffered datagrams that waited a full window."""
        return self._expire(now)

    def on_datagram(self, data: bytes, now: float) -> list[Event]:
        """Process the HTTP Datagram Payload ``data`` received at ``now``."""
        events = self._expire(now)
        if not self.receive_open:
            return [*events, Dropped("receive side closed")]
        try:
            context_id, payload = decode_datagram(data)
        except Incomplete:
            return [*events, Dropped("datagram too short for a Context ID")]
        if not self.request_received or context_id not in self._registered:
            return [*events, *self._hold(now, context_id, payload)]
        return [*events, *self._deliver(context_id, payload)]


def on_datagram(tunnel: Tunnel, data: bytes, now: float) -> list[Event]:
    """Process one received HTTP Datagram Payload for ``tunnel`` (RFC 9298 sec. 5).

    Returns events: ``Deliver`` for a registered Context ID, ``Buffered`` or ``Dropped`` for an
    unknown one, ``Abort`` for a UDP payload over 65527 octets on Context ID zero.
    """
    return tunnel.on_datagram(data, now)
