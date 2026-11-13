"""context identifier allocation (RFC 9298 sec. 4)."""

from __future__ import annotations

from typing import Literal

from .errors import ContextError
from .varint import MAX_VARINT

__all__ = [
    "ContextAllocator",
    "allocate_context",
]


class ContextAllocator:
    """Hands out Context IDs for one HTTP request (RFC 9298 sec. 4 paragraph 2).

    Context ID 0 is reserved for UDP payloads. Non-zero even IDs are allocated by the client
    and odd ones by the proxy, so the two ends never need to synchronise; an ID is never
    allocated twice in one request, in either direction. ``note_peer`` records an ID the peer
    allocated so that it is not reused. The parity restriction does not apply to *using* an ID
    once it has been allocated.
    """

    def __init__(self, role: Literal["client", "proxy"]) -> None:
        if role not in ("client", "proxy"):
            raise ValueError("role is 'client' or 'proxy'")
        self.role = role
        self._next = 2 if role == "client" else 1
        self._taken: set[int] = set()

    def allocate(self) -> int:
        """The next unused ID of the parity of this endpoint; raises at 2**62."""
        candidate = self._next
        while candidate in self._taken:
            candidate += 2
        if candidate > MAX_VARINT:
            raise ContextError("the Context ID space is exhausted")
        self._taken.add(candidate)
        self._next = candidate + 2
        return candidate

    def note_peer(self, context_id: int) -> None:
        """Record an ID in use that this endpoint did not allocate.

        Zero is reserved, and an ID that is already allocated cannot be allocated again.
        """
        if context_id == 0:
            raise ContextError("Context ID 0 is reserved for UDP payloads")
        if not 0 < context_id <= MAX_VARINT:
            raise ContextError(f"{context_id} is not a Context ID")
        if context_id in self._taken:
            raise ContextError(f"Context ID {context_id} is already allocated")
        self._taken.add(context_id)

    def is_allocated(self, context_id: int) -> bool:
        return context_id in self._taken


def allocate_context(tunnel: ContextAllocator) -> int:
    """Allocate the next Context ID for ``tunnel`` (RFC 9298 sec. 4)."""
    return tunnel.allocate()
