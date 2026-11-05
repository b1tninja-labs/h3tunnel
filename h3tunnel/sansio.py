"""transport-neutral tunnel state machine.

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

__all__ = [
    "on_datagram",
]


def on_datagram(data: bytes, now: float) -> list:
    """Pending behaviour defined by RFC 9298.

    Not implemented yet. See the ``sansio.on_datagram()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("on_datagram() is not implemented: RFC 9298")
