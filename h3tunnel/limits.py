"""MTU, ECN and optimistic-send rules (RFC 9298 sec. 6, RFC 9931 sec. 6.3).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

__all__ = [
    "clamp_payload",
]


def clamp_payload(mtu: int, tunnel_overhead: int) -> int:
    """Pending behaviour defined by RFC 9298 sec. 6.1.

    Not implemented yet. See the ``limits.clamp_payload()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("clamp_payload() is not implemented: RFC 9298 sec. 6.1")
