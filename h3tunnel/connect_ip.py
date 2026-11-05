"""CONNECT-IP URI template and IP packet framing (RFC 9484).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

__all__ = [
    "target_uri",
]


def target_uri(target: str | None, ipproto: str | None) -> str:
    """Pending behaviour defined by RFC 9484 sec. 4.6.

    Not implemented yet. See the ``connect_ip.target_uri()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("target_uri() is not implemented: RFC 9484 sec. 4.6")
