"""capsule framing and the registered capsule types (RFC 9297).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    Capsule = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "decode_capsule",
    "encode_capsule",
]


def encode_capsule(capsule_type: int, body: bytes) -> Capsule:
    """Pending behaviour defined by RFC 9297 sec. 3.2.

    Not implemented yet. See the ``capsule.encode_capsule()`` row in ROADMAP.md; this
    stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("encode_capsule() is not implemented: RFC 9297 sec. 3.2")


def decode_capsule(payload: bytes) -> tuple:
    """Pending behaviour defined by RFC 9297 sec. 3.2.

    Not implemented yet. See the ``capsule.decode_capsule()`` row in ROADMAP.md; this
    stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("decode_capsule() is not implemented: RFC 9297 sec. 3.2")
