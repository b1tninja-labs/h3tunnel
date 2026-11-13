"""capsule framing and the registered capsule types (RFC 9297 sec. 3).

``Capsule { Type (i), Length (i), Value (..) }`` (sec. 3.2). The codec returns every capsule it
frames, unknown types included: sec. 3.2 paragraph 11 makes silently dropping an unknown type the
*receiver's* duty, and an intermediary SHOULD forward it unchanged (paragraph 10), so the policy
belongs to the caller. The codec's own duties are sec. 3.3 (an error is a malformed or incomplete
message, a truncated last capsule at a clean end of stream included) and sec. 3.2 paragraph 17 and
3.5 paragraph 9 (do not accumulate a huge value before handling it).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from .errors import CapsuleTooLarge, Incomplete, MalformedCapsule
from .varint import decode_varint, encode_varint

__all__ = [
    "DATAGRAM",
    "Capsule",
    "CapsuleParser",
    "decode_capsule",
    "encode_capsule",
    "parse_capsule_protocol_header",
]

DATAGRAM = 0x00
DEFAULT_MAX_VALUE_LENGTH = 65_535


@dataclass(frozen=True)
class Capsule:
    """One framed capsule: its type and its value octets."""

    type: int
    value: bytes


def encode_capsule(capsule_type: int, body: bytes) -> bytes:
    """Frame a capsule: Type, Length and Value (RFC 9297 sec. 3.2).

    The Length is that of ``body``; zero is allowed. Types and lengths use the shortest
    variable-length form.
    """
    return encode_varint(capsule_type) + encode_varint(len(body)) + bytes(body)


def decode_capsule(payload: bytes | bytearray | memoryview) -> tuple[Capsule, int]:
    """Read one capsule from the front of ``payload``; returns ``(capsule, bytes_consumed)``.

    RFC 9297 sec. 3.2. Raises :class:`~h3tunnel.errors.Incomplete` when the capsule is not
    all there yet. Use :class:`CapsuleParser` for a stream.
    """
    capsule_type, pos = decode_varint(payload, 0)
    length, pos = decode_varint(payload, pos)
    end = pos + length
    if end > len(payload):
        raise Incomplete(f"capsule value needs {length} bytes, {len(payload) - pos} available")
    return Capsule(capsule_type, bytes(payload[pos:end])), end


class CapsuleParser:
    """Incremental parser for the data stream of a request that uses the Capsule Protocol.

    ``feed`` takes bytes as they arrive and returns the capsules completed by them.
    A declared value longer than ``max_value_length`` raises :class:`CapsuleTooLarge` as soon as
    the header is read, before any of the value is buffered (RFC 9297 sec. 3.2 paragraph 17,
    sec. 3.5 paragraph 9). ``finish`` is called at a clean end of stream and raises
    :class:`MalformedCapsule` if a capsule was left truncated (sec. 3.3 paragraph 3).
    """

    def __init__(self, max_value_length: int = DEFAULT_MAX_VALUE_LENGTH) -> None:
        if max_value_length < 0:
            raise ValueError("max_value_length must not be negative")
        self.max_value_length = max_value_length
        self._buffer = bytearray()
        self._pending: tuple[int, int] | None = None  # (type, length) once the header is read

    @property
    def buffered(self) -> int:
        """How many bytes are held back waiting for the rest of a capsule."""
        return len(self._buffer)

    def feed(self, data: bytes | bytearray | memoryview) -> list[Capsule]:
        self._buffer += data
        out: list[Capsule] = []
        while True:
            if self._pending is None:
                try:
                    capsule_type, pos = decode_varint(self._buffer, 0)
                    length, pos = decode_varint(self._buffer, pos)
                except Incomplete:
                    return out
                if length > self.max_value_length:
                    raise CapsuleTooLarge(
                        f"capsule {capsule_type:#x} declares {length} value bytes, "
                        f"more than the limit of {self.max_value_length}"
                    )
                del self._buffer[:pos]
                self._pending = (capsule_type, length)
            capsule_type, length = self._pending
            if len(self._buffer) < length:
                return out
            out.append(Capsule(capsule_type, bytes(self._buffer[:length])))
            del self._buffer[:length]
            self._pending = None

    def finish(self) -> None:
        """The stream ended cleanly: anything still buffered is a truncated capsule."""
        if self._pending is not None or self._buffer:
            raise MalformedCapsule("the stream ended inside a capsule")


def parse_capsule_protocol_header(lines: str | bytes | Iterable[str]) -> bool:
    """Is the Capsule Protocol in use according to the Capsule-Protocol header (RFC 9297 sec. 3.4)?

    ``lines`` is the field value, or every field line of that name. The field is an Item
    Structured Field (RFC 9651) whose value MUST be a Boolean; anything else, including a field
    that fails to parse or one that was sent several times (which makes it a List), is handled
    as if the field were not present. Parameters are ignored. An absent field is ``False``,
    as is ``?0``.
    """
    sfields = _sfields()
    if isinstance(lines, str | bytes):
        raw: str | bytes | Iterable[str] = lines
    else:
        raw = list(lines)
        if not raw:
            return False
    try:
        item = sfields.parse_field(raw, "item")
    except sfields.ParseError:
        return False
    value = item.value
    return isinstance(value, sfields.model.Boolean) and value.value


def _sfields():
    """The sibling ``sfields`` project, by path in development (see pyproject.toml)."""
    try:
        import sfields
    except ImportError as error:  # pragma: no cover - the sibling is on the test path
        raise ImportError(
            "h3tunnel reads the Capsule-Protocol header with sfields (RFC 9651); "
            "put ../sfields on the path"
        ) from error
    return sfields
