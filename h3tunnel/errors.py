"""exceptions for the wire codecs and the request builders.

Each says which obligation it enforces, because the caller's reaction differs: RFC 9297 sec. 3.3
requires a malformed capsule to be treated as a malformed or incomplete HTTP message, while an
HTTP/3 datagram error is a connection error with a code (RFC 9297 sec. 2.1).
"""

from __future__ import annotations

__all__ = [
    "CapsuleTooLarge",
    "ConnectionErrorH3",
    "ContextError",
    "H3DatagramError",
    "H3SettingsError",
    "Incomplete",
    "MalformedCapsule",
    "PayloadTooLarge",
    "TemplateError",
    "TunnelRefused",
]

H3_DATAGRAM_ERROR = 0x33
H3_SETTINGS_ERROR = 0x109


class Incomplete(ValueError):
    """The buffer ends inside a value: more bytes are needed, nothing was consumed."""


class MalformedCapsule(ValueError):
    """RFC 9297 sec. 3.3: treat the message as malformed or incomplete."""


class CapsuleTooLarge(MalformedCapsule):
    """A capsule declared a value longer than the parser's limit (RFC 9297 sec. 3.5 paragraph 9)."""


class ConnectionErrorH3(ValueError):
    """An HTTP/3 connection error: ``error_code`` is the code to close the connection with."""

    error_code: int = 0

    def __init__(self, message: str, error_code: int | None = None) -> None:
        super().__init__(message)
        if error_code is not None:
            self.error_code = error_code


class H3DatagramError(ConnectionErrorH3):
    """H3_DATAGRAM_ERROR (0x33), RFC 9297 sec. 2.1 paragraphs 4 and 6."""

    error_code = H3_DATAGRAM_ERROR


class H3SettingsError(ConnectionErrorH3):
    """A SETTINGS_H3_DATAGRAM value that RFC 9297 sec. 2.1.1 requires the connection to refuse."""


class PayloadTooLarge(ValueError):
    """A UDP Proxying Payload longer than 65527 octets on Context ID zero (RFC 9298 sec. 5)."""


class ContextError(ValueError):
    """A Context ID that cannot be allocated or has been allocated already (RFC 9298 sec. 4)."""


class TemplateError(ValueError):
    """A URI Template the client must reject without sending anything (RFC 9298 sec. 2)."""


class TunnelRefused(ValueError):
    """The response does not establish the tunnel; the client MUST abort (RFC 9298 sec. 3.3, 3.5)."""
