"""The URI Template subset that CONNECT-UDP and CONNECT-IP allow (RFC 9298 sec. 2, RFC 9484 sec. 3).

Not a general RFC 6570 engine. RFC 9298 sec. 2 and RFC 9484 sec. 3 require a template of level 3 or
lower that avoids five operators, so what is left is simple string expansion ``{a,b}`` and the
form-style operators ``{?a,b}`` and ``{&a,b}``. Everything else is refused when the template is
parsed, because the RFCs say a client MUST reject such a configuration and abort without
sending the request.

Syntax follows RFC 6570 sec. 2 (literals as corrected by verified erratum 6937, which also admits
the apostrophe, and expressions), expansion follows sec. 3.2.1, 3.2.2, 3.2.8 and 3.2.9: only the
unreserved characters of RFC 3986 pass through a value unencoded, so ``:`` becomes ``%3A``,
``/`` becomes ``%2F`` and ``*`` becomes ``%2A``.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

from .errors import TemplateError

__all__ = [
    "Expression",
    "Template",
    "parse_template",
    "validate_absolute",
]

_ALPHA = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
_DIGIT = frozenset("0123456789")
_HEX = frozenset("0123456789abcdefABCDEF")
UNRESERVED = _ALPHA | _DIGIT | frozenset("-._~")
# RFC 6570 sec. 2.1 as corrected by erratum 6937, limited to ASCII 0x21-0x7E (RFC 9298 sec. 2):
# every printable ASCII character except DQUOTE, "%" (except in a triplet), "<", ">", "\", "^",
# "`", "{", "|", "}".
_LITERAL = frozenset(chr(c) for c in range(0x21, 0x7F)) - frozenset('"%<>\\^`{|}')
_URL = re.compile(r"([A-Za-z][A-Za-z0-9+.\-]*)://([^/?#]*)(.*)", re.DOTALL)
_FORBIDDEN_OPERATORS = {
    "+": "reserved expansion",
    "#": "fragment expansion",
    ".": "label expansion",
    "/": "path segment expansion",
    ";": "path-style parameter expansion",
}
_RESERVED_OPERATORS = frozenset("=,!@|")  # RFC 6570 sec. 2.2 paragraph 11


@dataclass(frozen=True)
class Expression:
    """``{operator variable-list}``: ``operator`` is "", "?" or "&"."""

    operator: str
    variables: tuple[str, ...]


@dataclass(frozen=True)
class Template:
    """A parsed template: literal strings and expressions in order."""

    parts: tuple[str | Expression, ...]

    @property
    def variables(self) -> tuple[str, ...]:
        return tuple(
            v for part in self.parts if isinstance(part, Expression) for v in part.variables
        )

    def expand(self, values: Mapping[str, str]) -> str:
        """Expand with string values (RFC 6570 sec. 3.2). A variable not in ``values`` is undefined."""
        out: list[str] = []
        for part in self.parts:
            if isinstance(part, str):
                out.append(part)
            else:
                out.append(_expand(part, values))
        return "".join(out)


def encode_value(value: str) -> str:
    """Percent-encode everything outside the unreserved set, as UTF-8 (RFC 6570 sec. 3.2.1 paragraph 2)."""
    return "".join(
        c if c in UNRESERVED else "".join(f"%{b:02X}" for b in c.encode("utf-8")) for c in value
    )


def _expand(expression: Expression, values: Mapping[str, str]) -> str:
    defined = [(name, values[name]) for name in expression.variables if name in values]
    if not defined:
        return ""
    if expression.operator == "":
        return ",".join(encode_value(value) for _, value in defined)
    first = "?" if expression.operator == "?" else "&"
    pairs = [f"{name}={encode_value(value)}" for name, value in defined]
    return first + "&".join(pairs)


def _check_varname(name: str, where: int) -> None:
    i = 0
    previous_dot = True  # a name cannot start with "."
    while i < len(name):
        c = name[i]
        if c == "%":
            triplet = name[i + 1 : i + 3]
            if len(triplet) < 2 or not set(triplet) <= _HEX:
                raise TemplateError(f"bad percent-encoding in variable name at offset {where}")
            i += 3
            previous_dot = False
        elif c in _ALPHA or c in _DIGIT or c == "_":
            i += 1
            previous_dot = False
        elif c == "." and not previous_dot:
            i += 1
            previous_dot = True
        else:
            raise TemplateError(
                f"character {c!r} is not allowed in a variable name (offset {where})"
            )
    if previous_dot:
        raise TemplateError(f"empty or dot-terminated variable name at offset {where}")


def parse_template(template: str) -> Template:
    """Parse and validate ``template`` against the subset above.

    Refuses: any character outside 0x21-0x7E (RFC 9298 sec. 2 paragraph 10); the operators
    ``+ # . / ;`` (paragraph 11); the operators reserved for future extensions
    (RFC 6570 sec. 2.2); value modifiers ``:n`` and ``*``, which are level 4 (paragraph 5);
    unbalanced braces; an empty expression or variable name; a ``%`` that is not a triplet.
    """
    parts: list[str | Expression] = []
    literal: list[str] = []
    i = 0
    n = len(template)
    while i < n:
        c = template[i]
        if c == "{":
            end = template.find("}", i + 1)
            if end < 0:
                raise TemplateError(f"unclosed expression at offset {i}")
            if literal:
                parts.append("".join(literal))
                literal = []
            parts.append(_parse_expression(template[i + 1 : end], i))
            i = end + 1
        elif c == "%":
            triplet = template[i + 1 : i + 3]
            if len(triplet) < 2 or not set(triplet) <= _HEX:
                raise TemplateError(
                    f"a percent sign must start a percent-encoded triplet (offset {i})"
                )
            literal.append(template[i : i + 3])
            i += 3
        elif c in _LITERAL:
            literal.append(c)
            i += 1
        else:
            raise TemplateError(f"character {c!r} is not allowed in a template (offset {i})")
    if literal:
        parts.append("".join(literal))
    return Template(tuple(parts))


def _parse_expression(body: str, at: int) -> Expression:
    if not body:
        raise TemplateError(f"empty expression at offset {at}")
    operator = ""
    if body[0] in _FORBIDDEN_OPERATORS:
        raise TemplateError(
            f"{_FORBIDDEN_OPERATORS[body[0]]} ({body[0]!r}) is not allowed (offset {at})"
        )
    if body[0] in _RESERVED_OPERATORS:
        raise TemplateError(f"operator {body[0]!r} is reserved by RFC 6570 (offset {at})")
    if body[0] in "?&":
        operator, body = body[0], body[1:]
    names = body.split(",")
    for name in names:
        if name.endswith("*") or ":" in name:
            raise TemplateError(f"value modifiers are level 4 and not allowed (offset {at})")
        if not name:
            raise TemplateError(f"empty variable name at offset {at}")
        _check_varname(name, at)
    return Expression(operator, tuple(names))


def validate_absolute(template: str) -> Template:
    """Parse ``template`` and check the shape both MASQUE RFCs demand of it.

    RFC 9298 sec. 2 paragraphs 6 to 8 and RFC 9484 sec. 3 paragraphs 7 to 9: absolute form with a
    non-empty scheme, authority and path; the path starts with a slash; every variable is in the
    path or query (not the authority, not a fragment). The syntax limits are those of
    :func:`parse_template`.
    """
    parsed = parse_template(template)
    match = _URL.fullmatch(template)
    if match is None:
        raise TemplateError("the template must be absolute: scheme://authority/path")
    authority, rest = match.group(2), match.group(3)
    if not authority:
        raise TemplateError("the template has an empty authority")
    if "{" in authority:
        raise TemplateError("template variables must be in the path or query, not the authority")
    if not rest.startswith("/"):
        raise TemplateError("the path of the template must start with a slash")
    if "#" in rest and "{" in rest[rest.index("#") :]:
        raise TemplateError("template variables must be in the path or query, not a fragment")
    return parsed
