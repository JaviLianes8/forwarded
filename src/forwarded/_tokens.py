"""Token and quoted-string helpers shared by the parser and the builder (RFC 9110 5.6)."""

from __future__ import annotations

_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_TCHAR = frozenset("!#$%&'*+-.^_`|~0123456789" + _ALPHA)
OWS = " \t"


def is_token(value: str) -> bool:
    """Return whether ``value`` is a non-empty token that needs no quoting."""
    return bool(value) and all(char in _TCHAR for char in value)


def is_quotable(char: str) -> bool:
    """Return whether ``char`` can be carried inside a quoted-string.

    That is HTAB, SP, VCHAR and obs-text (``%x80-FF``); double quote and backslash need a
    quoted-pair but are still allowed.
    """
    code = ord(char)
    return code == 0x09 or 0x20 <= code <= 0x7E or 0x80 <= code <= 0xFF


def is_qdtext(char: str) -> bool:
    """Return whether ``char`` may appear unescaped inside a quoted-string."""
    return is_quotable(char) and char not in '"\\'


def quote(value: str) -> str:
    """Wrap ``value`` in a quoted-string, escaping backslash and double quote."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def quote_if_needed(value: str) -> str:
    """Return ``value`` as a bare token when possible, otherwise as a quoted-string."""
    return value if is_token(value) else quote(value)
