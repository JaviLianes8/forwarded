"""Token and quoted-string helpers shared by the parser and the builder (RFC 7230)."""

from __future__ import annotations

_TCHAR = frozenset("!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")


def is_token(value: str) -> bool:
    """Return whether ``value`` is a non-empty token that needs no quoting."""
    return bool(value) and all(char in _TCHAR for char in value)


def quote(value: str) -> str:
    """Wrap ``value`` in a quoted-string, escaping backslash and double quote."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def quote_if_needed(value: str) -> str:
    """Return ``value`` as a bare token when possible, otherwise as a quoted-string."""
    return value if is_token(value) else quote(value)


def unquote(value: str) -> str:
    """Strip surrounding quotes from a quoted-string and undo its escaping."""
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return _unescape(value[1:-1])
    return value


def _unescape(text: str) -> str:
    out: list[str] = []
    escaped = False
    for char in text:
        if escaped:
            out.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        else:
            out.append(char)
    if escaped:
        out.append("\\")
    return "".join(out)
