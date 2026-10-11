"""Parse an HTTP Forwarded header into its elements (RFC 7239)."""

from __future__ import annotations

from ._tokens import unquote


def parse(header: str) -> list[dict[str, str]]:
    """Parse ``header`` into a list of elements, each a dict of lower-cased parameters.

    Comma-separated elements become separate dicts, in order. Parameter names are
    lower-cased because they are case-insensitive, and values are unquoted (so a
    quoted IPv6 identifier comes back bare). Malformed pairs are skipped rather than
    raised, and empty elements are dropped.
    """
    elements: list[dict[str, str]] = []
    for element in _split(header, ","):
        pairs = _parse_element(element)
        if pairs:
            elements.append(pairs)
    return elements


def _parse_element(element: str) -> dict[str, str]:
    pairs: dict[str, str] = {}
    for segment in _split(element, ";"):
        if "=" not in segment:
            continue
        name, _, value = segment.partition("=")
        name = name.strip().lower()
        value = value.strip()
        if name and value:
            pairs[name] = unquote(value)
    return pairs


def _split(text: str, separator: str) -> list[str]:
    """Split on ``separator`` characters that lie outside a quoted-string."""
    parts: list[str] = []
    buffer: list[str] = []
    in_quotes = False
    escaped = False
    for char in text:
        if escaped:
            buffer.append(char)
            escaped = False
        elif char == "\\" and in_quotes:
            buffer.append(char)
            escaped = True
        elif char == '"':
            in_quotes = not in_quotes
            buffer.append(char)
        elif char == separator and not in_quotes:
            parts.append("".join(buffer))
            buffer = []
        else:
            buffer.append(char)
    parts.append("".join(buffer))
    return parts
