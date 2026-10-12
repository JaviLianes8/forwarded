"""Parse an HTTP Forwarded header into its elements (RFC 7239)."""

from __future__ import annotations

from collections.abc import Iterable

from ._errors import ForwardedError
from ._node import parse_node
from ._scan import Element, Pair, scan_line
from ._values import is_host, is_scheme


def header_lines(header: str | Iterable[str]) -> list[str]:
    """Return the field lines of ``header``: a single string is one line."""
    lines = [header] if isinstance(header, str) else list(header)
    for line in lines:
        if not isinstance(line, str):
            raise TypeError(f"header lines must be str, not {type(line).__name__}")
    return lines


def scan_header(header: str | Iterable[str], *, strict: bool) -> list[Element]:
    """Return the non-empty elements of every line of ``header``, in order."""
    return [element for line in header_lines(header) for element in scan_line(line, strict=strict)]


def parse(header: str | Iterable[str], *, strict: bool = False) -> list[dict[str, str]]:
    """Parse ``header`` into a list of elements, each a dict of lower-cased parameters.

    ``header`` is one field value or an iterable of them, one per ``Forwarded`` line
    received; the lines form one list, and quoting never runs from one line into the next.
    Comma-separated elements become separate dicts, in order. Parameter names are
    lower-cased because they are case-insensitive, and quoted values are unquoted (so a
    quoted IPv6 identifier comes back bare).

    By default the parser is lenient: it skips pairs it cannot read, keeps the last of
    duplicated parameters, and drops empty elements. A double quote opens a quoted-string
    only at the start of a value, and a broken one ends at the next comma, so a client
    cannot hide the elements proxies add after its own text.

    With ``strict=True`` anything outside the RFC 7239 grammar raises ``ForwardedError``:
    whitespace other than around commas, a duplicated parameter, a header with no pair,
    and ``for``/``by``/``host``/``proto`` values that break RFC 7239 sections 5 and 6.
    """
    elements = scan_header(header, strict=strict)
    if strict:
        if not elements:
            raise ForwardedError("a Forwarded header needs at least one parameter")
        for element in elements:
            for pair in element.pairs:
                _check_pair(pair)
    return [element.as_dict() for element in elements if element.pairs]


def check_value(name: str, value: str) -> None:
    """Raise ``ForwardedError`` if a registered parameter has a value of the wrong syntax."""
    if name in ("for", "by"):
        parse_node(value)
    elif name == "host" and not is_host(value):
        raise ForwardedError(f"host {value!r} is not a valid Host value")
    elif name == "proto" and not is_scheme(value):
        raise ForwardedError(f"proto {value!r} is not a URI scheme")


def _check_pair(pair: Pair) -> None:
    try:
        check_value(pair.name, pair.value)
    except ForwardedError as error:
        raise ForwardedError(str(error), pair.position) from None
