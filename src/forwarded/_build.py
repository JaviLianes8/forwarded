"""Build an HTTP Forwarded header from its elements (RFC 7239)."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from ._errors import ForwardedError, kind, show
from ._node import Node
from ._parse import check_value
from ._tokens import is_quotable, is_token, quote_if_needed


def build(elements: Iterable[Mapping[str, str | Node]]) -> str:
    """Build a Forwarded header from ``elements``, one mapping per element.

    Values may be strings or ``Node`` objects; a ``Node`` is written in its RFC form, so
    an IPv6 address gets its brackets. Parameter names are lower-cased and values are
    quoted only when they are not bare tokens, so an IPv6 identifier with a port is quoted
    while ``proto=http`` stays bare. Elements are joined with ``", "`` and the parameters
    within an element with ``";"``. No elements give an empty string.

    Raises ``ForwardedError`` (a ``ValueError``) rather than write a header a strict
    reader would reject: an empty element, a name that is not a token, two names that
    differ only in case, a character a header cannot carry (such as CR or LF), or a
    ``for``/``by``/``host``/``proto`` value of the wrong syntax. Raises ``TypeError`` for
    a single mapping or string given as ``elements``, an element that is not a mapping,
    and names or values that are not strings (or ``Node`` values).

    >>> from ipaddress import ip_address
    >>> from forwarded import Node, build
    >>> build([{"for": Node(ip=ip_address("2001:db8::1"), port=8080), "Proto": "https"}])
    'for="[2001:db8::1]:8080";proto=https'
    >>> build([{"for": "192.0.2.43"}, {"for": "unknown", "host": "example.com:8080"}])
    'for=192.0.2.43, for=unknown;host="example.com:8080"'
    >>> build([{"host": "example.com\\r\\nX-Admin: 1"}])
    Traceback (most recent call last):
      ...
    forwarded.ForwardedError: host value holds '\\r', which a header cannot carry
    """
    if isinstance(elements, (str, bytes, bytearray, Mapping)):
        raise TypeError(f"elements must be an iterable of mappings, not a {kind(elements)}")
    try:
        items = iter(elements)
    except TypeError:
        raise TypeError(f"elements must be an iterable of mappings, not {kind(elements)}") from None
    return ", ".join(_build_element(element) for element in items)


def _build_element(element: object) -> str:
    if not isinstance(element, Mapping):
        raise TypeError(f"each element must be a mapping, not {kind(element)}")
    if not element:
        raise ForwardedError("an element needs at least one parameter")
    written: dict[str, str] = {}
    for raw_name, raw_value in element.items():
        name, value = _checked(raw_name, raw_value)
        if name in written:
            raise ForwardedError(f"parameter {show(name)} is given twice")
        written[name] = value
    return ";".join(f"{name}={quote_if_needed(value)}" for name, value in written.items())


def _checked(name: object, value: object) -> tuple[str, str]:
    if not isinstance(name, str):
        raise TypeError(f"parameter names must be str, not {kind(name)}")
    if not isinstance(value, (str, Node)):
        raise TypeError(f"parameter values must be str or Node, not {kind(value)}")
    name = str.__str__(name)
    if not is_token(name):
        raise ForwardedError(f"parameter name {show(name)} is not a token")
    text = str.__str__(value) if isinstance(value, str) else Node.__str__(value)
    bad = next((char for char in text if not is_quotable(char)), None)
    if bad is not None:
        label = name if len(name) <= 40 else name[:37] + "..."
        raise ForwardedError(f"{label} value holds {bad!r}, which a header cannot carry")
    check_value(name.lower(), text)
    return name.lower(), text
