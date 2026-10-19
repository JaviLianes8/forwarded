"""The de-facto X-Forwarded-For, X-Forwarded-Proto and X-Forwarded-Host headers."""

from __future__ import annotations

from collections.abc import Iterable

from ._build import build
from ._node import Node, parse_lenient_node
from ._parse import header_lines
from ._tokens import OWS


def parse_x_forwarded(header: str | Iterable[str]) -> list[str]:
    """Split an X-Forwarded-* header into its comma-separated values, in order.

    ``header`` is one field value or an iterable of them, one per line received; the lines
    form a single list, the first value of the first line coming first. Spaces and tabs
    around values are removed and empty values are dropped. The values themselves are not
    checked.

    >>> from forwarded import parse_x_forwarded
    >>> parse_x_forwarded(["203.0.113.195, 2001:db8::1", " , 198.51.100.178"])
    ['203.0.113.195', '2001:db8::1', '198.51.100.178']
    """
    return split_values(header, "header")


def split_values(header: str | Iterable[str], name: str) -> list[str]:
    """Return ``parse_x_forwarded(header)``, naming the argument ``name`` in errors."""
    return [
        value
        for line in header_lines(header, name)
        for value in (part.strip(OWS) for part in line.split(","))
        if value
    ]


def convert_x_forwarded_for(header: str | Iterable[str]) -> str:
    """Translate an X-Forwarded-For header into a Forwarded header (RFC 7239 section 7.4).

    Each entry becomes a ``for=`` element. A bare IPv6 address is bracketed and quoted,
    and ports are kept. An entry that is not an address or a node identifier becomes
    ``for=unknown`` so the number and order of hops stay intact. No entries give an
    empty string.

    >>> from forwarded import convert_x_forwarded_for
    >>> convert_x_forwarded_for("192.0.2.43, 2001:db8:cafe::17, 192.0.2.1:8080, garbage")
    'for=192.0.2.43, for="[2001:db8:cafe::17]", for="192.0.2.1:8080", for=unknown'
    """
    nodes = [
        parse_lenient_node(entry) or Node(name="unknown") for entry in parse_x_forwarded(header)
    ]
    return build({"for": node} for node in nodes)
