"""Build an HTTP Forwarded header from its elements (RFC 7239)."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from ._tokens import quote_if_needed


def build(elements: Iterable[Mapping[str, str]]) -> str:
    """Build a Forwarded header from ``elements``.

    Each mapping becomes one element. Parameter names are lower-cased and values are
    quoted only when they are not bare tokens, so an IPv6 identifier with a port is
    quoted while ``proto=http`` stays bare. Elements are joined with ``", "`` and the
    parameters within an element with ``";"``.
    """
    return ", ".join(_build_element(element) for element in elements)


def _build_element(element: Mapping[str, str]) -> str:
    return ";".join(f"{name.lower()}={quote_if_needed(value)}" for name, value in element.items())
