"""Node identifiers of the ``for`` and ``by`` parameters (RFC 7239 section 6)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address

from ._errors import ForwardedError

_OBFUSCATED = re.compile(r"_[A-Za-z0-9._-]+")
_PORT = re.compile(r"[0-9]{1,5}")
_IPV4 = re.compile(r"[0-9]{1,3}(\.[0-9]{1,3}){3}")
_IPV6 = re.compile(r"[0-9A-Fa-f:.]+")


@dataclass(frozen=True)
class Node:
    """A node identifier: an IP address or a name, with an optional port.

    Exactly one of ``ip`` and ``name`` is set. ``name`` is ``"unknown"`` or an obfuscated
    identifier such as ``"_hidden"``. ``port`` is a number, an obfuscated port such as
    ``"_8080"``, or ``None``. ``str(node)`` gives the RFC 7239 form, with an IPv6 address
    in brackets; it still needs quoting in a header when it holds ``:`` or ``[``, which
    ``build`` does.
    """

    ip: IPv4Address | IPv6Address | None = None
    name: str | None = None
    port: int | str | None = None

    def __post_init__(self) -> None:
        if (self.ip is None) == (self.name is None):
            raise ValueError("a Node needs exactly one of ip and name")
        if self.ip is not None and not isinstance(self.ip, (IPv4Address, IPv6Address)):
            raise TypeError("ip must be an IPv4Address or an IPv6Address")
        if isinstance(self.ip, IPv6Address) and self.ip.scope_id is not None:
            raise ValueError("a node identifier cannot carry an IPv6 zone")
        if self.name is not None:
            if _is_unknown(self.name):
                object.__setattr__(self, "name", "unknown")
            elif not _is_obfuscated(self.name):
                raise ValueError(f"{self.name!r} is neither 'unknown' nor an obfuscated name")
        if isinstance(self.port, bool) or not isinstance(self.port, (int, str, type(None))):
            raise TypeError("port must be an int, an obfuscated port string or None")
        if isinstance(self.port, int) and not 0 <= self.port <= 99999:
            raise ValueError("a port has at most five digits")
        if isinstance(self.port, str) and not _is_obfuscated(self.port):
            raise ValueError(f"{self.port!r} is not an obfuscated port")

    @property
    def unknown(self) -> bool:
        """Whether this is the ``unknown`` identifier."""
        return self.name == "unknown"

    @property
    def obfuscated(self) -> bool:
        """Whether the name is an obfuscated identifier (the port is not considered)."""
        return self.name is not None and self.name.startswith("_")

    def __str__(self) -> str:
        if isinstance(self.ip, IPv6Address):
            host = f"[{self.ip}]"
        else:
            host = str(self.ip) if self.ip is not None else str(self.name)
        return host if self.port is None else f"{host}:{self.port}"


def parse_node(value: str) -> Node:
    """Parse a ``for`` or ``by`` value (already unquoted) as RFC 7239 section 6 defines it.

    Accepts an IPv4 address, an IPv6 address in brackets, ``unknown`` in any case or an
    obfuscated name, each with an optional port or obfuscated port. Raises
    ``ForwardedError`` for anything else, such as an IPv6 address without brackets.
    """
    if value.startswith("["):
        close = value.find("]")
        ip6 = _ipv6(value[1:close]) if close > 0 else None
        if ip6 is None:
            raise ForwardedError(f"{value!r} is not a bracketed IPv6 address")
        node = Node(ip=ip6)
        rest = value[close + 1 :]
    else:
        host, colon, port = value.partition(":")
        node = _nodename(host, value)
        rest = colon + port
    if not rest:
        return node
    if rest[0] != ":" or not (_PORT.fullmatch(rest[1:]) or _is_obfuscated(rest[1:])):
        raise ForwardedError(f"{value!r} has an invalid port")
    port = rest[1:]
    return Node(ip=node.ip, name=node.name, port=port if port[0] == "_" else int(port))


def parse_lenient_node(value: str) -> Node | None:
    """Read an X-Forwarded-For entry: the RFC 7239 forms plus a bare IPv6 address."""
    value = value.strip(" \t")
    try:
        return parse_node(value)
    except ForwardedError:
        pass
    ip6 = _ipv6(value)
    return Node(ip=ip6) if ip6 is not None else None


def _nodename(host: str, value: str) -> Node:
    if _IPV4.fullmatch(host):
        try:
            return Node(ip=IPv4Address(host))
        except ValueError:
            pass
    elif _is_unknown(host) or _is_obfuscated(host):
        return Node(name=host)
    raise ForwardedError(f"{value!r} is not a node identifier")


def _ipv6(text: str) -> IPv6Address | None:
    if not _IPV6.fullmatch(text):
        return None
    try:
        return IPv6Address(text)
    except ValueError:
        return None


def _is_unknown(text: str) -> bool:
    # ABNF literals are case-insensitive over ASCII only; the Kelvin sign lowers to "k".
    return text.isascii() and text.lower() == "unknown"


def _is_obfuscated(text: str) -> bool:
    return bool(_OBFUSCATED.fullmatch(text))
