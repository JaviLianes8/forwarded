"""Node identifiers of the ``for`` and ``by`` parameters (RFC 7239 section 6)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address

from ._errors import ForwardedError, kind, show

_OBFUSCATED = re.compile(r"_[A-Za-z0-9._-]+")
_PORT = re.compile(r"[0-9]{1,5}")
_IPV4 = re.compile(r"[0-9]{1,3}(\.[0-9]{1,3}){3}")
_IPV6 = re.compile(r"[0-9A-Fa-f:.]+")


@dataclass(frozen=True)
class Node:
    """A node identifier: an IP address or a name, with an optional port.

    Exactly one of ``ip`` and ``name`` is set. ``name`` is ``"unknown"`` (written in any
    case, stored in lower case) or an obfuscated identifier such as ``"_hidden"``.
    ``port`` is a number from 0 to 99999, an obfuscated port such as ``"_8080"``, or
    ``None``. Wrong types raise ``TypeError``, wrong values ``ValueError``. Fields hold
    plain ``str``, ``int`` and ``ipaddress`` values, whatever subclass was given.

    ``str(node)`` gives the RFC 7239 form: an IPv6 address in brackets, written as
    RFC 5952 says (an IPv4-mapped address as ``::ffff:192.0.2.1`` on every Python
    version). It still needs quoting in a header when it holds ``:`` or ``[``, which
    ``build`` does.

    >>> from ipaddress import ip_address
    >>> from forwarded import Node
    >>> str(Node(ip=ip_address("2001:DB8::17"), port=4711))
    '[2001:db8::17]:4711'
    >>> str(Node(ip=ip_address("::ffff:c000:201")))
    '[::ffff:192.0.2.1]'
    >>> Node(name="UNKNOWN")
    Node(ip=None, name='unknown', port=None)
    """

    ip: IPv4Address | IPv6Address | None = None
    name: str | None = None
    port: int | str | None = None

    def __post_init__(self) -> None:
        ip, name, port = self.ip, self.name, self.port
        if ip is not None and not isinstance(ip, (IPv4Address, IPv6Address)):
            raise TypeError(f"ip must be an IPv4Address or an IPv6Address, not {kind(ip)}")
        if name is not None and not isinstance(name, str):
            raise TypeError(f"name must be a str, not {kind(name)}")
        if isinstance(port, bool) or not isinstance(port, (int, str, type(None))):
            raise TypeError(f"port must be an int, an obfuscated port or None, not {kind(port)}")
        if (ip is None) == (name is None):
            raise ValueError("a Node needs exactly one of ip and name")
        if isinstance(ip, IPv6Address) and ip.scope_id is not None:
            raise ValueError("a node identifier cannot carry an IPv6 zone")
        if ip is not None and type(ip) not in (IPv4Address, IPv6Address):
            plain = IPv6Address if isinstance(ip, IPv6Address) else IPv4Address
            object.__setattr__(self, "ip", plain(int(ip)))
        if name is not None:
            name = str.__str__(name)
            if _is_unknown(name):
                name = "unknown"
            elif not _is_obfuscated(name):
                raise ValueError(f"{show(name)} is neither 'unknown' nor an obfuscated name")
            object.__setattr__(self, "name", name)
        if isinstance(port, int):
            port = int.__int__(port)
            if not 0 <= port <= 99999:
                raise ValueError("a port is a number from 0 to 99999")
        elif port is not None:
            port = str.__str__(port)
            if not _is_obfuscated(port):
                raise ValueError(f"{show(port)} is not an obfuscated port")
        object.__setattr__(self, "port", port)

    @property
    def unknown(self) -> bool:
        """Whether this is the ``unknown`` identifier.

        >>> from forwarded import parse_node
        >>> parse_node("UnKnOwN").unknown, parse_node("_hidden").unknown
        (True, False)
        """
        return self.name == "unknown"

    @property
    def obfuscated(self) -> bool:
        """Whether the name is an obfuscated identifier (the port is not considered).

        >>> from forwarded import parse_node
        >>> parse_node("_hidden").obfuscated, parse_node("192.0.2.43:_p").obfuscated
        (True, False)
        """
        return self.name is not None and self.name.startswith("_")

    def __str__(self) -> str:
        if isinstance(self.ip, IPv6Address):
            mapped = self.ip.ipv4_mapped
            # RFC 5952 section 5; CPython 3.11.5 itself writes ::ffff:c000:201.
            host = f"[::ffff:{mapped}]" if mapped is not None else f"[{self.ip}]"
        else:
            host = str(self.ip) if self.ip is not None else str(self.name)
        return host if self.port is None else f"{host}:{self.port}"


def parse_node(value: str) -> Node:
    """Parse a ``for`` or ``by`` value (already unquoted) as RFC 7239 section 6 defines it.

    Accepts an IPv4 address, an IPv6 address in brackets, ``unknown`` in any case or an
    obfuscated name, each with an optional port or obfuscated port. Raises
    ``ForwardedError`` for anything else, such as an IPv6 address without brackets, and
    ``TypeError`` for a value that is not a ``str``.

    >>> from forwarded import parse_node
    >>> node = parse_node("[2001:db8:cafe::17]:4711")
    >>> node.ip, node.port
    (IPv6Address('2001:db8:cafe::17'), 4711)
    >>> parse_node("_hidden:_port")
    Node(ip=None, name='_hidden', port='_port')
    >>> parse_node("2001:db8::1")
    Traceback (most recent call last):
      ...
    forwarded.ForwardedError: '2001:db8::1' is not a node identifier
    """
    if not isinstance(value, str):
        raise TypeError(f"value must be a str, not {kind(value)}")
    value = str.__str__(value)
    if value.startswith("["):
        close = value.find("]")
        ip6 = _ipv6(value[1:close]) if close != -1 else None
        if ip6 is None:
            raise ForwardedError(f"{show(value)} is not a bracketed IPv6 address")
        node = Node(ip=ip6)
        rest = value[close + 1 :]
    else:
        host, colon, port = value.partition(":")
        node = _nodename(host, value)
        rest = colon + port
    if not rest:
        return node
    if rest[0] != ":" or not (_PORT.fullmatch(rest[1:]) or _is_obfuscated(rest[1:])):
        raise ForwardedError(f"{show(value)} has an invalid port")
    port = rest[1:]
    return Node(ip=node.ip, name=node.name, port=port if port[0] == "_" else int(port))


def parse_lenient_node(value: str) -> Node | None:
    """Read an X-Forwarded-For entry: the RFC 7239 forms plus a bare IPv6 address."""
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
    raise ForwardedError(f"{show(value)} is not a node identifier")


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
