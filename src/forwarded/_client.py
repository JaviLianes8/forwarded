"""Pick the client out of a chain of proxies without trusting what the client wrote."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from ._errors import kind
from ._node import Node
from ._parse import scan_header
from ._trust import Address, Trust, Trusted, remote_node, walk
from ._xff import parse_x_forwarded


@dataclass(frozen=True)
class Client:
    """The client as seen by the first proxy you trust.

    ``node`` is the client's identifier, ``proto`` and ``host`` are the protocol and Host
    the client used as recorded by that proxy (``None`` when it recorded none), and
    ``proxies`` is the number of trusted proxies between the client and this server.
    Building one by hand checks the field types (``TypeError``) and that ``proxies`` is
    not negative (``ValueError``).

    >>> from forwarded import Client, client_from_forwarded, parse_node
    >>> header = "for=192.0.2.43;proto=https;host=shop.example"
    >>> client = client_from_forwarded(header, "10.0.0.2", trusted=["10.0.0.0/8"])
    >>> client == Client(parse_node("192.0.2.43"), "https", "shop.example", proxies=1)
    True
    """

    node: Node
    proto: str | None = None
    host: str | None = None
    proxies: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.node, Node):
            raise TypeError(f"node must be a Node, not {kind(self.node)}")
        for field in ("proto", "host"):
            value = getattr(self, field)
            if value is not None:
                if not isinstance(value, str):
                    raise TypeError(f"{field} must be a str or None, not {kind(value)}")
                object.__setattr__(self, field, str.__str__(value))
        if isinstance(self.proxies, bool) or not isinstance(self.proxies, int):
            raise TypeError(f"proxies must be an int, not {kind(self.proxies)}")
        if self.proxies < 0:
            raise ValueError("proxies cannot be negative")
        object.__setattr__(self, "proxies", int.__int__(self.proxies))


def client_from_forwarded(
    header: str | Iterable[str] | None,
    remote: Address | None,
    *,
    trusted: Iterable[Trusted] = (),
    hops: int | None = None,
) -> Client | None:
    """Return the client of a request from its ``Forwarded`` lines and the peer address.

    The chain is every ``for`` in ``header`` followed by ``remote``, the address the
    connection came from. It is walked from the right: while an entry is a trusted proxy
    the walk goes on, and the first entry that is not is the client. Proxies are trusted
    by address (``trusted``: addresses or networks) or by position (``hops``: that many
    proxies in front of this server, whatever their addresses). With neither, nothing is
    trusted and the client is ``remote``.

    Returns ``None`` when the client cannot be told: the entry at the boundary is
    malformed or has no ``for``, ``remote`` is ``None`` and not covered by ``hops``, or
    the chain is shorter than ``hops``. When every address is trusted the leftmost is
    the client. ``proto`` and ``host`` come from the client's own element.

    >>> from forwarded import client_from_forwarded
    >>> header = 'for=10.0.0.9, for="[2001:db8::7]:4711";proto=https, for=10.0.0.7'
    >>> client = client_from_forwarded(header, "10.0.0.2", trusted=["10.0.0.0/8"])
    >>> print(client.node, client.proto, client.proxies)
    [2001:db8::7]:4711 https 2
    >>> print(client_from_forwarded(header, "10.0.0.2", hops=1).node)
    10.0.0.7
    >>> untrusted_peer = client_from_forwarded(header, "203.0.113.9", trusted=["10.0.0.0/8"])
    >>> print(untrusted_peer.node, untrusted_peer.proxies)
    203.0.113.9 0
    """
    trust = Trust(trusted, hops)
    peer = remote_node(remote)
    elements = scan_header(header if header is not None else [], strict=False)
    entries = [
        None if element.error is not None else element.as_dict().get("for") for element in elements
    ]
    found = walk(entries, peer, trust)
    if found is None:
        return None
    index, node, proxies = found
    pairs = elements[index].as_dict() if index < len(elements) else {}
    return Client(node, pairs.get("proto"), pairs.get("host"), proxies)


def client_from_x_forwarded(
    x_forwarded_for: str | Iterable[str] | None,
    remote: Address | None,
    *,
    proto: str | Iterable[str] | None = None,
    host: str | Iterable[str] | None = None,
    trusted: Iterable[Trusted] = (),
    hops: int | None = None,
    proto_hops: int = 1,
    host_hops: int = 1,
) -> Client | None:
    """Return the client of a request from its ``X-Forwarded-For`` lines and peer address.

    The walk is the one of ``client_from_forwarded`` over the X-Forwarded-For entries,
    which may be bare IPv4 or IPv6 addresses, with or without a port. ``proto`` and
    ``host`` are the X-Forwarded-Proto and X-Forwarded-Host lines. Proxies often set those
    at the edge only, so each has its own count, as in Werkzeug's ``ProxyFix``:
    ``proto_hops`` and ``host_hops`` are the number of trusted proxies that append to
    that header, and the value used is that many from the right. It is ``None`` when the
    header has fewer values, or when the count is larger than the number of trusted
    proxies the walk passed, since such a value could come from the client.

    >>> from forwarded import client_from_x_forwarded
    >>> client = client_from_x_forwarded(
    ...     "1.1.1.1, 203.0.113.195, 10.0.0.7", "10.0.0.2", proto="https", trusted=["10.0.0.0/8"]
    ... )
    >>> print(client.node, client.proto, client.proxies)
    203.0.113.195 https 2
    >>> print(client_from_x_forwarded("203.0.113.195, junk", "10.0.0.2", hops=1))
    None
    """
    proto_hops, host_hops = _count(proto_hops, "proto_hops"), _count(host_hops, "host_hops")
    trust = Trust(trusted, hops)
    peer = remote_node(remote)
    entries = parse_x_forwarded(x_forwarded_for) if x_forwarded_for is not None else []
    protos = parse_x_forwarded(proto) if proto is not None else []
    hosts = parse_x_forwarded(host) if host is not None else []
    found = walk(entries, peer, trust)
    if found is None:
        return None
    _, node, proxies = found
    proto_value = _nth_from_right(protos, proto_hops, proxies)
    return Client(node, proto_value, _nth_from_right(hosts, host_hops, proxies), proxies)


def _count(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, not {kind(value)}")
    if value < 1:
        raise ValueError(f"{name} must be at least 1")
    return value


def _nth_from_right(values: list[str], n: int, proxies: int) -> str | None:
    # A value further left than the trusted proxies passed could come from the client.
    return values[-n] if n <= proxies and len(values) >= n else None
