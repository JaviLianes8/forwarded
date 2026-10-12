"""Pick the client out of a chain of proxies without trusting what the client wrote."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_network

from ._node import Node, parse_lenient_node
from ._parse import scan_header
from ._xff import parse_x_forwarded

Address = str | IPv4Address | IPv6Address
Trusted = str | IPv4Address | IPv6Address | IPv4Network | IPv6Network


@dataclass(frozen=True)
class Client:
    """The client as seen by the first proxy you trust.

    ``node`` is the client's identifier, ``proto`` and ``host`` are the protocol and Host
    the client used as recorded by that proxy (``None`` when it recorded none), and
    ``proxies`` is the number of trusted proxies between the client and this server.
    """

    node: Node
    proto: str | None = None
    host: str | None = None
    proxies: int = 0


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
    """
    elements = scan_header(header if header is not None else [], strict=False)
    nodes: list[Node | None] = []
    for element in elements:
        value = element.as_dict().get("for")
        bad = element.error is not None or value is None
        nodes.append(None if bad or value is None else parse_lenient_node(value))
    found = _walk(nodes, remote, _Trust(trusted, hops))
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
) -> Client | None:
    """Return the client of a request from its ``X-Forwarded-For`` lines and peer address.

    The walk is the one of ``client_from_forwarded`` over the X-Forwarded-For entries,
    which may be bare IPv4 or IPv6 addresses, with or without a port. ``proto`` and
    ``host`` are the X-Forwarded-Proto and X-Forwarded-Host lines: with N trusted proxies
    in front of the client, the value used is the N-th from the right, and ``None`` when
    there are fewer values (the rule of Werkzeug's ``ProxyFix``).
    """
    entries = parse_x_forwarded(x_forwarded_for) if x_forwarded_for is not None else []
    nodes = [parse_lenient_node(entry) for entry in entries]
    found = _walk(nodes, remote, _Trust(trusted, hops))
    if found is None:
        return None
    _, node, proxies = found
    return Client(node, _nth_from_right(proto, proxies), _nth_from_right(host, proxies), proxies)


class _Trust:
    def __init__(self, trusted: Iterable[Trusted], hops: int | None) -> None:
        if isinstance(trusted, (str, bytes)):
            raise TypeError("trusted must be an iterable of addresses or networks, not a str")
        self.networks = [_network(item) for item in trusted]
        if hops is not None:
            if isinstance(hops, bool) or not isinstance(hops, int):
                raise TypeError("hops must be an int")
            if hops < 0:
                raise ValueError("hops cannot be negative")
            if self.networks:
                raise ValueError("give trusted or hops, not both")
        self.hops = hops

    def by_position(self, position: int) -> bool:
        return self.hops is not None and position < self.hops

    def by_address(self, node: Node) -> bool:
        ip = node.ip
        if ip is None:
            return False
        mapped = ip.ipv4_mapped if isinstance(ip, IPv6Address) else None
        return any(ip in net or (mapped is not None and mapped in net) for net in self.networks)


def _walk(
    nodes: Sequence[Node | None], remote: Address | None, trust: _Trust
) -> tuple[int, Node, int] | None:
    chain = [*nodes, _remote_node(remote)]
    for position, index in enumerate(range(len(chain) - 1, -1, -1)):
        node = chain[index]
        if trust.by_position(position):
            continue
        if node is None:
            return None
        if trust.hops is not None or not trust.by_address(node):
            return index, node, position
    if trust.hops is not None or chain[0] is None:
        return None
    return 0, chain[0], len(chain) - 1


def _remote_node(remote: Address | None) -> Node | None:
    if remote is None:
        return None
    if isinstance(remote, (IPv4Address, IPv6Address)):
        ip = remote
    elif isinstance(remote, str):
        node = parse_lenient_node(remote.partition("%")[0])
        if node is None or node.ip is None:
            raise ValueError(f"remote {remote!r} is not an IP address")
        return node
    else:
        raise TypeError("remote must be a str, an IPv4Address, an IPv6Address or None")
    if isinstance(ip, IPv6Address) and ip.scope_id is not None:
        ip = IPv6Address(str(ip).partition("%")[0])
    return Node(ip=ip)


def _network(item: Trusted) -> IPv4Network | IPv6Network:
    if isinstance(item, (IPv4Network, IPv6Network)):
        return item
    if isinstance(item, (str, IPv4Address, IPv6Address)):
        return ip_network(item, strict=False)
    raise TypeError(f"cannot trust {item!r}: give an address or a network")


def _nth_from_right(header: str | Iterable[str] | None, n: int) -> str | None:
    values = parse_x_forwarded(header) if header is not None and n > 0 else []
    return values[-n] if len(values) >= n > 0 else None
