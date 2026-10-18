"""Which addresses are trusted proxies, the peer address, and the walk from the right."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_network

from ._errors import kind, show
from ._node import Node, parse_lenient_node

Address = str | IPv4Address | IPv6Address
Trusted = str | IPv4Address | IPv6Address | IPv4Network | IPv6Network

_MAPPED = IPv6Network("::ffff:0:0/96")


class Trust:
    """Proxies trusted by address (IPv4 and IPv6 networks) or by position (``hops``)."""

    def __init__(self, trusted: Iterable[Trusted], hops: int | None) -> None:
        if isinstance(trusted, (str, bytes, bytearray)):
            raise TypeError("trusted must be an iterable of addresses or networks, not one string")
        try:
            items = iter(trusted)
        except TypeError:
            raise TypeError(f"trusted must be an iterable, not {kind(trusted)}") from None
        self.v4: list[IPv4Network] = []
        self.v6: list[IPv6Network] = []
        for item in items:
            network = _network(item)
            if isinstance(network, IPv4Network):
                self.v4.append(network)
            else:
                self.v6.append(network)
        if hops is not None:
            if isinstance(hops, bool) or not isinstance(hops, int):
                raise TypeError(f"hops must be an int or None, not {kind(hops)}")
            if hops < 0:
                raise ValueError("hops cannot be negative")
            if self.v4 or self.v6:
                raise ValueError("give trusted or hops, not both")
        self.hops = hops

    def by_position(self, position: int) -> bool:
        return self.hops is not None and position < self.hops

    def by_address(self, node: Node) -> bool:
        ip = node.ip
        if ip is None:
            return False
        if isinstance(ip, IPv6Address):
            mapped = ip.ipv4_mapped
            if mapped is None:
                return any(ip in network for network in self.v6)
            # A dual-stack socket reports IPv4 peers as ::ffff:a.b.c.d: read them as IPv4.
            ip = mapped
        return any(ip in network for network in self.v4)


def walk(
    entries: Sequence[str | None], peer: Node | None, trust: Trust
) -> tuple[int, Node, int] | None:
    """Find the client in ``entries`` followed by ``peer``, walking from the right.

    Returns its index in that chain, its node and the number of trusted proxies passed,
    or ``None``. Entries are read only when the walk reaches them; ``None`` is malformed.
    """
    count = len(entries) + 1
    node: Node | None = None
    for position in range(count):
        if trust.by_position(position):
            continue
        index = count - 1 - position
        if position == 0:
            node = peer
        else:
            entry = entries[index]
            node = parse_lenient_node(entry) if entry is not None else None
        if node is None:
            return None
        if not trust.by_address(node):
            return index, node, position
    if trust.hops is not None or node is None:
        return None
    # Every address is trusted: the leftmost entry is the best there is.
    return 0, node, count - 1


def remote_node(remote: Address | None) -> Node | None:
    """Return the peer address as a node, its IPv6 zone dropped; ``None`` stays ``None``."""
    if remote is None:
        return None
    if isinstance(remote, (IPv4Address, IPv6Address)):
        if isinstance(remote, IPv6Address) and remote.scope_id is not None:
            return Node(ip=IPv6Address(int(remote)))
        return Node(ip=remote)
    if not isinstance(remote, str):
        raise TypeError(f"remote must be a str, an IP address or None, not {kind(remote)}")
    node = parse_lenient_node(_without_zone(str.__str__(remote)))
    if node is None or node.ip is None:
        raise ValueError(f"remote {show(remote)} is not an IP address")
    return node


def _network(item: object) -> IPv4Network | IPv6Network:
    if isinstance(item, (IPv4Network, IPv6Network)):
        network = item
    elif isinstance(item, (IPv4Address, IPv6Address)):
        network = ip_network(item)
    elif isinstance(item, str):
        network = _parse_network(str.__str__(item))
    else:
        raise TypeError(f"cannot trust {show(item)}: give an address or a network")
    if isinstance(network, IPv6Network) and network.subnet_of(_MAPPED):
        # A genuine IPv4-mapped network names IPv4 addresses: keep it as that IPv4 network.
        return IPv4Network((int(network.network_address) & 0xFFFFFFFF, network.prefixlen - 96))
    return network


def _parse_network(text: str) -> IPv4Network | IPv6Network:
    try:
        network = ip_network(text, strict=False)
    except ValueError:
        raise ValueError(f"cannot trust {show(text)}: not an address or a network") from None
    address, slash, _ = text.partition("/")
    if slash and isinstance(network, IPv6Network) and network.prefixlen < 96:
        written = IPv6Address(address)
        if written.ipv4_mapped is not None:
            # ::ffff:10.0.0.0/8 would silently mean ::/8 (CVE-2026-90711 in proxy-addr).
            raise ValueError(
                f"cannot trust {show(text)}: an IPv4-mapped network needs a prefix of at "
                "least 96; write the IPv4 network instead"
            )
    return network


def _without_zone(remote: str) -> str:
    """Drop the zone of an IPv6 address (``fe80::1%eth0``, ``[fe80::1%eth0]:80``)."""
    address, percent, zone = remote.partition("%")
    if not percent or ":" not in address:
        return remote
    _, bracket, port = zone.partition("]")
    return address + bracket + port
