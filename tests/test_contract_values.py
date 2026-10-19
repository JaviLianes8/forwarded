"""Contracts on stored values: plain types, honest range checks, safe entry points.

Hand-written: the subclasses below stand for hostile or careless callers.
"""

from __future__ import annotations

from enum import IntEnum
from ipaddress import IPv4Address, IPv6Address

import pytest

from forwarded import Client, Node, client_from_forwarded, client_from_x_forwarded, parse_node

UNKNOWN = parse_node("unknown")


class Liar(int):
    """An int whose comparisons always say the value is in range."""

    def __lt__(self, other: object) -> bool:
        return False

    def __gt__(self, other: object) -> bool:
        return False

    def __le__(self, other: object) -> bool:
        return True

    def __ge__(self, other: object) -> bool:
        return True


class Count(IntEnum):
    TWO = 2


class Text(str):
    pass


class V4(IPv4Address):
    pass


class V6(IPv6Address):
    pass


def test_unknown_and_addresses_are_not_obfuscated() -> None:
    assert parse_node("unknown").obfuscated is False
    assert Node(name="UNKNOWN").obfuscated is False
    assert parse_node("192.0.2.43:_port").obfuscated is False
    assert parse_node("_hidden").obfuscated is True


def test_a_negative_proxy_count_raises() -> None:
    with pytest.raises(ValueError, match="proxies cannot be negative"):
        Client(UNKNOWN, proxies=-1)


def test_a_proxy_count_that_lies_about_its_range_still_raises() -> None:
    with pytest.raises(ValueError, match="proxies cannot be negative"):
        Client(UNKNOWN, proxies=Liar(-1))


@pytest.mark.parametrize("name", ["proto_hops", "host_hops"])
def test_header_counts_that_lie_about_their_range_still_raise(name: str) -> None:
    with pytest.raises(ValueError, match=f"{name} must be at least 1"):
        client_from_x_forwarded("203.0.113.9", "10.0.0.2", **{name: Liar(0)})  # type: ignore[arg-type]


def test_a_header_count_of_zero_never_reads_the_client_value() -> None:
    with pytest.raises(ValueError, match="proto_hops must be at least 1"):
        client_from_x_forwarded("203.0.113.9", "10.0.0.2", proto="javascript, https", proto_hops=0)


def test_a_hop_count_that_lies_about_its_range_still_raises() -> None:
    with pytest.raises(ValueError, match="hops cannot be negative"):
        client_from_forwarded("for=192.0.2.43", "10.0.0.2", hops=Liar(-1))


def test_counts_are_used_as_plain_ints() -> None:
    client = client_from_x_forwarded(
        "203.0.113.9, 10.0.0.7", "10.0.0.2", proto="a, https", hops=Count.TWO, proto_hops=Count.TWO
    )
    assert client is not None and client.proto == "a" and type(client.proxies) is int


@pytest.mark.parametrize("field", ["proto", "host"])
def test_client_text_fields_of_the_wrong_type_name_the_field(field: str) -> None:
    with pytest.raises(TypeError, match=f"^{field} must be a str or None, not int$"):
        Client(UNKNOWN, **{field: 5})  # type: ignore[arg-type]


def test_node_fields_hold_plain_values_whatever_subclass_was_given() -> None:
    v4 = Node(ip=V4("192.0.2.1"), port=Count.TWO)
    v6 = Node(ip=V6("2001:db8::1"), port=Text("_p"))
    named = Node(name=Text("_hidden"))
    assert (type(v4.ip), type(v4.port)) == (IPv4Address, int)
    assert (type(v6.ip), type(v6.port)) == (IPv6Address, str)
    assert type(named.name) is str


def test_client_fields_hold_plain_values_whatever_subclass_was_given() -> None:
    client = Client(UNKNOWN, Text("https"), Text("example.com"), proxies=Count.TWO)
    assert (type(client.proto), type(client.host), type(client.proxies)) == (str, str, int)
    assert client.proxies == 2
