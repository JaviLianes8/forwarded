from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address, ip_address

import pytest

from forwarded import ForwardedError, Node, parse_node


def test_ipv4_with_and_without_a_port() -> None:
    assert parse_node("192.0.2.43") == Node(ip=IPv4Address("192.0.2.43"))
    assert parse_node("192.0.2.43:47011") == Node(ip=IPv4Address("192.0.2.43"), port=47011)


def test_bracketed_ipv6_with_and_without_a_port() -> None:
    ip = IPv6Address("2001:db8:cafe::17")
    assert parse_node("[2001:db8:cafe::17]") == Node(ip=ip)
    assert parse_node("[2001:db8:cafe::17]:47011") == Node(ip=ip, port=47011)


def test_ipv6_with_an_embedded_ipv4() -> None:
    assert parse_node("[::ffff:192.0.2.1]").ip == ip_address("::ffff:192.0.2.1")


def test_unknown_in_any_case_is_normalised() -> None:
    for text in ("unknown", "UNKNOWN", "UnKnOwN"):
        node = parse_node(text)
        assert node.unknown and node.name == "unknown" and node.ip is None


def test_unknown_with_a_kelvin_sign_is_not_unknown() -> None:
    with pytest.raises(ForwardedError):
        parse_node("un" + chr(0x212A) + "nown")


def test_obfuscated_names_and_ports() -> None:
    node = parse_node("_hidden:_p.1-x")
    assert (node.name, node.port, node.obfuscated, node.unknown) == (
        "_hidden",
        "_p.1-x",
        True,
        False,
    )
    assert parse_node("unknown:_x").port == "_x"


def test_ports_follow_the_five_digit_grammar() -> None:
    assert parse_node("192.0.2.1:0").port == 0
    assert parse_node("192.0.2.1:00080").port == 80
    assert parse_node("192.0.2.1:99999").port == 99999


@pytest.mark.parametrize(
    "text",
    [
        "",
        "2001:db8::1",
        "[2001:db8::1",
        "[2001:db8::1]x",
        "[2001:db8::1]x80",
        "[2001:db8::1]_x",
        "[2001:db8::1]:",
        "[192.0.2.1]",
        "[fe80::1%eth0]",
        "[]",
        "192.0.2.1:",
        "192.0.2.1:123456",
        "192.0.2.1:-1",
        "192.0.2.1:" + chr(0xFF18) + chr(0xFF10),
        "192.0.2.1:_",
        "192.0.2.1:8:8",
        "192.0.2.256",
        "01.2.3.4",
        "1.2.3",
        chr(0xFF11) + ".2.3.4",
        "_",
        "_a b",
        "_\xe9",
        "hidden",
        "example.com",
        " 192.0.2.1",
    ],
)
def test_invalid_identifiers_raise(text: str) -> None:
    with pytest.raises(ForwardedError):
        parse_node(text)


def test_str_writes_the_rfc_form() -> None:
    assert str(Node(ip=ip_address("2001:DB8::0:1"), port=80)) == "[2001:db8::1]:80"
    assert str(Node(ip=ip_address("192.0.2.1"))) == "192.0.2.1"
    assert str(Node(name="UNKNOWN", port="_p")) == "unknown:_p"


def test_str_round_trips_through_parse_node() -> None:
    for text in ("192.0.2.1:8", "[2001:db8::1]", "_x:_y", "unknown"):
        assert str(parse_node(text)) == text


@pytest.mark.parametrize(
    "kwargs",
    [
        {},
        {"ip": ip_address("192.0.2.1"), "name": "_a"},
        {"name": "hidden"},
        {"ip": ip_address("fe80::1%eth0")},
        {"name": "_a", "port": 100000},
        {"name": "_a", "port": -1},
        {"name": "_a", "port": "80"},
    ],
)
def test_invalid_nodes_cannot_be_built(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        Node(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "kwargs", [{"ip": "192.0.2.1"}, {"name": "_a", "port": True}, {"name": "_a", "port": 1.0}]
)
def test_nodes_of_the_wrong_type_cannot_be_built(kwargs: dict[str, object]) -> None:
    with pytest.raises(TypeError):
        Node(**kwargs)  # type: ignore[arg-type]


def test_nodes_are_frozen_and_hashable() -> None:
    node = parse_node("_a")
    with pytest.raises(AttributeError):
        node.name = "_b"  # type: ignore[misc]
    assert len({node, parse_node("_a")}) == 1
