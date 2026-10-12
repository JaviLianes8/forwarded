"""Client resolution from Forwarded; hand-written from RFC 7239 sections 5.2, 7.5 and 8.1."""

from __future__ import annotations

from ipaddress import ip_address, ip_network

import pytest

from forwarded import Client, Node, client_from_forwarded

CHAIN = "for=192.0.2.43, for=198.51.100.17;by=203.0.113.60;proto=http;host=example.com"


def _ip(client: Client | None) -> str | None:
    return None if client is None else str(client.node)


def test_without_trust_the_client_is_the_peer() -> None:
    assert client_from_forwarded(CHAIN, "203.0.113.60") == Client(
        Node(ip=ip_address("203.0.113.60"))
    )


def test_an_untrusted_peer_means_the_header_is_ignored() -> None:
    client = client_from_forwarded(CHAIN, "192.0.2.99", trusted=["203.0.113.0/24"])
    assert client == Client(Node(ip=ip_address("192.0.2.99")))


def test_the_rightmost_untrusted_entry_is_the_client() -> None:
    client = client_from_forwarded(CHAIN, "203.0.113.60", trusted=["203.0.113.60"])
    assert client == Client(
        Node(ip=ip_address("198.51.100.17")), proto="http", host="example.com", proxies=1
    )


def test_trusting_more_proxies_walks_further_left() -> None:
    trusted = ["203.0.113.60", "198.51.100.0/24"]
    client = client_from_forwarded(CHAIN, "203.0.113.60", trusted=trusted)
    assert client == Client(Node(ip=ip_address("192.0.2.43")), proxies=2)


def test_when_everything_is_trusted_the_leftmost_entry_is_the_client() -> None:
    client = client_from_forwarded(CHAIN, "203.0.113.60", trusted=["0.0.0.0/0"])
    assert _ip(client) == "192.0.2.43"
    assert client is not None and client.proxies == 2


def test_a_spoofed_leftmost_entry_is_not_believed() -> None:
    header = "for=10.0.0.1, for=192.0.2.43"
    client = client_from_forwarded(header, "10.0.0.2", trusted=["10.0.0.0/8"])
    assert _ip(client) == "192.0.2.43"


def test_hops_trust_by_position() -> None:
    assert _ip(client_from_forwarded(CHAIN, "10.9.9.9", hops=0)) == "10.9.9.9"
    assert _ip(client_from_forwarded(CHAIN, "10.9.9.9", hops=1)) == "198.51.100.17"
    assert _ip(client_from_forwarded(CHAIN, "10.9.9.9", hops=2)) == "192.0.2.43"


def test_a_chain_shorter_than_hops_gives_none() -> None:
    assert client_from_forwarded(CHAIN, "10.9.9.9", hops=3) is None
    assert client_from_forwarded(None, "10.9.9.9", hops=1) is None


def test_hops_do_not_need_a_peer_address() -> None:
    assert _ip(client_from_forwarded(CHAIN, None, hops=1)) == "198.51.100.17"


def test_no_peer_address_without_hops_gives_none() -> None:
    assert client_from_forwarded(CHAIN, None, trusted=["0.0.0.0/0"]) is None
    assert client_from_forwarded(CHAIN, None, hops=0) is None


@pytest.mark.parametrize(
    "header",
    [
        "for=192.0.2.43, proto=https",
        "for=192.0.2.43, for=nonsense",
        'for=192.0.2.43, for="192.0.2.9;x="',
        "for=192.0.2.43, for=192.0.2.8;for=192.0.2.9",
        'for=192.0.2.43, for="192.0.2.9"junk',
    ],
)
def test_a_malformed_entry_at_the_boundary_gives_none(header: str) -> None:
    assert client_from_forwarded(header, "10.0.0.1", trusted=["10.0.0.0/8"]) is None


def test_a_malformed_entry_beyond_the_boundary_does_not_matter() -> None:
    header = "for=nonsense, for=192.0.2.9"
    assert _ip(client_from_forwarded(header, "10.0.0.1", trusted=["10.0.0.0/8"])) == "192.0.2.9"


def test_identifiers_that_are_not_addresses_are_never_trusted() -> None:
    header = "for=_hidden, for=unknown"
    client = client_from_forwarded(header, "10.0.0.1", trusted=["0.0.0.0/0", "::/0"])
    assert client is not None and client.node.unknown


def test_ipv6_entries_and_ports() -> None:
    header = 'for="[2001:db8::7]:4711";proto=https, for="[2001:db8:1::1]"'
    client = client_from_forwarded(header, "2001:db8:1::2", trusted=["2001:db8:1::/48"])
    assert client == Client(Node(ip=ip_address("2001:db8::7"), port=4711), "https", None, 2)


def test_an_unbracketed_ipv6_entry_from_a_sloppy_proxy_is_read() -> None:
    header = 'for="2001:db8::7"'
    assert _ip(client_from_forwarded(header, "10.0.0.1", trusted=["10.0.0.1"])) == "[2001:db8::7]"


def test_an_ipv4_mapped_peer_matches_an_ipv4_network() -> None:
    client = client_from_forwarded("for=192.0.2.43", "::ffff:10.0.0.1", trusted=["10.0.0.0/8"])
    assert _ip(client) == "192.0.2.43"
    client = client_from_forwarded("for=192.0.2.43", "::ffff:10.0.0.1", trusted=["::ffff:0:0/96"])
    assert _ip(client) == "192.0.2.43"


def test_an_ipv4_mapped_peer_outside_the_network_is_not_trusted() -> None:
    client = client_from_forwarded("for=192.0.2.43", "::ffff:11.0.0.1", trusted=["10.0.0.0/8"])
    assert _ip(client) == "[::ffff:11.0.0.1]"


def test_trusted_accepts_addresses_networks_and_strings() -> None:
    trusted = [ip_address("10.0.0.1"), ip_network("10.1.0.0/16"), "10.2.0.0/16", "10.3.0.9/8"]
    header = "for=192.0.2.43, for=10.1.2.3, for=10.2.3.4"
    assert _ip(client_from_forwarded(header, "10.0.0.1", trusted=trusted)) == "192.0.2.43"


def test_peer_forms() -> None:
    assert _ip(client_from_forwarded(None, ip_address("2001:db8::1"))) == "[2001:db8::1]"
    assert _ip(client_from_forwarded(None, "[2001:db8::1]:443")) == "[2001:db8::1]:443"
    assert _ip(client_from_forwarded(None, "fe80::1%eth0")) == "[fe80::1]"
    assert _ip(client_from_forwarded(None, ip_address("fe80::1%eth0"))) == "[fe80::1]"


def test_several_lines_form_one_chain() -> None:
    lines = ["for=192.0.2.43", "for=198.51.100.17"]
    assert _ip(client_from_forwarded(lines, "10.0.0.1", trusted=["10.0.0.1"])) == "198.51.100.17"


@pytest.mark.parametrize("remote", ["unknown", "_x", "example.com", ""])
def test_a_peer_that_is_not_an_address_raises(remote: str) -> None:
    with pytest.raises(ValueError, match="not an IP address"):
        client_from_forwarded(None, remote)


def test_bad_arguments_raise() -> None:
    with pytest.raises(ValueError, match="not both"):
        client_from_forwarded(None, "10.0.0.1", trusted=["10.0.0.1"], hops=1)
    with pytest.raises(ValueError, match="negative"):
        client_from_forwarded(None, "10.0.0.1", hops=-1)
    with pytest.raises(TypeError):
        client_from_forwarded(None, "10.0.0.1", hops=True)
    with pytest.raises(TypeError, match="not a str"):
        client_from_forwarded(None, "10.0.0.1", trusted="10.0.0.0/8")
    with pytest.raises(TypeError):
        client_from_forwarded(None, "10.0.0.1", trusted=[10])  # type: ignore[list-item]
    with pytest.raises(TypeError):
        client_from_forwarded(None, 167772161)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        client_from_forwarded(None, "10.0.0.1", trusted=["10.0.0.0/33"])
