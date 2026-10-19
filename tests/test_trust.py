"""The trusted list: IPv4 and IPv6 networks, IPv4-mapped forms, and what they never cover.

The networks are hand-written. The IPv6 rules are the ones proxy-addr 2.0.8 adopted for
CVE-2026-90711 (https://github.com/advisories/GHSA-jqcg-44mw-7w3h, read 2026-10-19);
tests/test_oracles_node.py checks them against proxy-addr itself.
"""

from __future__ import annotations

from ipaddress import IPv4Network, IPv6Address, IPv6Network, ip_address

import pytest

from forwarded import client_from_forwarded, client_from_x_forwarded

SPOOF = "6.6.6.6"


def _trusts(trusted: list[object], peer: str) -> bool:
    client = client_from_x_forwarded(SPOOF, peer, trusted=trusted)  # type: ignore[arg-type]
    assert client is not None
    return client.proxies == 1


@pytest.mark.parametrize("network", ["::/0", "::/1", "::/8", "::/64", "::/95", "::/96"])
def test_a_wide_ipv6_network_never_covers_ipv4_peers(network: str) -> None:
    assert not _trusts([network], "203.0.113.9")
    assert not _trusts([network], "::ffff:203.0.113.9")
    assert client_from_x_forwarded(SPOOF, "203.0.113.9", trusted=[network]) is not None


def test_a_wide_ipv6_network_covers_ipv6_peers() -> None:
    assert _trusts(["::/1"], "2001:db8::1")
    assert not _trusts(["::/1"], "fe80::1")
    assert _trusts(["8000::/1"], "fe80::1")
    assert _trusts(["::/0"], "2001:db8::1")


@pytest.mark.parametrize("network", ["::ffff:10.0.0.0/8", "::ffff:10.0.0.0/95", "::ffff:a00:0/16"])
def test_an_ipv4_mapped_network_with_a_short_prefix_raises(network: str) -> None:
    with pytest.raises(ValueError, match="prefix of at least 96"):
        client_from_x_forwarded(SPOOF, "10.0.0.1", trusted=[network])


@pytest.mark.parametrize(
    "network",
    ["::ffff:10.0.0.0/104", "::ffff:a00:0/104", IPv6Network("::ffff:10.0.0.0/104"), "10.0.0.0/8"],
)
def test_an_ipv4_mapped_network_covers_its_ipv4_addresses_in_both_forms(network: object) -> None:
    assert _trusts([network], "10.1.2.3")
    assert _trusts([network], "::ffff:10.1.2.3")
    assert not _trusts([network], "11.0.0.1")
    assert not _trusts([network], "::ffff:11.0.0.1")


def test_the_whole_mapped_range_covers_every_ipv4_address_and_nothing_else() -> None:
    assert _trusts(["::ffff:0:0/96"], "198.51.100.1")
    assert _trusts(["::ffff:0:0/96"], "::ffff:198.51.100.1")
    assert not _trusts(["::ffff:0:0/96"], "2001:db8::1")


def test_a_mapped_host_address_is_trusted_as_its_ipv4_address() -> None:
    assert _trusts([ip_address("::ffff:10.0.0.1")], "10.0.0.1")
    assert _trusts(["::ffff:10.0.0.1"], "::ffff:10.0.0.1")
    assert not _trusts(["::ffff:10.0.0.1"], "10.0.0.2")


def test_ipv4_networks_never_cover_ipv6_addresses_holding_the_same_bits() -> None:
    assert not _trusts(["0.0.0.0/0"], "::a00:1")
    assert not _trusts([IPv4Network("0.0.0.0/0")], "2001:db8::1")


def test_networks_with_host_bits_are_widened_to_their_network() -> None:
    assert _trusts(["10.9.9.9/8"], "10.0.0.1")
    assert _trusts(["2001:db8::5/32"], "2001:db8:ffff::1")


def test_the_same_rules_apply_to_forwarded_entries() -> None:
    header = f"for={SPOOF}, for=203.0.113.9"
    client = client_from_forwarded(header, "10.0.0.1", trusted=["::/0", "10.0.0.0/8"])
    assert client is not None and str(client.node) == "203.0.113.9" and client.proxies == 1


@pytest.mark.parametrize("item", ["not a network", "10.0.0.0/33", "::/129", "10.0.0.0/8/8", ""])
def test_entries_that_are_not_networks_raise_value_error(item: str) -> None:
    with pytest.raises(ValueError, match="cannot trust"):
        client_from_x_forwarded(SPOOF, "10.0.0.1", trusted=[item])


@pytest.mark.parametrize(
    "item",
    [10, 10**5000, b"10.0.0.0/8", None, ("10.0.0.0", 8)],
    ids=["int", "huge", "bytes", "none", "tuple"],
)
def test_entries_of_the_wrong_type_raise_type_error(item: object) -> None:
    with pytest.raises(TypeError, match="cannot trust"):
        client_from_x_forwarded(SPOOF, "10.0.0.1", trusted=[item])  # type: ignore[list-item]


def test_messages_about_trusted_entries_stay_short() -> None:
    with pytest.raises(ValueError) as caught:
        client_from_x_forwarded(SPOOF, "10.0.0.1", trusted=["x" * 1_000_000])
    assert len(str(caught.value)) < 200


def test_a_trusted_peer_with_a_zone_matches_its_network() -> None:
    peer = IPv6Address("fe80::1%eth0")
    client = client_from_x_forwarded(SPOOF, peer, trusted=["fe80::/10"])
    assert client is not None and client.proxies == 1
    client = client_from_x_forwarded(SPOOF, "[fe80::1%eth0]:443", trusted=["fe80::/10"])
    assert client is not None and client.proxies == 1
