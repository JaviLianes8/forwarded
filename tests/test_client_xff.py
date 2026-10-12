"""Client resolution from X-Forwarded-*; hand-written from the MDN page, nginx and ProxyFix.

The selection rules (trusted proxy list searched from the right, trusted proxy count) are
MDN's; ports and the leftmost fallback follow nginx's realip module; the N-th value from
the right for X-Forwarded-Proto and X-Forwarded-Host follows Werkzeug's ProxyFix. Sources
are listed in IMPROVEMENTS-round.md.
"""

from __future__ import annotations

from ipaddress import ip_address

import pytest

from forwarded import Client, Node, client_from_x_forwarded

XFF = "203.0.113.195, 2001:db8:85a3:8d3:1319:8a2e:370:7348, 198.51.100.178"


def _ip(client: Client | None) -> str | None:
    return None if client is None else str(client.node)


def test_trusted_list_skips_proxies_from_the_right() -> None:
    trusted = ["10.0.0.0/8", "198.51.100.0/24"]
    assert _ip(client_from_x_forwarded(XFF, "10.0.0.1", trusted=trusted)) == (
        "[2001:db8:85a3:8d3:1319:8a2e:370:7348]"
    )
    trusted.append("2001:db8::/32")
    assert _ip(client_from_x_forwarded(XFF, "10.0.0.1", trusted=trusted)) == "203.0.113.195"


def test_trusted_count_takes_the_entry_count_minus_one_from_the_right() -> None:
    # One reverse proxy: it added the client, so the rightmost entry is used.
    assert _ip(client_from_x_forwarded(XFF, "10.0.0.1", hops=1)) == "198.51.100.178"
    assert _ip(client_from_x_forwarded(XFF, "10.0.0.1", hops=3)) == "203.0.113.195"
    assert client_from_x_forwarded(XFF, "10.0.0.1", hops=4) is None


def test_an_untrusted_peer_ignores_the_header() -> None:
    client = client_from_x_forwarded(XFF, "192.0.2.1", trusted=["10.0.0.0/8"], proto="https")
    assert client == Client(Node(ip=ip_address("192.0.2.1")))


def test_entries_with_ports_are_read() -> None:
    header = "192.0.2.1:4711, [2001:db8::1]:443"
    assert _ip(client_from_x_forwarded(header, "10.0.0.1", hops=1)) == "[2001:db8::1]:443"
    assert _ip(client_from_x_forwarded(header, "10.0.0.1", hops=2)) == "192.0.2.1:4711"


def test_when_everything_is_trusted_the_leftmost_entry_is_the_client() -> None:
    client = client_from_x_forwarded("10.0.0.3, 10.0.0.2", "10.0.0.1", trusted=["10.0.0.0/8"])
    assert _ip(client) == "10.0.0.3"


@pytest.mark.parametrize("garbage", ["evil", "", "unknown", "_x", "1.2.3.4.5", "10.0.0.1 10.0.0.2"])
def test_a_spoofed_value_left_of_the_client_is_never_used(garbage: str) -> None:
    header = f"{garbage}, 192.0.2.43"
    assert _ip(client_from_x_forwarded(header, "10.0.0.1", trusted=["10.0.0.0/8"])) == "192.0.2.43"


@pytest.mark.parametrize("garbage", ["evil", "1.2.3.4.5", "[::1", "10.0.0.1 10.0.0.2"])
def test_a_value_that_is_not_an_address_at_the_boundary_gives_none(garbage: str) -> None:
    header = f"192.0.2.43, {garbage}"
    assert client_from_x_forwarded(header, "10.0.0.1", trusted=["10.0.0.0/8"]) is None


def test_node_identifiers_at_the_boundary_are_returned_not_trusted() -> None:
    client = client_from_x_forwarded("192.0.2.43, unknown", "10.0.0.1", trusted=["0.0.0.0/0"])
    assert client is not None and client.node.unknown


def test_several_lines_are_one_list() -> None:
    lines = ["192.0.2.43", "10.0.0.5"]
    assert _ip(client_from_x_forwarded(lines, "10.0.0.1", trusted=["10.0.0.0/8"])) == "192.0.2.43"


def test_proto_and_host_take_the_value_of_the_first_trusted_proxy() -> None:
    client = client_from_x_forwarded(
        "192.0.2.43, 10.0.0.5",
        "10.0.0.1",
        proto="https, http",
        host=["shop.example", "internal:8080"],
        trusted=["10.0.0.0/8"],
    )
    assert client == Client(Node(ip=ip_address("192.0.2.43")), "https", "shop.example", 2)


def test_a_single_proto_from_the_only_proxy() -> None:
    client = client_from_x_forwarded("192.0.2.43", "10.0.0.1", proto="https", hops=1)
    assert client is not None and client.proto == "https" and client.proxies == 1


def test_fewer_proto_values_than_proxies_give_none() -> None:
    client = client_from_x_forwarded(
        "192.0.2.43, 10.0.0.5", "10.0.0.1", proto="http", host="", trusted=["10.0.0.0/8"]
    )
    assert client is not None and (client.proto, client.host) == (None, None)


def test_more_proto_values_than_proxies_use_the_nth_from_the_right() -> None:
    client = client_from_x_forwarded("192.0.2.43", "10.0.0.1", proto="gopher, https", hops=1)
    assert client is not None and client.proto == "https"


def test_without_a_header_the_peer_is_the_client() -> None:
    assert _ip(client_from_x_forwarded(None, "10.0.0.1", trusted=["10.0.0.0/8"])) == "10.0.0.1"
    assert _ip(client_from_x_forwarded("", "10.0.0.1", trusted=["10.0.0.0/8"])) == "10.0.0.1"


def test_bad_arguments_raise() -> None:
    with pytest.raises(ValueError, match="not both"):
        client_from_x_forwarded(None, "10.0.0.1", trusted=["10.0.0.1"], hops=1)
    with pytest.raises(ValueError, match="not an IP address"):
        client_from_x_forwarded(None, "localhost")
