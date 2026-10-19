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


def test_proto_and_host_default_to_the_rightmost_value() -> None:
    client = client_from_x_forwarded(
        "192.0.2.43, 10.0.0.5", "10.0.0.1", proto="http", host="shop.example", hops=2
    )
    assert client == Client(Node(ip=ip_address("192.0.2.43")), "http", "shop.example", 2)


def test_a_host_written_by_the_client_is_not_used() -> None:
    # Only the edge proxy sets X-Forwarded-Host; the client sent the first value itself.
    client = client_from_x_forwarded(
        "203.0.113.5, 10.0.0.7",
        "10.0.0.2",
        host="evil.example, shop.example",
        trusted=["10.0.0.0/8"],
    )
    assert client is not None and client.host == "shop.example"


def test_proto_and_host_have_their_own_counts() -> None:
    client = client_from_x_forwarded(
        "192.0.2.43, 10.0.0.5",
        "10.0.0.1",
        proto="https, http",
        host=["shop.example", "internal:8080"],
        trusted=["10.0.0.0/8"],
        proto_hops=2,
        host_hops=2,
    )
    assert client == Client(Node(ip=ip_address("192.0.2.43")), "https", "shop.example", 2)


def test_proto_and_host_counts_are_independent() -> None:
    client = client_from_x_forwarded(
        "192.0.2.43, 10.0.0.5", "10.0.0.1", proto="a, b", host="c, d", hops=2, host_hops=2
    )
    assert client is not None and (client.proto, client.host) == ("b", "c")


def test_a_count_beyond_the_trusted_proxies_gives_none() -> None:
    client = client_from_x_forwarded(
        "192.0.2.43", "10.0.0.1", proto="evil, https", hops=1, proto_hops=2
    )
    assert client is not None and client.proto is None


def test_fewer_values_than_the_count_give_none() -> None:
    client = client_from_x_forwarded(
        "192.0.2.43, 10.0.0.5", "10.0.0.1", proto="http", host="", hops=2, proto_hops=2
    )
    assert client is not None and (client.proto, client.host) == (None, None)


def test_an_untrusted_peer_gives_no_proto() -> None:
    client = client_from_x_forwarded("192.0.2.43", "10.0.0.1", proto="https", hops=0)
    assert client is not None and client.proto is None


def test_without_a_header_the_peer_is_the_client() -> None:
    assert _ip(client_from_x_forwarded(None, "10.0.0.1", trusted=["10.0.0.0/8"])) == "10.0.0.1"
    assert _ip(client_from_x_forwarded("", "10.0.0.1", trusted=["10.0.0.0/8"])) == "10.0.0.1"


def test_bad_arguments_raise() -> None:
    with pytest.raises(ValueError, match="not both"):
        client_from_x_forwarded(None, "10.0.0.1", trusted=["10.0.0.1"], hops=1)
    with pytest.raises(ValueError, match="not an IP address"):
        client_from_x_forwarded(None, "localhost")
    for name in ("proto_hops", "host_hops"):
        with pytest.raises(ValueError, match="at least 1"):
            client_from_x_forwarded(None, "10.0.0.1", **{name: 0})  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            client_from_x_forwarded(None, "10.0.0.1", **{name: True})  # type: ignore[arg-type]


@pytest.mark.parametrize("name", ["proto", "host"])
@pytest.mark.parametrize(
    ("value", "message"),
    [
        (5, "{name} must be str or an iterable of str, not int"),
        (b"x", "{name} must be str or an iterable of str, not bytes"),
        (bytearray(b"x"), "{name} must be str or an iterable of str, not bytearray"),
        ([b"x"], "{name} lines must be str, not bytes"),
    ],
)
def test_a_proto_or_host_of_the_wrong_type_names_the_argument(
    name: str, value: object, message: str
) -> None:
    with pytest.raises(TypeError, match=f"^{message.format(name=name)}$"):
        client_from_x_forwarded("192.0.2.43", "10.0.0.1", **{name: value})  # type: ignore[arg-type]


def test_an_x_forwarded_for_of_the_wrong_type_names_the_argument() -> None:
    with pytest.raises(
        TypeError, match=r"^x_forwarded_for must be str or an iterable of str, not int$"
    ):
        client_from_x_forwarded(5, "10.0.0.1")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match=r"^x_forwarded_for lines must be str, not int$"):
        client_from_x_forwarded([5], "10.0.0.1")  # type: ignore[list-item]
