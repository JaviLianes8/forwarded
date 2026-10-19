"""IPv6 addresses are written as RFC 5952 says, on every Python version.

The example addresses are cut from RFC 5952 as fetched (tests/upstream/MANIFEST.json).
The random check compares with a text form written here by hand from sections 4 and 5:
mixed notation for IPv4-mapped addresses (section 5), hexadecimal for everything else,
including the other prefixes section 5 allows in mixed notation (RFC 2765's
IPv4-translated ``::ffff:0:0:0/96``), which this library leaves hexadecimal.
"""

from __future__ import annotations

import random
import re
from ipaddress import IPv6Address

from forwarded import Node, build, convert_x_forwarded_for, parse_node


def _prose(rfc5952: str) -> str:
    body = rfc5952.rsplit("4.  A Recommendation for IPv6 Text Representation", 1)[1]
    return " ".join(body.split("6.  Notes on Combining IPv6 Addresses", 1)[0].split())


def _examples(rfc5952: str) -> dict[str, str]:
    """Non-canonical address -> canonical address, as the RFC sentences state them."""
    text = _prose(rfc5952)
    pairs = re.findall(r"(\S+) is not acceptable and must be represented as (\S+?)\.", text)
    pairs += re.findall(r"(\S+) must be shortened to (\S+?)\.", text)
    pairs += re.findall(r"(\S+) is not acceptable, because .*? representation (\S+?)\.", text)
    pairs += [(b, a) for a, b in re.findall(r"representation (\S+) is correct, but (\S+)", text)]
    pairs += re.findall(r"\(i\.e\., (\S+)\), the first .*? For example, (\S+) is correct", text)
    pairs += [(b, a) for a, b in re.findall(r"\(i\.e\., (\S+) instead of (\S+?)\)", text)]
    return dict(pairs)


def test_the_rfc_5952_examples_are_found(rfc5952: str) -> None:
    assert _examples(rfc5952) == {
        "2001:0db8::0001": "2001:db8::1",
        "2001:db8:0:0:0:0:2:1": "2001:db8::2:1",
        "2001:db8::0:1": "2001:db8::1",
        "2001:db8::1:1:1:1:1": "2001:db8:0:1:1:1:1:1",
        "2001:db8:0:0:1:0:0:1": "2001:db8::1:0:0:1",
        "0:0:0:0:0:ffff:192.0.2.1": "::ffff:192.0.2.1",
    }


def test_nodes_write_the_rfc_5952_examples_in_canonical_form(rfc5952: str) -> None:
    for written, canonical in _examples(rfc5952).items():
        assert str(parse_node(f"[{written}]")) == f"[{canonical}]"
        assert str(Node(ip=IPv6Address(written), port=80)) == f"[{canonical}]:80"
        assert build([{"for": parse_node(f"[{written}]")}]) == f'for="[{canonical}]"'
        assert convert_x_forwarded_for(written) == f'for="[{canonical}]"'


def test_upper_case_digits_are_written_in_lower_case(rfc5952: str) -> None:
    assert "MUST be represented in lowercase" in _prose(rfc5952)
    assert str(parse_node("[2001:DB8:ABCD::EF]")) == "[2001:db8:abcd::ef]"


def test_a_port_follows_the_bracketed_address(rfc5952: str) -> None:
    assert "o [2001:db8::1]:80" in " ".join(rfc5952.split())
    assert str(parse_node("[2001:db8::1]:80")) == "[2001:db8::1]:80"


def _rfc5952(packed: bytes) -> str:
    """The text form by RFC 5952 sections 4 and 5, written from the RFC prose."""
    groups = [int.from_bytes(packed[index : index + 2], "big") for index in range(0, 16, 2)]
    if groups[:6] == [0, 0, 0, 0, 0, 0xFFFF]:
        return "::ffff:" + ".".join(str(byte) for byte in packed[12:])
    best, length, index = -1, 1, 0  # the longest run of two or more zeros, the first on a tie
    while index < 8:
        end = index
        while end < 8 and groups[end] == 0:
            end += 1
        if end - index > length:
            best, length = index, end - index
        index = max(end, index + 1)
    digits = [format(group, "x") for group in groups]
    if best < 0:
        return ":".join(digits)
    return ":".join(digits[:best]) + "::" + ":".join(digits[best + length :])


def test_random_addresses_are_written_as_rfc_5952_says() -> None:
    rng = random.Random(5952)
    choices = [0, 0, 0, 0, 1, 0xFFFF, 0xDB8, 0x2001]
    for _ in range(50000):
        groups = [
            rng.choice(choices) if rng.random() < 0.7 else rng.randrange(65536) for _ in range(8)
        ]
        if rng.random() < 0.1:
            groups[:6] = [0, 0, 0, 0, 0, 0xFFFF]
        packed = b"".join(group.to_bytes(2, "big") for group in groups)
        assert str(Node(ip=IPv6Address(packed))) == f"[{_rfc5952(packed)}]", packed.hex()


def test_ipv4_translated_addresses_stay_hexadecimal() -> None:
    # A choice, documented on Node: only IPv4-mapped addresses use mixed notation.
    assert str(parse_node("[::ffff:0:192.0.2.1]")) == "[::ffff:0:c000:201]"
