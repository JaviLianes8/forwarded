"""X-Forwarded-* parsing and the RFC 7239 section 7.4 conversion; hand-written cases."""

from __future__ import annotations

import pytest

from forwarded import convert_x_forwarded_for, parse, parse_x_forwarded


def test_values_are_split_and_trimmed() -> None:
    assert parse_x_forwarded(" 203.0.113.195 ,2001:db8::1,\t198.51.100.178 ") == [
        "203.0.113.195",
        "2001:db8::1",
        "198.51.100.178",
    ]


def test_several_lines_form_one_list_in_order() -> None:
    assert parse_x_forwarded(["192.0.2.1, 192.0.2.2", "192.0.2.3"]) == [
        "192.0.2.1",
        "192.0.2.2",
        "192.0.2.3",
    ]


def test_empty_values_and_lines_are_dropped() -> None:
    assert parse_x_forwarded(["", " , ,a,,", "b"]) == ["a", "b"]
    assert parse_x_forwarded("") == []


def test_values_are_not_checked() -> None:
    assert parse_x_forwarded("https, not an ip") == ["https", "not an ip"]


def test_non_str_lines_are_rejected() -> None:
    with pytest.raises(TypeError):
        parse_x_forwarded([None])  # type: ignore[list-item]


def test_conversion_brackets_and_quotes_bare_ipv6() -> None:
    assert convert_x_forwarded_for("192.0.2.43, 2001:DB8:cafe::17") == (
        'for=192.0.2.43, for="[2001:db8:cafe::17]"'
    )


def test_conversion_keeps_ports() -> None:
    assert convert_x_forwarded_for("192.0.2.1:4711, [2001:db8::1]:80") == (
        'for="192.0.2.1:4711", for="[2001:db8::1]:80"'
    )


def test_conversion_keeps_node_identifiers() -> None:
    assert convert_x_forwarded_for("unknown, _hidden") == "for=unknown, for=_hidden"


@pytest.mark.parametrize("entry", ["not an ip", "999.1.1.1", "fe80::1%eth0", '"', "a=b;c"])
def test_conversion_writes_unknown_for_entries_that_are_not_nodes(entry: str) -> None:
    assert convert_x_forwarded_for(f"192.0.2.1, {entry}, 192.0.2.2") == (
        "for=192.0.2.1, for=unknown, for=192.0.2.2"
    )


def test_conversion_output_passes_the_strict_parser() -> None:
    header = convert_x_forwarded_for(["2001:db8::1, junk", "192.0.2.1:80"])
    assert len(parse(header, strict=True)) == 3


def test_conversion_of_nothing_is_empty() -> None:
    assert convert_x_forwarded_for([]) == ""
