"""Exact type errors for every header argument, and the whitespace that splitting removes."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from forwarded import (
    client_from_forwarded,
    client_from_x_forwarded,
    convert_x_forwarded_for,
    parse,
    parse_x_forwarded,
)

# Falsy values must raise like any other wrong type, not pass for a missing header.
WRONG = [
    (5, "int"),
    (0, "int"),
    (b"", "bytes"),
    (bytearray(), "bytearray"),
    (memoryview(b"x"), "memoryview"),
    (memoryview(b""), "memoryview"),
]

HEADER_TAKERS: list[Callable[[object], object]] = [
    parse,  # type: ignore[list-item]
    lambda header: client_from_forwarded(header, "10.0.0.1"),  # type: ignore[arg-type]
    lambda header: client_from_forwarded(header, "10.0.0.1", hops=0),  # type: ignore[arg-type]
    parse_x_forwarded,  # type: ignore[list-item]
    convert_x_forwarded_for,  # type: ignore[list-item]
]


@pytest.mark.parametrize("take", HEADER_TAKERS)
@pytest.mark.parametrize(("value", "type_name"), WRONG)
def test_a_header_of_the_wrong_type_raises_naming_header(
    take: Callable[[object], object], value: object, type_name: str
) -> None:
    expected = f"^header must be str or an iterable of str, not {type_name}$"
    with pytest.raises(TypeError, match=expected):
        take(value)


@pytest.mark.parametrize("take", HEADER_TAKERS)
def test_a_header_line_of_the_wrong_type_raises_naming_header(
    take: Callable[[object], object],
) -> None:
    with pytest.raises(TypeError, match=r"^header lines must be str, not int$"):
        take([5])


@pytest.mark.parametrize("name", ["x_forwarded_for", "proto", "host"])
@pytest.mark.parametrize(("value", "type_name"), WRONG)
def test_an_x_forwarded_argument_of_the_wrong_type_raises_naming_it(
    name: str, value: object, type_name: str
) -> None:
    arguments: dict[str, object] = {"x_forwarded_for": "192.0.2.43", name: value}
    expected = f"^{name} must be str or an iterable of str, not {type_name}$"
    with pytest.raises(TypeError, match=expected):
        client_from_x_forwarded(remote="10.0.0.1", **arguments)  # type: ignore[arg-type]


OTHER_WHITESPACE = ["\x0b", "\x0c", "\r", "\n", "\xa0", "\u2003"]


@pytest.mark.parametrize("space", OTHER_WHITESPACE)
def test_only_spaces_and_tabs_are_removed_around_values(space: str) -> None:
    assert parse_x_forwarded(f"192.0.2.43{space}, {space}192.0.2.44") == [
        f"192.0.2.43{space}",
        f"{space}192.0.2.44",
    ]


@pytest.mark.parametrize("space", OTHER_WHITESPACE)
def test_an_address_with_other_whitespace_is_not_a_client(space: str) -> None:
    for entry in (f"192.0.2.43{space}", f"{space}192.0.2.43"):
        assert client_from_x_forwarded(entry, "10.0.0.1", trusted=["10.0.0.0/8"]) is None
