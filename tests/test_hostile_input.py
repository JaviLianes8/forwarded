"""Every entry point reads a str subclass as the plain text it holds; messages stay short.

Hand-written: ``Hostile`` overrides the str methods a parser might call, so a function
that used them instead of the plain text would give a different answer.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, SupportsIndex

import pytest

from forwarded import (
    ForwardedError,
    build,
    client_from_forwarded,
    client_from_x_forwarded,
    convert_x_forwarded_for,
    parse,
    parse_node,
    parse_x_forwarded,
)


class Hostile(str):
    def __len__(self) -> int:
        return 3

    def __getitem__(self, key: SupportsIndex | slice) -> str:
        return "_evil"

    def __iter__(self) -> Any:
        return iter("_evil")

    def __str__(self) -> str:
        return "_evil"

    def partition(self, sep: str, /) -> tuple[str, str, str]:
        return ("_evil", "", "")

    def split(self, sep: str | None = None, maxsplit: SupportsIndex = -1) -> Any:
        return ["_evil"]

    def strip(self, chars: str | None = None, /) -> Any:
        return "_evil"

    def lower(self) -> Any:
        return "_evil"

    def startswith(self, *args: object) -> bool:
        return False

    def find(self, *args: object) -> int:
        return -1


H = Hostile

CALLS: list[tuple[str, Callable[[type[str]], object]]] = [
    ("parse one line", lambda s: parse(s("for=192.0.2.43;proto=https"))),
    ("parse lines", lambda s: parse([s("for=192.0.2.43"), s("for=198.51.100.17")])),
    ("parse strict", lambda s: parse(s("for=192.0.2.43"), strict=True)),
    ("parse_node", lambda s: parse_node(s("[2001:db8::1]:80"))),
    ("parse_node ipv4", lambda s: parse_node(s("192.0.2.43"))),
    ("parse_x_forwarded", lambda s: parse_x_forwarded([s("192.0.2.43, 10.0.0.1")])),
    ("convert", lambda s: convert_x_forwarded_for(s("192.0.2.43, 2001:db8::1"))),
    ("build", lambda s: build([{s("For"): s("192.0.2.43"), s("host"): s("a.example")}])),
    (
        "client_from_forwarded",
        lambda s: client_from_forwarded(
            s("for=192.0.2.43;proto=https"), s("10.0.0.2"), trusted=[s("10.0.0.0/8")]
        ),
    ),
    (
        "client_from_x_forwarded",
        lambda s: client_from_x_forwarded(
            s("192.0.2.43"), s("10.0.0.2"), proto=s("https"), trusted=[s("10.0.0.0/8")]
        ),
    ),
]


@pytest.mark.parametrize(("label", "call"), CALLS, ids=[label for label, _ in CALLS])
def test_a_str_subclass_is_read_as_its_plain_text(
    label: str, call: Callable[[type[str]], object]
) -> None:
    assert call(H) == call(str), label


def test_a_huge_type_name_stays_out_of_messages() -> None:
    huge = type("T" * 5000, (), {})()
    for call in (
        lambda: parse(huge),
        lambda: parse_node(huge),
        lambda: build([huge]),
        lambda: client_from_forwarded(None, huge),
        lambda: client_from_forwarded(None, "10.0.0.1", trusted=[huge]),
    ):
        with pytest.raises(TypeError) as caught:
            call()
        assert len(str(caught.value)) < 200


def test_a_huge_parameter_name_stays_out_of_messages() -> None:
    with pytest.raises(ForwardedError) as caught:
        build([{"n" * 5000: "a\x00"}])
    assert len(str(caught.value)) < 200
