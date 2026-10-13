"""Strict mode follows the RFC 7239 grammar; the cases are written by hand from sections 4-6."""

from __future__ import annotations

import pytest

from forwarded import ForwardedError, parse


@pytest.mark.parametrize(
    "header",
    [
        "for=192.0.2.60",
        'for="[2001:db8:cafe::17]:4711";by=_proxy;proto=https;host="example.com:8080"',
        "for=unknown, for=UNKNOWN, for=_a.b-c_d",
        'for="unknown:_port"',
        "for=_a;;proto=http;",
        "for=_a , ,for=_b ,",
        "for=192.0.2.1; ,by=192.0.2.2",
        "for=_a;	",
        "\tfor=_a",
        "ext=anything;for=_a",
        'host=""',
        'host="[v1.fe]:80"',
        "proto=coap+tcp",
    ],
)
def test_valid_headers_parse(header: str) -> None:
    assert parse(header, strict=True) == parse(header)


@pytest.mark.parametrize(
    ("header", "position"),
    [
        ("for=_a; proto=http", 7),
        ("for=_a ;proto=http", 7),
        ("for =_a", 0),
        ("for= _a", 4),
        ("for=[::1]", 4),
        ("for=_a;for=_b", 11),
        ('for="_a"x', 8),
        ('for="_a', 4),
        ('note="a\x00b"', 7),
        ('note="a\\\x00"', 8),
        ("note=\xe9", 5),
        ("=x", 0),
        ("for=_a junk", 7),
    ],
)
def test_grammar_errors_raise_with_their_offset(header: str, position: int) -> None:
    with pytest.raises(ForwardedError) as caught:
        parse(header, strict=True)
    assert caught.value.position == position
    assert f"at offset {position}" in str(caught.value)


@pytest.mark.parametrize("header", ["", ",", " , ,", ";", ";;, ;"])
def test_a_header_without_parameters_raises(header: str) -> None:
    with pytest.raises(ForwardedError, match="at least one"):
        parse(header, strict=True)


@pytest.mark.parametrize(
    "header",
    [
        'for="2001:db8::1"',
        "for=example",
        'for="192.0.2.1:"',
        'for="192.0.2.1:123456"',
        'for="192.0.2.1:_"',
        'for="[2001:db8::1"',
        'for="[fe80::1%eth0]"',
        "for=192.0.2.256",
        "for=01.2.3.4",
        "by=_",
        "by=unknow",
        'host="a b"',
        'host="a:8o"',
        'host="[nope]"',
        "proto=1http",
        "proto=-",
    ],
)
def test_registered_values_of_the_wrong_syntax_raise(header: str) -> None:
    with pytest.raises(ForwardedError):
        parse(header, strict=True)


def test_value_errors_point_at_the_value() -> None:
    with pytest.raises(ForwardedError) as caught:
        parse("proto=http;for=nope", strict=True)
    assert caught.value.position == 15


def test_lenient_mode_returns_the_same_values_strict_mode_rejects() -> None:
    assert parse('for="2001:db8::1"') == [{"for": "2001:db8::1"}]


def test_strict_errors_are_value_errors() -> None:
    with pytest.raises(ValueError):
        parse("for=_a;for=_b", strict=True)


def test_strict_mode_checks_every_line() -> None:
    with pytest.raises(ForwardedError):
        parse(["for=_a", "for=bad value"], strict=True)
