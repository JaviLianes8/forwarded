"""Text a client controls must not hide or forge what proxies append after it.

Each case is hand-written: the client sends the first part, a proxy appends the second
after a comma, as RFC 7239 section 4 allows, or on a line of its own.
"""

from __future__ import annotations

import pytest

from forwarded import client_from_forwarded, parse

PROXY = ", for=198.51.100.7;proto=https"
APPENDED = {"for": "198.51.100.7", "proto": "https"}

CLIENT_TEXTS = [
    'for=192.0.2.66;x="',
    'for="192.0.2.66',
    'for="192.0.2.66\\',
    'for="a,b',
    'for="a" x="',
    'for="a"junk',
    "for=",
    "for=192.0.2.66;",
    "for=192.0.2.66;y",
    '"',
    '="',
    'x=""',
    '\\"',
    'for="[2001:db8::66]',
]


@pytest.mark.parametrize("client_text", CLIENT_TEXTS)
def test_the_appended_element_survives_whatever_the_client_sent(client_text: str) -> None:
    assert parse(client_text + PROXY)[-1] == APPENDED


@pytest.mark.parametrize("client_text", CLIENT_TEXTS)
def test_the_client_is_the_address_the_proxy_saw(client_text: str) -> None:
    client = client_from_forwarded(client_text + PROXY, "10.0.0.1", trusted=["10.0.0.0/8"])
    assert client is not None
    assert str(client.node) == "198.51.100.7"
    assert client.proto == "https"


def test_a_quote_ending_inside_the_appended_element_does_not_capture_it() -> None:
    header = 'for="x, for="[2001:db8::7]";proto=https'
    assert parse(header)[-1] == {"for": "[2001:db8::7]", "proto": "https"}


def test_a_quote_never_spans_header_lines() -> None:
    assert parse(['for="192.0.2.66', "for=198.51.100.7;proto=https"]) == [APPENDED]


def test_an_unterminated_quote_drops_only_its_own_element() -> None:
    assert parse('for=_a, for=_b;x="c, for=_d') == [{"for": "_a"}, {"for": "_b"}, {"for": "_d"}]


def test_a_forged_trusted_element_inside_quotes_is_not_an_element() -> None:
    header = 'for="10.0.0.9, for=10.0.0.8"' + PROXY
    assert parse(header) == [{"for": "10.0.0.9, for=10.0.0.8"}, APPENDED]
    client = client_from_forwarded(header, "10.0.0.1", trusted=["10.0.0.0/8", "198.51.100.7"])
    assert client is None


def test_scanning_is_linear_in_the_header_length() -> None:
    # A rescan from every quote would be quadratic; 200k quotes must stay fast.
    assert parse('x="' * 200_000 + PROXY)[-1] == APPENDED
    assert parse('x="a,' * 100_000 + PROXY)[-1] == APPENDED
    assert parse('x="\\",' * 100_000 + PROXY)[-1] == APPENDED
    assert parse('x="' + '\\",x=' * 100_000 + '"junk' + PROXY)[-1] == APPENDED
