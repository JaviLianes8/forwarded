"""Check the library against RFC 7239, RFC 9110, RFC 3986 and MDN, read from the pinned files.

The files are not committed (URL, size and sha256 in tests/upstream/MANIFEST.json); the
tests that read them skip until `python scripts/fetch_upstream.py` has fetched them.
"""

from __future__ import annotations

import re
import string

import pytest

from forwarded import (
    ForwardedError,
    build,
    client_from_x_forwarded,
    convert_x_forwarded_for,
    parse,
    parse_node,
    parse_x_forwarded,
)

# The four examples of RFC 7239 section 4 with the elements they carry, copied from
# https://www.rfc-editor.org/rfc/rfc7239.txt (section 4, "Examples").
SECTION_4 = {
    'for="_gazonk"': [{"for": "_gazonk"}],
    'For="[2001:db8:cafe::17]:4711"': [{"for": "[2001:db8:cafe::17]:4711"}],
    "for=192.0.2.60;proto=http;by=203.0.113.43": [
        {"for": "192.0.2.60", "proto": "http", "by": "203.0.113.43"}
    ],
    "for=192.0.2.43, for=198.51.100.17": [{"for": "192.0.2.43"}, {"for": "198.51.100.17"}],
}


def _forwarded_lines(rfc7239: str) -> list[str]:
    return re.findall(r"^ +Forwarded: (.+)$", rfc7239, flags=re.MULTILINE)


def _section(text: str, title: str, end: str) -> str:
    """The body of a section: its last heading (the first is in the contents) to ``end``."""
    return text.rsplit(title, 1)[1].split(end, 1)[0]


def _abnf_chars(rule: str) -> set[str]:
    """The characters a hand-copied ABNF alternation names: quoted literals, ALPHA, DIGIT."""
    chars = set(re.findall(r'"(.)"', rule))
    if "ALPHA" in rule:
        chars |= set(string.ascii_letters)
    if "DIGIT" in rule:
        chars |= set(string.digits)
    return chars


def test_the_section_4_examples_are_in_the_fetched_rfc(rfc7239: str) -> None:
    assert _forwarded_lines(rfc7239)[:4] == list(SECTION_4)


@pytest.mark.parametrize(("header", "expected"), SECTION_4.items())
def test_the_section_4_examples_parse_to_their_elements(header: str, expected: object) -> None:
    assert parse(header, strict=True) == expected


def test_every_forwarded_example_in_the_rfc_passes_the_strict_parser(rfc7239: str) -> None:
    lines = _forwarded_lines(rfc7239)
    assert len(lines) == 10
    for line in lines:
        assert parse(line, strict=True), line


def test_the_http_list_forms_of_section_7_1_are_equivalent(rfc7239: str) -> None:
    lines = _forwarded_lines(_section(rfc7239, "7.1.  HTTP Lists", "7.2.  "))
    assert len(lines) == 4
    joined, spaced, *split = lines
    assert parse(joined) == parse(spaced) == parse(split)
    assert [str(parse_node(e["for"])) for e in parse(split)] == [
        "192.0.2.43",
        "[2001:db8:cafe::17]",
        "unknown",
    ]


def test_the_transition_example_of_section_7_4(rfc7239: str) -> None:
    section = _section(rfc7239, "7.4.  Transition", "7.5.  ")
    (xff,) = re.findall(r"^ +X-Forwarded-For: (.+)$", section, flags=re.MULTILINE)
    (forwarded,) = _forwarded_lines(section)
    assert convert_x_forwarded_for(xff) == forwarded


def test_the_proxy_chain_of_section_7_5(rfc7239: str) -> None:
    section = " ".join(_section(rfc7239, "7.5.  Example Usage", "8.  ").split())
    header = re.findall(r'"Forwarded: ([^"]+)" header field', section)[-1]
    assert header == "for=192.0.2.43, for=198.51.100.17;by=203.0.113.60;proto=http;host=example.com"
    first, second = parse(header, strict=True)
    assert first == {"for": "192.0.2.43"}
    assert second["by"] == "203.0.113.60" and second["host"] == "example.com"


def test_the_node_examples_of_section_6(rfc7239: str) -> None:
    section = _section(rfc7239, "6.  Node Identifiers", "6.1.  ")
    examples = re.findall(r'^ +"([^"]+)"$', section, flags=re.MULTILINE)
    assert examples == ["192.0.2.43:47011", "[2001:db8:cafe::17]:47011"]
    assert [str(parse_node(example)) for example in examples] == examples


def test_obfuscated_names_and_ports_use_the_rfc_alphabet(rfc7239: str) -> None:
    (obfnode,) = re.findall(r"obfnode = (.+)", rfc7239)
    (obfport,) = re.findall(r"obfport += (.+)", rfc7239)
    allowed = _abnf_chars(obfnode.removeprefix('"_"'))
    assert allowed == _abnf_chars(obfport.removeprefix('"_"'))
    for code in range(0x21, 0x7F):
        char = chr(code)
        for text in (f"_{char}", f"unknown:_{char}"):
            try:
                parse_node(text)
            except ForwardedError:
                assert char not in allowed, text
            else:
                assert char in allowed, text


def test_parameter_names_are_exactly_the_rfc_9110_tokens(rfc9110: str) -> None:
    rule = rfc9110.split("tchar          =", 1)[1].split("; any VCHAR", 1)[0]
    tchar = _abnf_chars(rule)
    assert len(tchar) == 77
    for code in range(0x100):
        char = chr(code)
        try:
            build([{char: "x"}])
        except ForwardedError:
            assert char not in tchar, repr(char)
        else:
            assert char in tchar, repr(char)


def test_quoted_strings_accept_exactly_the_rfc_9110_qdtext(rfc9110: str) -> None:
    rule = re.findall(r"qdtext +=(.+)", rfc9110)[0]
    assert rule.split() == "HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text".split()
    qdtext = {9, 32, 0x21, *range(0x23, 0x5C), *range(0x5D, 0x7F), *range(0x80, 0x100)}
    for code in range(0x180):
        try:
            parse(f'note="{chr(code)}"', strict=True)
        except ForwardedError:
            assert code not in qdtext, hex(code)
        else:
            assert code in qdtext, hex(code)


def test_proto_follows_the_rfc_3986_scheme_rule(rfc3986: str) -> None:
    rule = re.findall(r"scheme += (.+)", rfc3986)[0]
    first, rest = rule.split(" *", 1)
    assert first == "ALPHA"
    tail = _abnf_chars(rest)
    for code in range(0x21, 0x7F):
        char = chr(code)
        for text, valid in ((f"a{char}", char in tail), (char, char in string.ascii_letters)):
            try:
                parse(f'proto="{text}"', strict=True)
            except ForwardedError:
                assert not valid, text
            else:
                assert valid, text


def test_the_mdn_header_examples_are_read(mdn_xff: str) -> None:
    lines = re.findall(r"^X-Forwarded-For: ([0-9a-f.:, ]+)$", mdn_xff, flags=re.MULTILINE)
    assert len(lines) == 4
    for line in lines:
        assert len(parse(convert_x_forwarded_for(line), strict=True)) == len(
            parse_x_forwarded(line)
        )


def test_the_mdn_client_and_proxy_example(mdn_xff: str) -> None:
    section = mdn_xff.split("### Client and proxy IPs", 1)[1]
    (line,) = re.findall(r"^X-Forwarded-For: (.+)$", section, flags=re.MULTILINE)
    trusted = ["10.0.0.1", "2001:db8::/32", "198.51.100.0/24"]
    client = client_from_x_forwarded(line, "10.0.0.1", trusted=trusted)
    assert client is not None and str(client.node) == "203.0.113.195"
    assert client.proxies == 3
