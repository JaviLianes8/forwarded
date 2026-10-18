"""Strict parsing and node, host and IPv6 syntax against the grammar of the fetched RFCs.

The oracle (grammar.py) is compiled at test time from the ABNF printed in RFC 7239,
RFC 9110 and RFC 3986 as fetched (tests/upstream/MANIFEST.json), so it shares no code
with the library. The inputs come from the hand-written generators in generators.py.
"""

from __future__ import annotations

import random
import re

import pytest
from generators import header_text, host_text, ipv6_text, node_text
from grammar import Grammar, load

from forwarded import ForwardedError, convert_x_forwarded_for, parse, parse_node


@pytest.fixture(scope="module")
def grammar(rfc7239: str, rfc9110: str, rfc3986: str) -> Grammar:
    return load(rfc7239, rfc9110, rfc3986)


def _strict(header: str) -> list[dict[str, str]] | None:
    try:
        return parse(header, strict=True)
    except ForwardedError:
        return None


def test_the_compiled_grammar_accepts_every_example_of_rfc_7239(
    grammar: Grammar, rfc7239: str
) -> None:
    lines = re.findall(r"^ +Forwarded: (.+)$", rfc7239, flags=re.MULTILINE)
    assert len(lines) == 10
    for line in lines:
        assert grammar.strict(line) is not None, line
        assert grammar.strict(line) == parse(line, strict=True)


@pytest.mark.parametrize(
    "header",
    [
        "for=_a; proto=http",
        "for=_a ;proto=http",
        "for=_a;For=_b",
        "for=[2001:db8::1]",
        'for="2001:db8::1"',
        "for=unknown:_port",
        'host="exa mple"',
        "proto=1http",
        'x="unterminated',
        "",
        " , ;",
    ],
)
def test_the_compiled_grammar_refuses_what_the_rfcs_rule_out(grammar: Grammar, header: str) -> None:
    assert grammar.strict(header) is None
    assert _strict(header) is None


@pytest.mark.parametrize("seed", [7239, 9110, 3986])
def test_strict_parsing_accepts_exactly_the_grammar(grammar: Grammar, seed: int) -> None:
    rng = random.Random(seed)
    accepted = 0
    for _ in range(6000):
        header = header_text(rng)
        expected = grammar.strict(header)
        assert _strict(header) == expected, ascii(header)
        accepted += expected is not None
    # Both sides of the boundary are exercised, not just one.
    assert 1500 < accepted < 4500, accepted


def test_node_identifiers_follow_the_rfc_grammar(grammar: Grammar) -> None:
    rng = random.Random(6)
    accepted = 0
    for _ in range(30000):
        text = node_text(rng)
        try:
            node = parse_node(text)
        except ForwardedError:
            assert not grammar.node.fullmatch(text), ascii(text)
            continue
        assert grammar.node.fullmatch(text), ascii(text)
        assert parse_node(str(node)) == node
        accepted += 1
    assert 8000 < accepted < 22000, accepted


def test_host_values_follow_the_rfc_grammar(grammar: Grammar) -> None:
    rng = random.Random(72)
    accepted = 0
    for _ in range(20000):
        text = host_text(rng)
        escaped = text.replace("\\", "\\\\").replace('"', '\\"')
        valid = bool(grammar.host.fullmatch(text))
        assert (_strict(f'host="{escaped}"') is not None) == valid, ascii(text)
        accepted += valid
    assert 6000 < accepted < 18000, accepted


def test_bare_ipv6_entries_follow_the_rfc_3986_grammar(grammar: Grammar) -> None:
    rng = random.Random(4291)
    bracketed = 0
    for _ in range(20000):
        text = ipv6_text(rng)
        converted = convert_x_forwarded_for(text)
        if grammar.node.fullmatch(text):
            continue  # an IPv4 address or a node identifier, read as such
        if grammar.ipv6.fullmatch(text):
            assert converted.startswith('for="[') and converted.endswith(']"'), ascii(text)
            assert parse_node(converted[5:-1]).ip == parse_node(f"[{text}]").ip
            bracketed += 1
        else:
            assert converted == "for=unknown", ascii(text)
    assert bracketed > 5000, bracketed
