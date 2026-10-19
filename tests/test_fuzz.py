"""Seeded fuzzing of every public function: only the documented errors, short messages, and
time that grows linearly with the input.

The inputs come from the hand-written generators in tests/generators.py and
tests/addresses.py; the seeds are fixed so a failure always reproduces.
"""

from __future__ import annotations

import random
import time
from collections.abc import Callable

import pytest
from addresses import address, networks, spelled
from generators import NOISE, damage, header_text, node_text, pick

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


def _noise(rng: random.Random, size: int) -> str:
    return "".join(pick(rng, NOISE) for _ in range(size))


def _xff(rng: random.Random) -> str:
    entries = [spelled(rng, address(rng, mapped=True)) for _ in range(rng.randint(0, 5))]
    entries += [node_text(rng) for _ in range(rng.randint(0, 2))]
    rng.shuffle(entries)
    text = pick(rng, [",", ", ", " ,\t"]).join(entries)
    return damage(rng, text) if rng.random() < 0.3 else text


def test_parsers_return_or_raise_forwarded_error_only() -> None:
    rng = random.Random(1907)
    for _ in range(20000):
        text = header_text(rng) if rng.random() < 0.8 else _noise(rng, rng.randint(0, 40))
        elements = parse(text)
        assert all(isinstance(e, dict) for e in elements)
        assert all(
            isinstance(k, str) and isinstance(v, str) for e in elements for k, v in e.items()
        )
        try:
            assert parse(text, strict=True) == elements
        except ForwardedError as error:
            assert error.position is None or 0 <= error.position <= len(text)
            assert len(str(error)) < 200
        assert isinstance(parse_x_forwarded(text), list)
        assert convert_x_forwarded_for(text) == "" or parse(
            convert_x_forwarded_for(text), strict=True
        )


def test_nodes_parse_print_and_parse_back() -> None:
    rng = random.Random(6)
    for _ in range(20000):
        text = node_text(rng) if rng.random() < 0.8 else _noise(rng, rng.randint(0, 12))
        try:
            node = parse_node(text)
        except ForwardedError as error:
            assert len(str(error)) < 200
            continue
        assert parse_node(str(node)) == node
        assert parse([build([{"for": node}])], strict=True) == [{"for": str(node)}]


def test_build_writes_what_strict_parsing_reads_back() -> None:
    rng = random.Random(7239)
    for _ in range(10000):
        pairs = {pick(rng, ["for", "by", "host", "proto", "x", "Ext-1"]): None for _ in range(3)}
        element = {}
        for name in pairs:
            element[name] = _noise(rng, rng.randint(0, 6)) if rng.random() < 0.5 else node_text(rng)
        try:
            header = build([element])
        except ForwardedError as error:
            assert len(str(error)) < 200
            continue
        assert parse(header, strict=True) == [{k.lower(): v for k, v in element.items()}]


def test_client_resolution_returns_a_client_from_the_chain_or_none() -> None:
    rng = random.Random(208)
    for _ in range(10000):
        trusted = networks(rng, mapped=True)
        peer = str(address(rng, mapped=True))
        xff = _xff(rng)
        client = client_from_x_forwarded(xff, peer, trusted=trusted)
        if client is not None:
            assert 0 <= client.proxies <= len(parse_x_forwarded(xff))
        header = convert_x_forwarded_for(xff)
        hops = rng.choice([None, 0, 1, 2, 5])
        kwargs = {"hops": hops} if hops is not None else {"trusted": trusted}
        found = client_from_forwarded(header, peer, **kwargs)  # type: ignore[arg-type]
        assert found is None or found.proxies <= len(parse(header))


def _seconds(call: Callable[[], object]) -> float:
    best = float("inf")
    for _ in range(3):
        start = time.perf_counter()
        call()
        best = min(best, time.perf_counter() - start)
    return best


HOSTILE = [
    'x="',
    'x="a,',
    "for=",
    ";",
    ",",
    '"\\',
    "for=[::1",
    " \t",
    "a=b;" * 3,
    "\x00\xff",
]


@pytest.mark.parametrize("unit", HOSTILE)
def test_every_parser_runs_in_linear_time(unit: str) -> None:
    small, large = unit * 20_000, unit * 80_000
    for function in (parse, parse_x_forwarded, convert_x_forwarded_for):
        ratio = _seconds(lambda f=function: f(large)) / max(
            _seconds(lambda f=function: f(small)), 1e-4
        )
        assert ratio < 12, (function.__name__, unit, ratio)
    for text in (small, large):
        with pytest.raises(ForwardedError) as caught:
            parse_node(text)
        assert len(str(caught.value)) < 200


def test_a_long_chain_walks_in_linear_time() -> None:
    small = ", ".join(["10.0.0.1"] * 20_000)
    large = ", ".join(["10.0.0.1"] * 80_000)
    walk = client_from_x_forwarded

    def run(xff: str) -> Callable[[], object]:
        return lambda: walk(xff, "10.0.0.2", trusted=["10.0.0.0/8"])

    assert _seconds(run(large)) / max(_seconds(run(small)), 1e-4) < 12
