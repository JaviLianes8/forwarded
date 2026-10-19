"""forwarded against forwarded-parse 2.1.2 and proxy-addr 2.0.8, run live under Node.js.

proxy-addr 2.0.8 is the release that fixed CVE-2026-90711: an IPv6 trust network covers
IPv4 addresses only when it is a genuine IPv4-mapped network. The trust checks here compare
that rule address by address. Install the packages with
`npm install --prefix tests/upstream forwarded-parse@2.1.2 proxy-addr@2.0.8`; the tests
skip without Node.js or the packages.
"""

from __future__ import annotations

import json
import random
import shutil
import subprocess
from collections.abc import Callable
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from pathlib import Path
from typing import Any

import pytest
from addresses import address, spelled
from generators import header_text

from forwarded import client_from_x_forwarded, parse

HERE = Path(__file__).resolve().parent
PINNED = {"forwarded-parse": "2.1.2", "proxy-addr": "2.0.8"}
Ask = Callable[[list[dict[str, Any]]], list[dict[str, Any]]]


@pytest.fixture(scope="module")
def node() -> Ask:
    program = shutil.which("node")
    if program is None:
        pytest.skip("Node.js is not installed")
    for name, version in PINNED.items():
        manifest = HERE / "upstream" / "node_modules" / name / "package.json"
        if not manifest.is_file():
            pytest.skip(f"npm install --prefix tests/upstream {name}@{version}")
        assert json.loads(manifest.read_text(encoding="utf-8"))["version"] == version

    def ask(requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
        payload = "".join(json.dumps(request) + "\n" for request in requests)
        done = subprocess.run(
            [str(program), str(HERE / "node_oracle.js")],
            input=payload,
            capture_output=True,
            encoding="utf-8",
            check=True,
            timeout=240,
        )
        answers = [json.loads(line) for line in done.stdout.splitlines()]
        assert len(answers) == len(requests)
        return answers

    return ask


def test_headers_forwarded_parse_accepts_are_read_the_same(node: Ask) -> None:
    rng = random.Random(2122)
    headers = [header_text(rng) for _ in range(30000)]
    answers = node([{"op": "parse", "header": header} for header in headers])
    accepted = 0
    for header, answer in zip(headers, answers, strict=True):
        if "ok" in answer:
            assert parse(header) == answer["ok"], ascii(header)
            accepted += 1
    assert accepted > 1200, accepted


def _subnet(rng: random.Random) -> str:
    """A trust entry in proxy-addr notation: no /0, no IPv4-mapped prefix under 96."""
    roll = rng.random()
    if roll < 0.3:
        return f"{IPv4Address(rng.getrandbits(32))}/{rng.randint(1, 32)}"
    if roll < 0.55:
        network = IPv6Address(rng.getrandbits(128) >> rng.choice([0, 64, 100]))
        return f"{network}/{rng.randint(1, 128)}"
    if roll < 0.7:
        return f"::ffff:{IPv4Address(rng.getrandbits(32))}/{rng.randint(96, 128)}"
    if roll < 0.85:
        return rng.choice(["::/1", "::/8", "::/64", "::/80", "::/95", "::ffff:0:0/96", "8000::/1"])
    return str(address(rng, mapped=True))


def _candidate(rng: random.Random, subnets: list[str]) -> IPv4Address | IPv6Address:
    if rng.random() < 0.4:
        return address(rng, mapped=True)
    network = ip_network(rng.choice(subnets), strict=False)
    found = network[rng.randrange(min(network.num_addresses, 2**64))]
    if isinstance(found, IPv6Address) and found.ipv4_mapped is not None and rng.random() < 0.5:
        return found.ipv4_mapped
    return found


def test_trust_matches_proxy_addr_address_by_address(node: Ask) -> None:
    rng = random.Random(90711)
    cases = []
    for _ in range(20000):
        subnets = [_subnet(rng) for _ in range(rng.randint(1, 3))]
        cases.append((subnets, _candidate(rng, subnets)))
    answers = node([{"op": "trust", "trust": s, "addr": str(a)} for s, a in cases])
    trusted = 0
    for (subnets, candidate), answer in zip(cases, answers, strict=True):
        client = client_from_x_forwarded("unknown", candidate, trusted=subnets)
        assert client is not None
        assert (client.proxies == 1) == answer["ok"], (subnets, str(candidate))
        trusted += answer["ok"]
    assert 5000 < trusted < 15000, trusted


def test_trust_walks_match_proxy_addr(node: Ask) -> None:
    rng = random.Random(208)
    cases = []
    for _ in range(5000):
        subnets = [_subnet(rng) for _ in range(rng.randint(1, 3))]
        entries = [_candidate(rng, subnets) for _ in range(rng.randint(0, 5))]
        xff = rng.choice([",", ", "]).join(spelled(rng, entry) for entry in entries)
        cases.append((subnets, _candidate(rng, subnets), xff))
    answers = node([{"op": "walk", "trust": s, "peer": str(p), "xff": x} for s, p, x in cases])
    for (subnets, peer, xff), answer in zip(cases, answers, strict=True):
        client = client_from_x_forwarded(xff or None, peer, trusted=subnets)
        assert client is not None and client.node.ip == ip_address(answer["ok"]), (subnets, xff)


def test_hop_counts_match_express(node: Ask) -> None:
    rng = random.Random(4)
    cases = []
    for _ in range(3000):
        entries = [address(rng, mapped=True) for _ in range(rng.randint(0, 5))]
        xff = ", ".join(spelled(rng, entry) for entry in entries)
        cases.append((rng.randint(0, 5), address(rng), xff, len(entries)))
    answers = node([{"op": "walk", "trust": n, "peer": str(p), "xff": x} for n, p, x, _ in cases])
    for (hops, peer, xff, count), answer in zip(cases, answers, strict=True):
        client = client_from_x_forwarded(xff or None, peer, hops=hops)
        if hops <= count:
            assert client is not None and client.node.ip == ip_address(answer["ok"]), xff
        else:
            # Express falls back to the leftmost address; forwarded cannot tell, so None.
            assert client is None
