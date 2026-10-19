"""forwarded against Werkzeug, uvicorn, Hypercorn and aiohttp, run live on the same input.

Each comparison stays inside the inputs both sides define the same way, as stated next to
it; the differences outside that domain are listed in GUIDE.md. The packages are optional
(`pip install werkzeug==3.1.9 uvicorn==0.54.0 hypercorn==0.18.0 aiohttp==3.14.5`) and
each test skips without its package.
"""

from __future__ import annotations

import random
from collections.abc import Callable, Coroutine
from ipaddress import IPv4Address, ip_address
from typing import Any

import pytest
from addresses import address, chain, networks, spelled, trusted_chain
from generators import TCHAR, pick

from forwarded import client_from_forwarded, client_from_x_forwarded, parse


def _run(call: Coroutine[Any, Any, None]) -> None:
    """Drive an ASGI middleware call to its end; the test apps never wait for anything."""
    with pytest.raises(StopIteration):
        call.send(None)


def _asgi_app(seen: dict[str, Any]) -> Callable[..., Coroutine[Any, Any, None]]:
    async def app(scope: dict[str, Any], receive: object, send: object) -> None:
        seen.update(scope)

    return app


def test_hop_counts_match_werkzeug_proxy_fix() -> None:
    # Domain: X-Forwarded-* values that are addresses, never empty, proto/host counts not
    # above the X-Forwarded-For count (forwarded never takes a value a client could write).
    proxy_fix = pytest.importorskip("werkzeug.middleware.proxy_fix")
    rng = random.Random(15)
    for _ in range(3000):
        hops = rng.randint(1, 4)
        proto_hops, host_hops = rng.randint(1, hops), rng.randint(1, hops)
        values = {
            "HTTP_X_FORWARDED_FOR": [spelled(rng, ip) for ip in chain(rng)],
            "HTTP_X_FORWARDED_PROTO": [
                pick(rng, ["http", "https"]) for _ in range(rng.randint(0, 4))
            ],
            "HTTP_X_FORWARDED_HOST": [
                pick(rng, ["a.example", "b:8080"]) for _ in range(rng.randint(0, 4))
            ],
        }
        environ = {"REMOTE_ADDR": "192.0.2.1", "wsgi.url_scheme": "origin", "HTTP_HOST": "origin"}
        headers = {
            key: pick(rng, [",", ", "]).join(found) for key, found in values.items() if found
        }
        environ.update(headers)
        seen: dict[str, Any] = {}

        def app(env: dict[str, Any], start: object, seen: dict[str, Any] = seen) -> list[bytes]:
            seen.update(env)
            return []

        fix = proxy_fix.ProxyFix(app, x_for=hops, x_proto=proto_hops, x_host=host_hops)
        fix(environ, lambda *args: None)
        client = client_from_x_forwarded(
            headers.get("HTTP_X_FORWARDED_FOR"),
            "192.0.2.1",
            proto=headers.get("HTTP_X_FORWARDED_PROTO"),
            host=headers.get("HTTP_X_FORWARDED_HOST"),
            hops=hops,
            proto_hops=proto_hops,
            host_hops=host_hops,
        )
        if len(values["HTTP_X_FORWARDED_FOR"]) < hops:
            assert client is None and seen["REMOTE_ADDR"] == "192.0.2.1"
            continue
        assert client is not None and client.node.ip == ip_address(seen["REMOTE_ADDR"])
        proto = seen["wsgi.url_scheme"]
        assert client.proto == (None if proto == "origin" else proto)
        assert client.host == (None if seen["HTTP_HOST"] == "origin" else seen["HTTP_HOST"])


def test_trusted_lists_match_uvicorn() -> None:
    # Domain: X-Forwarded-For of bare addresses, strict networks, no IPv4-mapped forms
    # (uvicorn compares them as written; forwarded reads them as the IPv4 address).
    middleware = pytest.importorskip("uvicorn.middleware.proxy_headers")
    rng = random.Random(54)
    for _ in range(3000):
        trusted = networks(rng)
        peer, found = trusted_chain(rng, trusted)
        entries = [spelled(rng, ip) for ip in found] or [str(address(rng))]
        header = pick(rng, [",", ", "]).join(entries)
        seen: dict[str, Any] = {}
        scope = {
            "type": "http",
            "client": (str(peer), 1234),
            "headers": [(b"x-forwarded-for", header.encode())],
        }
        _run(
            middleware.ProxyHeadersMiddleware(_asgi_app(seen), trusted_hosts=trusted)(
                scope, None, None
            )
        )
        client = client_from_x_forwarded(header, peer, trusted=trusted)
        assert client is not None and client.node.ip == ip_address(seen["client"][0]), header


def test_forwarded_hop_counts_match_hypercorn() -> None:
    # Domain: lower-case names, token values, a for in every element (Hypercorn splits on
    # commas and semicolons and reads no quoted-string).
    proxy_fix = pytest.importorskip("hypercorn.middleware.proxy_fix")
    rng = random.Random(18)
    for _ in range(3000):
        hops = rng.randint(1, 4)
        elements = []
        for _ in range(rng.randint(0, 5)):
            node = pick(rng, [str(IPv4Address(rng.getrandbits(32))), "_hidden", "unknown"])
            pairs = [f"for={node}"]
            pairs += [f"proto={pick(rng, ['http', 'https'])}"] if rng.random() < 0.5 else []
            pairs += [f"host={pick(rng, ['a.example', 'b.example'])}"] if rng.random() < 0.5 else []
            rng.shuffle(pairs)
            elements.append(";".join(pairs))
        header = pick(rng, [",", ", "]).join(elements)
        seen: dict[str, Any] = {}
        scope = {
            "type": "http",
            "client": ("192.0.2.1", 1),
            "scheme": "origin",
            "headers": [(b"forwarded", header.encode())],
        }
        _run(proxy_fix.ProxyFixMiddleware(_asgi_app(seen), "modern", hops)(scope, None, None))
        client = client_from_forwarded(header, "192.0.2.1", hops=hops)
        if len(elements) < hops:
            assert client is None and seen["client"] == ("192.0.2.1", 1)
            continue
        assert client is not None and str(client.node) == seen["client"][0]
        assert client.proto == (None if seen["scheme"] == "origin" else seen["scheme"])
        host = dict(seen["headers"]).get(b"host")
        assert client.host == (host.decode() if host is not None else None)


def _valid_line(rng: random.Random) -> str:
    elements = []
    for _ in range(rng.randint(1, 3)):
        names = rng.sample(["for", "by", "host", "proto", "x", "Secret", "n-1"], rng.randint(1, 3))
        pairs = []
        for name in names:
            text = "".join(pick(rng, TCHAR + ' "\\,;=\t') for _ in range(rng.randint(0, 6)))
            if text and all(char in TCHAR for char in text) and rng.random() < 0.5:
                pairs.append(f"{name}={text}")
            else:
                escaped = "".join("\\" + c if c in '"\\' or rng.random() < 0.1 else c for c in text)
                pairs.append(f'{name}="{escaped}"')
        elements.append(";".join(pairs))
    return "".join(
        e if not i else pick(rng, [",", ", ", " , "]) + e for i, e in enumerate(elements)
    )


def test_valid_headers_parse_like_aiohttp() -> None:
    # Domain: headers the RFC 7239 grammar accepts, without obs-text (aiohttp stops at it)
    # and without empty elements (aiohttp returns an empty dict for each).
    test_utils = pytest.importorskip("aiohttp.test_utils")
    multidict = pytest.importorskip("multidict")
    rng = random.Random(3)
    for _ in range(3000):
        lines = [_valid_line(rng) for _ in range(rng.randint(1, 3))]
        headers = multidict.CIMultiDict(("Forwarded", line) for line in lines)
        request = test_utils.make_mocked_request("GET", "/", headers=headers)
        assert [dict(element) for element in request.forwarded] == parse(lines), lines
