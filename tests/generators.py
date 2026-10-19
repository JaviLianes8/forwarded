"""Seeded generators of valid, near-valid and hostile input, written by hand for the tests.

They aim at the boundaries of the RFC 7239, RFC 9110 and RFC 3986 rules: every value is
built from parts that are sometimes right and sometimes wrong, then randomly damaged.
"""

from __future__ import annotations

import random

TCHAR = "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
NOISE = ' \t;,="\\[]:._-%/@\x00\x01\r\n\x7f\x80\xe9\xff\u0100\u212a\U0001f600aZ09'
NAMES = ["for", "by", "host", "proto", "For", "BY", "x", "secret", "a-b", "n_1"]


def pick(rng: random.Random, options: str | list[str]) -> str:
    return options[rng.randrange(len(options))]


def ipv4_text(rng: random.Random) -> str:
    octets = [str(rng.choice([0, 1, 9, 10, 99, 127, 192, 199, 200, 249, 250, 255, 256, 300]))]
    octets += [str(rng.randrange(256)) for _ in range(3)]
    if rng.random() < 0.1:
        octets[rng.randrange(4)] = "0" + octets[0]
    if rng.random() < 0.05:
        octets = octets[: rng.randrange(1, 5)] + ["1"] * rng.randrange(2)
    return ".".join(octets)


def ipv6_text(rng: random.Random) -> str:
    groups = [
        "".join(pick(rng, "0123456789abcdefABCDEF") for _ in range(rng.randint(1, 4)))
        for _ in range(rng.randint(1, 8))
    ]
    if rng.random() < 0.1:
        groups[rng.randrange(len(groups))] = "12345"
    if rng.random() < 0.3:
        groups[-1] = ipv4_text(rng)
    if rng.random() < 0.6:
        cut = rng.randrange(len(groups) + 1)
        text = ":".join(groups[:cut]) + "::" + ":".join(groups[cut:])
    else:
        text = ":".join(groups)
    if rng.random() < 0.05:
        text += pick(rng, ["::", ":", "%eth0", "%1"])
    return text


def node_text(rng: random.Random) -> str:
    roll = rng.random()
    if roll < 0.3:
        host = ipv4_text(rng)
    elif roll < 0.55:
        host = f"[{ipv6_text(rng)}]" if rng.random() < 0.9 else ipv6_text(rng)
    elif roll < 0.7:
        host = pick(rng, ["unknown", "UNKNOWN", "Unknown", "unknow", "un\u212anown", ""])
    else:
        host = "_" * rng.randint(0, 2) + "".join(
            pick(rng, "aZ09._-" + "~!$ \xe9") for _ in range(rng.randint(0, 6))
        )
    if rng.random() < 0.4:
        digits = "".join(pick(rng, "0123456789") for _ in range(rng.randint(0, 6)))
        port = digits if rng.random() < 0.7 else "_" + digits + pick(rng, "aZ._-~")
        host += ":" + port
    return damage(rng, host) if rng.random() < 0.1 else host


def host_text(rng: random.Random) -> str:
    roll = rng.random()
    if roll < 0.2:
        host = f"[{ipv6_text(rng)}]"
    elif roll < 0.3:
        host = f"[v{pick(rng, '1fF')}.{pick(rng, ['a', 'b:c', '~!', ''])}]"
    else:
        parts = [pick(rng, "aZ09-._~!$&'()*+,;=") for _ in range(rng.randint(0, 8))]
        if rng.random() < 0.3:
            parts.insert(rng.randrange(len(parts) + 1), pick(rng, ["%41", "%7e", "%4", "%zz", "%"]))
        host = "".join(parts)
    if rng.random() < 0.4:
        host += ":" + "".join(pick(rng, "0123456789") for _ in range(rng.randint(0, 5)))
    return damage(rng, host) if rng.random() < 0.15 else host


def scheme_text(rng: random.Random) -> str:
    first = pick(rng, "aZq") if rng.random() < 0.9 else pick(rng, "1+.-")
    text = first + "".join(pick(rng, "aZ09+.-") for _ in range(rng.randint(0, 5)))
    return damage(rng, text) if rng.random() < 0.1 else text


def quote(rng: random.Random, text: str) -> str:
    """A quoted-string for ``text``, now and then with an extra escape or broken."""
    body = "".join("\\" + char if char in '"\\' or rng.random() < 0.05 else char for char in text)
    ending = '"' if rng.random() < 0.97 else ""
    return f'"{body}{ending}'


CANNED = {
    "for": ["192.0.2.43", '"[2001:db8::17]:4711"', "_hidden", "unknown", '"192.0.2.1:8080"'],
    "host": ["example.com", '"example.com:8080"', '""', '"[::1]:80"', "a%41"],
    "proto": ["http", "https", "coap+tcp", "Wss"],
    "": ["1", '"a b"', "tok_en", '"\\"q\\""', '"\xe9"'],
}


def value_text(rng: random.Random, name: str) -> str:
    lower = name.lower()
    if rng.random() < 0.5:
        return pick(rng, CANNED.get("for" if lower == "by" else lower, CANNED[""]))
    if lower in ("for", "by"):
        text = node_text(rng)
    elif lower == "host":
        text = host_text(rng)
    elif lower == "proto":
        text = scheme_text(rng)
    else:
        text = "".join(pick(rng, TCHAR + ' "\\,;=\t\xe9') for _ in range(rng.randint(0, 6)))
    if rng.random() < 0.5 or not text or any(char not in TCHAR for char in text):
        return quote(rng, text) if rng.random() < 0.9 else text
    return text


def ows(rng: random.Random) -> str:
    return pick(rng, ["", "", "", " ", "\t", "  ", " \t"])


def header_text(rng: random.Random) -> str:
    """A Forwarded field line: elements of pairs, separators with spaces, then damage."""
    elements = []
    for _ in range(rng.randint(1, 3)):
        pairs = []
        for _ in range(rng.randint(0, 3)):
            name = pick(rng, NAMES)
            pairs.append(f"{name}={value_text(rng, name)}" if rng.random() < 0.95 else "")
        if rng.random() < 0.1:
            pairs.append(pairs[0] if pairs else "")
        semicolon = ";" if rng.random() < 0.9 else pick(rng, [" ;", "; ", ";;"])
        elements.append(semicolon.join(pairs))
    text = ows(rng)
    for index, element in enumerate(elements):
        text += element if not index else f"{ows(rng)},{ows(rng)}{element}"
    text += ows(rng)
    return damage(rng, text) if rng.random() < 0.2 else text


def damage(rng: random.Random, text: str) -> str:
    """Insert, delete or replace a few characters, using characters that matter here."""
    chars = list(text)
    for _ in range(rng.randint(1, 3)):
        position = rng.randrange(len(chars) + 1)
        roll = rng.random()
        if roll < 0.4 or not chars:
            chars.insert(position, pick(rng, NOISE))
        elif roll < 0.7:
            del chars[min(position, len(chars) - 1)]
        else:
            chars[min(position, len(chars) - 1)] = pick(rng, NOISE)
    return "".join(chars)
