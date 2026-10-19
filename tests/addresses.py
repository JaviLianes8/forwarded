"""Seeded random addresses, written by hand for the oracle and property tests.

Half of the addresses fall inside a small pool of networks, so trust checks hit both
ways; IPv6 text comes in compressed, exploded and upper-case spellings.
"""

from __future__ import annotations

import random
from ipaddress import IPv4Address, IPv6Address, ip_network

POOL = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "198.51.100.0/24",
    "203.0.113.7/32",
    "2001:db8::/32",
    "2001:db8:1::5/128",
    "fd00::/8",
]


def address(rng: random.Random, *, mapped: bool = False) -> IPv4Address | IPv6Address:
    """A random address: inside a pool network half of the time, sometimes IPv4-mapped."""
    if rng.random() < 0.5:
        network = ip_network(rng.choice(POOL))
        found = network[rng.randrange(network.num_addresses)]
    elif rng.random() < 0.5:
        found = IPv4Address(rng.getrandbits(32))
    else:
        found = IPv6Address(rng.getrandbits(128) >> rng.choice([0, 0, 64, 96]))
    if mapped and isinstance(found, IPv4Address) and rng.random() < 0.3:
        return IPv6Address(f"::ffff:{found}")
    return found


def spelled(rng: random.Random, ip: IPv4Address | IPv6Address) -> str:
    """The address as text, in one of the spellings a header can carry."""
    if isinstance(ip, IPv4Address):
        return str(ip)
    return rng.choice([str(ip), ip.exploded, str(ip).upper()])


def networks(rng: random.Random, *, mapped: bool = False) -> list[str]:
    """A list of trusted addresses and networks, strict (no host bits), from the pool."""
    found = []
    for _ in range(rng.randint(1, 4)):
        roll = rng.random()
        if roll < 0.6:
            found.append(rng.choice(POOL))
        elif roll < 0.8:
            found.append(str(address(rng)))
        elif mapped:
            network = ip_network(rng.choice(POOL[:5]))
            found.append(f"::ffff:{network.network_address}/{96 + network.prefixlen}")
        else:
            found.append(rng.choice(["::/1", "::/64", "8000::/1", "0.0.0.0/1", "128.0.0.0/1"]))
    return found


def chain(rng: random.Random, *, mapped: bool = False) -> list[IPv4Address | IPv6Address]:
    """X-Forwarded-For entries, left to right."""
    return [address(rng, mapped=mapped) for _ in range(rng.randint(0, 5))]


def inside(rng: random.Random, trusted: list[str]) -> IPv4Address | IPv6Address:
    """An address inside one of the ``trusted`` networks (IPv4-mapped ones as IPv4)."""
    network = ip_network(rng.choice(trusted), strict=False)
    found = network[rng.randrange(min(network.num_addresses, 2**64))]
    mapped = found.ipv4_mapped if isinstance(found, IPv6Address) else None
    return mapped if mapped is not None else found


def trusted_chain(
    rng: random.Random, trusted: list[str]
) -> tuple[IPv4Address | IPv6Address, list[IPv4Address | IPv6Address]]:
    """A peer and X-Forwarded-For entries whose right end is often inside ``trusted``."""
    entries = chain(rng)
    for index in range(len(entries) - 1, -1, -1):
        if rng.random() > 0.6:
            break
        entries[index] = inside(rng, trusted)
    return (inside(rng, trusted) if rng.random() < 0.7 else address(rng)), entries
