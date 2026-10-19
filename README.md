# forwarded

[![Lianes8 Certified](https://lianes8studio.com/certified/lianes8-certified-badge.svg)](https://lianes8studio.com/certified)

Parse and build the HTTP `Forwarded` header (RFC 7239), read `X-Forwarded-For`, and find
the real client behind a chain of proxies without trusting what the client wrote.

Typed, zero dependencies, Python 3.10+. The
[guide](https://github.com/JaviLianes8/forwarded/blob/main/GUIDE.md) explains the trust
model, lenient and strict parsing, and how the results differ from other tools; the
[changelog](https://github.com/JaviLianes8/forwarded/blob/main/CHANGELOG.md) lists what
changed in each release.

## Install

```
pip install forwarded
```

## Find the client

Behind a reverse proxy the socket address is the proxy, and the headers hold the rest of
the chain. Anyone can send those headers, so only the entries your own proxies added can
be believed. Give the address the connection came from and the proxies you run:

```python
from forwarded import client_from_forwarded, client_from_x_forwarded

client = client_from_x_forwarded(
    "203.0.113.195, 10.0.0.7",  # X-Forwarded-For as received
    "10.0.0.2",  # the peer address of the connection
    proto="https",  # X-Forwarded-Proto, set by the edge proxy
    trusted=["10.0.0.0/8"],  # your proxies: addresses or networks
)
assert client is not None  # None when the client cannot be told (see below)
print(client.node)
# 203.0.113.195
print(client.proto, client.proxies)
# https 2

# A client that writes its own entries cannot get past your proxies.
spoofed = client_from_x_forwarded("1.1.1.1, 203.0.113.195", "10.0.0.2", trusted=["10.0.0.0/8"])
assert spoofed is not None
print(spoofed.node)
# 203.0.113.195

# The same with Forwarded, where proto and host travel in the client's own element.
header = 'for="[2001:db8::7]:4711";proto=https;host=shop.example, for=10.0.0.7'
client = client_from_forwarded(header, "10.0.0.2", trusted=["10.0.0.0/8"])
assert client is not None
print(client.node, client.node.ip, client.node.port)
# [2001:db8::7]:4711 2001:db8::7 4711
print(client.proto, client.host)
# https shop.example

# When the proxies have no fixed addresses, trust a number of hops instead.
by_hops = client_from_x_forwarded("203.0.113.195, 198.51.100.4", "172.16.0.9", hops=1)
if by_hops is not None:
    print(by_hops.node)
# 198.51.100.4

# A malformed entry where the walk stops gives None, never a guess.
print(client_from_x_forwarded("203.0.113.195, junk", "10.0.0.2", trusted=["10.0.0.0/8"]))
# None
```

The walk goes from the right, starting with the peer address: while an entry is a trusted
proxy it moves on, and the first entry that is not is the client. If the peer itself is
not trusted, the headers are ignored and the peer is the client. The result is `None`
when the client cannot be told: the entry at the boundary is malformed (with
`Forwarded`, that means its whole element: any syntax error in it, such as a repeated
parameter or an unreadable pair, counts even when `parse` still reads a `for` from it),
it is a `Forwarded` element with no `for`, `remote` is `None` and not covered by `hops`,
or there are fewer entries than `hops`. When every address is trusted, the leftmost one is returned
(as nginx does); that entry was written by whoever sent the request into your network,
so do not use it for security decisions.

`proto` and `host` are what the client used. With `Forwarded` they come from the
client's own element, written by the first proxy you trust. `X-Forwarded-Proto` and
`X-Forwarded-Host` are often set by the edge proxy only, so they have their own counts,
as in Werkzeug's `ProxyFix`: `proto_hops` and `host_hops` (default 1) are the number of
trusted proxies that append to that header, and the value used is that many from the
right. It is `None` when there are fewer values, or when the count is larger than the
number of trusted proxies the walk passed, since such a value could come from the
client.

Read only one of the two headers, the one your proxies set, and make sure your edge
proxy drops or overwrites the other: a client can send whichever header you do not
control.

## Parse and build

```python
from ipaddress import ip_address

from forwarded import Node, build, parse, parse_node

# One dict per element; names are lower-cased, quoted values come back bare.
print(parse('for="[2001:db8:cafe::17]:4711";Proto=https, for=192.0.2.43'))
# [{'for': '[2001:db8:cafe::17]:4711', 'proto': 'https'}, {'for': '192.0.2.43'}]

# Several Forwarded lines form one list; quoting never runs from one line into the next.
print(parse(["for=192.0.2.43", "for=198.51.100.17"]))
# [{'for': '192.0.2.43'}, {'for': '198.51.100.17'}]

# for and by values are node identifiers.
node = parse_node("[2001:db8:cafe::17]:4711")
print(node.ip, node.port)
# 2001:db8:cafe::17 4711
print(parse_node("UNKNOWN").unknown, parse_node("_hidden").obfuscated)
# True True

# build quotes only where the grammar needs it and writes a Node in its RFC form.
print(build([{"for": Node(ip=ip_address("2001:db8::1"), port=8080), "proto": "https"}]))
# for="[2001:db8::1]:8080";proto=https
```

`parse` is lenient by default: it skips pairs it cannot read, keeps the last of a
duplicated parameter and drops empty elements. A double quote opens a quoted-string only
where a value starts. When a quoted-string is unterminated, or followed by anything but
`;`, `,` or whitespace, scanning resumes at the first comma after its opening quote, so
text a client sends cannot swallow the element a proxy appends after it.

With `strict=True`, anything outside RFC 7239 raises `ForwardedError`, a `ValueError`
carrying the offset in its line:

```python
from forwarded import ForwardedError, parse

for header in ('for="2001:db8::1"', "for=192.0.2.43;for=192.0.2.44", "for=a; proto=http"):
    try:
        parse(header, strict=True)
    except ForwardedError as error:
        print(error)
# '2001:db8::1' is not a node identifier at offset 4
# parameter 'for' occurs twice in one element at offset 15
# expected a parameter name followed by '=' at offset 6
```

`build` refuses to write a header a strict reader would reject: a character a header
cannot carry (CR and LF included, so a value cannot inject a header), a name that is not
a token, two names that differ only in case, an empty element, or a `for`, `by`, `host`
or `proto` value of the wrong syntax.

## X-Forwarded-For

```python
from forwarded import convert_x_forwarded_for, parse_x_forwarded

# Every X-Forwarded-For line is part of one list.
print(parse_x_forwarded(["192.0.2.43, 2001:db8:cafe::17", "198.51.100.17"]))
# ['192.0.2.43', '2001:db8:cafe::17', '198.51.100.17']

# RFC 7239 section 7.4: each entry becomes a for= element, IPv6 bracketed and quoted.
print(convert_x_forwarded_for("192.0.2.43, 2001:db8:cafe::17, garbage"))
# for=192.0.2.43, for="[2001:db8:cafe::17]", for=unknown
```

Entries that are not addresses become `for=unknown`, so hop counts stay right.

## API

| Name | What it does |
| --- | --- |
| `client_from_forwarded(header, remote, *, trusted=(), hops=None)` | The client from `Forwarded` lines and the peer address, or `None`. |
| `client_from_x_forwarded(x_forwarded_for, remote, *, proto=None, host=None, trusted=(), hops=None, proto_hops=1, host_hops=1)` | The same from `X-Forwarded-For`, with `X-Forwarded-Proto` and `-Host`. |
| `Client` | Frozen result: `node`, `proto`, `host`, `proxies` (trusted proxies passed). |
| `parse(header, *, strict=False)` | `Forwarded` lines to a list of dicts. |
| `build(elements)` | Mappings of `str` or `Node` values to a `Forwarded` value. |
| `parse_node(value)` | A `for` or `by` value to a `Node`. |
| `Node` | Frozen node identifier: `ip` or `name`, optional `port`; `unknown`, `obfuscated`; `str()` gives the RFC form. |
| `parse_x_forwarded(header)` | `X-Forwarded-*` lines to a list of values. |
| `convert_x_forwarded_for(header)` | `X-Forwarded-For` to `Forwarded`. |
| `ForwardedError` | `ValueError` raised by strict parsing, `parse_node` and `build`; `position` is the offset or `None`. |

`header` and `x_forwarded_for` take one field value or an iterable of them, one per line
received. `remote` is a `str` or an `ipaddress` address (a zone such as `%eth0` is
dropped), or `None` when the connection has no IP address (a Unix socket), which only
`hops` can get past. `trusted` takes an iterable of addresses and networks as strings or `ipaddress`
objects (a bare string raises `TypeError`); an IPv4 address and its IPv4-mapped IPv6
form such as `::ffff:10.0.0.1` match the same networks.

## Standards

- RFC 7239: grammar (section 4), parameters (5), node identifiers (6), HTTP lists and
  the X-Forwarded-For transition (7.1, 7.4).
- RFC 9110: lists, tokens, whitespace and quoted-strings (5.6), Host (7.2).
- RFC 3986: scheme, IPv4address, IPv6address and reg-name.
- `X-Forwarded-For` has no specification. The selection rules follow the MDN reference;
  ports and the leftmost fallback match nginx's realip module, and the per-header counts
  for `X-Forwarded-Proto` and `-Host` follow Werkzeug's `ProxyFix`. Unlike nginx, a
  malformed entry at the boundary gives `None` instead of the last trusted address.

The tests check the library against the examples and grammar rules of the RFCs and the
MDN page as published. Those files are not part of the repository:
`python scripts/fetch_upstream.py` downloads them into `tests/upstream/` and checks
their hashes, and their tests skip until then.

## Why

RFC 7239 defines one `Forwarded` header for what the `X-Forwarded-*` family did ad hoc,
but reading either one safely is easy to get wrong: splitting on commas inside quotes,
unquoting bracketed IPv6, or trusting the leftmost address that any client can forge.

The Python tools that exist each cover part of it (checked against the versions named,
see the [guide](https://github.com/JaviLianes8/forwarded/blob/main/GUIDE.md#differences-from-other-tools)):

- Werkzeug's `ProxyFix` and uvicorn's `ProxyHeadersMiddleware` read `X-Forwarded-*` only,
  and only as middleware for their own server interface. `ProxyFix` trusts by hop count
  and accepts a value that is not an address as the client.
- Hypercorn's `ProxyFixMiddleware` reads `Forwarded` without quoted-strings, so a quoted
  IPv6 client keeps its quotes.
- aiohttp parses `Forwarded` into mappings but leaves picking the client to you.

This library is the codec and the trust walk for both headers, as plain functions you can
call from any framework, a log processor or a proxy, with no runtime dependencies. If you
already run one of the middlewares above and only need `X-Forwarded-For` by hop count, it
may be all you need.

## License

MIT. See [LICENSE](https://github.com/JaviLianes8/forwarded/blob/main/LICENSE).

## Links

- Website: https://lianes8studio.com
- GitHub: https://github.com/JaviLianes8
- LinkedIn: https://www.linkedin.com/in/jlianes/
