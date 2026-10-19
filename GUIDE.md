# forwarded guide

The README shows the calls. This guide explains the choices behind them: how the client
is found, what each setting trusts, how malformed input is read, and where the library
differs from the tools you may be replacing.

## The trust walk

A request that went through proxies carries a chain of addresses. With `Forwarded`, every
`for=` parameter is one entry; with `X-Forwarded-For`, every comma-separated value is one.
The address of the TCP connection (`remote`) is the last entry, because it is the one
nobody could write.

`client_from_forwarded` and `client_from_x_forwarded` walk that chain from the right. An
entry that is a trusted proxy is skipped; the first entry that is not is the client. The
entries further left were written by the client or by proxies you do not run, so they are
never read, and a client cannot get in by sending its own header.

There are two ways to say which proxies are yours:

- `trusted`: addresses and networks, as strings or `ipaddress` objects. Use it when your
  proxies have fixed addresses (a private subnet, a load balancer range).
- `hops`: the number of proxies in front of your server, whatever their addresses. Use
  it when they have no fixed addresses (a managed load balancer, a CDN). The chain must
  hold at least `hops` entries left of the peer, or the result is `None`.

Giving both raises `ValueError`. Giving neither trusts nothing: the client is `remote`.

`Client.proxies` is the number of trusted proxies the walk passed. When every entry is
trusted, the leftmost one is returned with `proxies` equal to the length of the chain
minus one. It was written by whatever sent the request into your network, so treat it as
a label, not an identity.

## When the answer is `None`

The functions return `None` rather than guess:

- the entry where the walk stops is malformed: not an address or a node identifier, or,
  with `Forwarded`, an element with any syntax error (a repeated parameter, a pair that
  cannot be read, a broken quoted-string), even when lenient `parse` still reads a `for`
  from it;
- a `Forwarded` element there has no `for`;
- there are fewer entries than `hops`;
- `remote` is `None` (a Unix socket, for example) and `hops` does not cover it.

A malformed entry further left than the client is never read, so it changes nothing.
Node identifiers such as `unknown` or `_hidden` can be the client, but they are never
trusted proxies, whatever `trusted` holds.

## IPv4, IPv6 and mapped addresses

A dual-stack socket reports IPv4 peers as IPv4-mapped IPv6 addresses (`::ffff:10.0.0.1`).
Both the peer and the header entries are read as the IPv4 address they name, so an IPv4
network in `trusted` covers either form.

An IPv6 network in `trusted` covers IPv6 addresses only, with one exception: a genuine
IPv4-mapped network (inside `::ffff:0:0/96`, prefix 96 or longer, such as
`::ffff:10.0.0.0/104`) is the IPv4 network it names. So `::/0` or `::/1` trusts every
IPv6 address and no IPv4 address. Before 1.0.0 an IPv4 address matched any IPv6 network
holding its mapped form, which let `::/1` trust every IPv4 client; proxy-addr had the
same flaw (CVE-2026-90711, fixed in 2.0.8).

A network written with an IPv4-mapped address and a prefix under 96, such as
`::ffff:10.0.0.0/8`, raises `ValueError`. Python reads it as `::/8`, which is almost never
what was meant: write `10.0.0.0/8` or `::ffff:10.0.0.0/104`.

Networks with host bits set (`10.9.9.9/8`) are widened to their network. The peer may
carry an IPv6 zone (`fe80::1%eth0`), which is dropped.

## X-Forwarded-Proto and X-Forwarded-Host

With `Forwarded`, the protocol and host travel in the client's own element, so they are
read from the element the walk stopped at.

The `X-Forwarded-*` headers are separate lists, and many setups append to
`X-Forwarded-Proto` and `X-Forwarded-Host` at the edge only. `proto_hops` and `host_hops`
(default 1) say how many trusted proxies append to each, and the value used is that many
from the right. It is `None` when the header has fewer values, or when the count is larger
than the number of trusted proxies the walk passed, since that value could have come from
the client.

Read only the header your proxies set and make the edge proxy drop or overwrite the
other one: a client can send whichever one you do not control.

## Lenient and strict parsing

`parse` is lenient by default, for reading what real proxies send:

- pairs it cannot read are skipped, and an element with no readable pair is dropped;
- empty elements are dropped and the last of a duplicated parameter wins;
- whitespace around `;`, `,` and `=` is accepted;
- a double quote opens a quoted-string only where a value starts, and quoting never runs
  from one header line into the next;
- when a quoted-string is unterminated, or is followed by anything but `;`, `,` or
  whitespace, scanning resumes at the first comma after its opening quote.

The last two rules are what keep a proxy's appended element intact whatever the client
put before it: a client that sends `for=x;y="` cannot swallow the `, for=192.0.2.60` your
proxy adds.

`parse(header, strict=True)` accepts exactly the RFC 7239 grammar (with the RFC 9110 list
and quoting rules) and checks the syntax of `for`, `by`, `host` and `proto`. Anything else
raises `ForwardedError` with the offset in its line. Strict mode suits tests and
proxies you control; lenient mode suits production traffic.

`build` writes only what strict parsing reads back, and raises `ForwardedError` for
anything else. That includes CR and LF, so a value cannot inject a header.

## Errors

| Error | Raised for |
| --- | --- |
| `ForwardedError` (a `ValueError`) | strict parsing, `parse_node`, `build`: input outside RFC 7239. `position` is the offset in the line, or `None` for a whole value. |
| `ValueError` | a `remote` that is not an IP address, a `trusted` entry that is not an address or network, `trusted` and `hops` together, a negative `hops` or `Client.proxies`, a `proto_hops` or `host_hops` under 1. |
| `TypeError` | arguments of the wrong type: `bytes` headers, a bare string as `trusted`, a `trusted` entry that is neither a string nor an `ipaddress` object, a count that is not an `int`, a non-mapping element given to `build`. |

Messages quote at most 80 characters of the input, so a hostile megabyte never ends up
in a log line. An argument of the wrong type is named by its type only, never by its
`repr`, which could hold a secret.

Counts are checked as the plain `int` they hold, so an `int` subclass cannot get a
negative count past the check by overriding its comparisons.

## Differences from other tools

The test suite compares the library with these tools on random input; the comparisons are
in `tests/test_oracles_node.py` and `tests/test_oracles_python.py`, and they hold inside
the domains stated there. Outside those domains, as observed with the versions listed:

- **proxy-addr 2.0.8** (Express): the same trust rules for networks and mapped
  addresses, with three differences. With a hop count larger than the chain, Express
  falls back to the leftmost address; this library returns `None`. proxy-addr accepts a
  trusted network such as `::ffff:10.0.0.0/8` and then trusts no IPv4 peer; this library
  raises `ValueError` for it. proxy-addr throws on `::/0` (`invalid range on address`);
  this library accepts it as every IPv6 address.
- **forwarded-parse 2.1.2**: its grammar is not quite RFC 7239. It accepts whitespace
  around `;` (`for=1.2.3.4; proto=http`) and a repeated parameter, keeping the last, both
  of which strict mode here rejects. It throws on an empty pair or element
  (`for=1.2.3.4;;proto=http`, `for=1.2.3.4,`), which the grammar allows and strict mode
  here accepts. In lenient mode this library reads all four.
- **Werkzeug 3.1.9 `ProxyFix`**: takes the X-Forwarded-For value at the hop count even
  when it is not an address (`junk` becomes `REMOTE_ADDR`), and takes an
  X-Forwarded-Proto value at its own count even when that count goes past the trusted
  `X-Forwarded-For` hops. This library returns `None` for the first and no `proto` for
  the second. `ProxyFix` does not read `Forwarded`.
- **uvicorn 0.54.0 `ProxyHeadersMiddleware`**: compares the peer address as written, so
  an IPv4-mapped peer `::ffff:10.0.0.1` is not covered by `10.0.0.0/8`. It does not read
  `Forwarded`.
- **Hypercorn 0.18.0 `ProxyFixMiddleware`** (modern mode): splits `Forwarded` on commas
  and semicolons without reading quoted-strings, so `for="[2001:db8::1]:4711"` becomes a
  client address with the quotes in it, and trusts by hop count only.
- **aiohttp 3.14.5 `request.forwarded`**: parses `Forwarded` but does not pick the client.
  It returns an empty mapping for each empty element, which this library drops, and it
  stops reading an element at a pair holding obs-text, keeping only the pairs before it
  (so the mapping is empty when that pair comes first); this library reads the whole
  element.

## Upgrading from 0.2.0

See the 1.0.0 section of the
[CHANGELOG](https://github.com/JaviLianes8/forwarded/blob/main/CHANGELOG.md). The changes
that can affect a working 0.2.0 setup:

- `trusted` entries such as `::/0`, `::/1` or `::/64` no longer trust IPv4 clients. If you
  relied on that, add the IPv4 networks you meant.
- `::ffff:10.0.0.0/8` style entries raise `ValueError` at the call.
- IPv4-mapped addresses print as `::ffff:192.0.2.1` on every Python version.
- Some misuse raises `TypeError` where 0.2.0 raised `AttributeError` or `ForwardedError`.
