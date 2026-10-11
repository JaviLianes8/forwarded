# forwarded

Parse and build the HTTP Forwarded header per RFC 7239, with correct quoting and multiple elements.

## Install

```
pip install forwarded
```

## Usage

```python
from forwarded import parse, build

# Parse a header into a list of elements, one dict per comma-separated element.
parse("for=192.0.2.43, for=198.51.100.17")
# [{"for": "192.0.2.43"}, {"for": "198.51.100.17"}]

# Parameter names are case-insensitive and come back lower-cased; quoted values
# (such as an IPv6 identifier with a port) come back bare.
parse('for="[2001:db8:cafe::17]:4711";proto=https')
# [{"for": "[2001:db8:cafe::17]:4711", "proto": "https"}]

# Build a header back. Values are quoted only when they are not bare tokens, so an
# IPv6 identifier or a host with a port is quoted while proto=https stays bare.
build([{"by": "203.0.113.43", "for": "[2001:db8::1]:8080", "proto": "https"}])
# 'by=203.0.113.43;for="[2001:db8::1]:8080";proto=https'
```

`parse` tolerates malformed input: it skips pairs it cannot read and drops empty
elements instead of raising.

## Why

RFC 7239 defines a single `Forwarded` header that carries `for=`, `by=`, `host=` and
`proto=` across one or more proxy hops, and it replaces the ad-hoc `X-Forwarded-For`
family. Getting it right means splitting on commas and semicolons that sit outside a
quoted-string, unquoting IPv6 identifiers like `"[2001:db8::1]:8080"`, lower-casing the
case-insensitive parameter names, and quoting again on the way out only where the token
grammar requires it. People reach for a naive split and mishandle the quoting.

No standalone, typed, zero-dependency package covers this: `Django-Forwarded` is Django
middleware and Falcon's handling is internal to the framework. This library is just the
codec, both directions, with no runtime dependencies.

## License

MIT. See [LICENSE](LICENSE).

## Links

- Website: https://lianes8studio.com
- GitHub: https://github.com/JaviLianes8
- LinkedIn: https://www.linkedin.com/in/jlianes/
