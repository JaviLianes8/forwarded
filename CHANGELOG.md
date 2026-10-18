# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-10-18

The public API is now stable: the ten names in `forwarded.__all__`, their signatures,
defaults and error types follow Semantic Versioning from this release on.

### Security

- An IPv6 network in `trusted` no longer covers IPv4 addresses unless it is a genuine
  IPv4-mapped network (inside `::ffff:0:0/96`, prefix 96 or longer), which then covers
  the IPv4 addresses it names. In 0.2.0 an IPv4 address matched any IPv6 network that
  held its IPv4-mapped form, so `trusted=["::ffff:10.0.0.0/8"]` (read as `::/8`),
  `["::/1"]` or `["::/0"]` made every IPv4 client a trusted proxy, and the client's
  own `X-Forwarded-For` or `Forwarded` entry became its address. This is the flaw
  fixed in proxy-addr 2.0.8 (CVE-2026-90711). A network written with an IPv4-mapped
  address and a prefix shorter than 96, such as `::ffff:10.0.0.0/8`, now raises
  `ValueError` instead of meaning `::/8`; write the IPv4 network (`10.0.0.0/8`) or the
  full mapped form (`::ffff:10.0.0.0/104`).

### Changed

- IPv4-mapped IPv6 addresses are written `::ffff:192.0.2.1` (RFC 5952 section 5) by
  `str(Node)`, `build` and `convert_x_forwarded_for` on every Python version; on
  CPython 3.11.5, for example, 0.2.0 wrote `::ffff:c000:201`.
- `Node`, `Client` and `ForwardedError` show and pickle as `forwarded.<Name>` instead
  of the private module that defines them; pickles made by 0.2.0 still load.
- `Client` checks its fields: `TypeError` for a `node` that is not a `Node`, a `proto`
  or `host` that is not a `str` or `None`, or a `proxies` that is not an `int`, and
  `ValueError` for a negative `proxies`.
- `Node` and `Client` store plain `str`, `int` and `ipaddress` values when given
  subclasses.

### Fixed

- `TypeError` instead of `AttributeError` for `Node(name=5)`, `parse_node(None)`,
  `build({"for": "_a"})` and `build("for=_a")`; `build([None])` raises `TypeError`
  instead of `ForwardedError`, and a header argument that is not iterable gets a
  message that names the argument.
- Error messages quote at most 80 characters of the input; 0.2.0 quoted the whole
  value (a 1 MB message for a 1 MB peer address). A `trusted` item whose `repr` fails,
  or an integer past the digit limit, raises `TypeError` instead of that failure.
- `client_from_x_forwarded` checks the types of `proto` and `host` even when it does
  not use them.

### Added

- Runnable examples in every public docstring, run as doctests, and a GUIDE.

## [0.2.0]

### Added

- `client_from_forwarded` and `client_from_x_forwarded`: the client behind a chain of
  proxies, walked from the right and trusting proxies by address or network (`trusted`)
  or by count (`hops`), with the `proto` and `host` the client used (`proto_hops` and
  `host_hops` count the proxies that append to X-Forwarded-Proto and -Host). IPv4 and
  IPv4-mapped IPv6 addresses match the same networks.
- `Client`, the frozen result: `node`, `proto`, `host`, `proxies`.
- `Node` and `parse_node` for `for` and `by` values: IPv4, bracketed IPv6,
  case-insensitive `unknown`, obfuscated names and ports.
- `parse(header, strict=True)`, which raises `ForwardedError` for anything outside the
  RFC 7239 grammar, duplicate parameters and invalid `for`/`by`/`host`/`proto` values.
- `ForwardedError`, a `ValueError` with the offset of the problem.
- `parse_x_forwarded` for the X-Forwarded-* list headers and `convert_x_forwarded_for`
  for the RFC 7239 section 7.4 transition.
- `parse` and the new functions take several header lines as an iterable.
- `build` takes `Node` values.

### Changed

- `parse` opens a quoted-string only where a value starts. A broken one (unterminated,
  or followed by junk) resumes scanning at the first comma after its opening quote. In 0.1.0 an unterminated quote from a client swallowed the elements a
  proxy appended after it. Malformed input can therefore give different results.
- `parse` keeps quoting within each line when given several lines.
- `build` raises `ForwardedError` for values a header cannot carry (CR, LF, other
  controls, code points above U+00FF), names that are not tokens, names that differ only
  in case, empty elements, and `for`/`by`/`host`/`proto` values of the wrong syntax. In
  0.1.0 it wrote them out, including a bare IPv6 address without brackets.
- `build` raises `TypeError` for names or values that are not strings or `Node`s.

## [0.1.0]

- First release: `parse` and `build` for the RFC 7239 Forwarded header, covering
  `for=`/`by=`/`host=`/`proto=`, multiple comma-separated elements, quoted IPv6
  identifiers, case-insensitive parameter names and token-aware quoting.
