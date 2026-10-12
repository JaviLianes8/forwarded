# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0]

### Added

- `client_from_forwarded` and `client_from_x_forwarded`: the client behind a chain of
  proxies, walked from the right and trusting proxies by address or network (`trusted`)
  or by count (`hops`), with the `proto` and `host` the client used. IPv4-mapped IPv6
  peers match IPv4 networks.
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

- `parse` opens a quoted-string only where a value starts, and a broken one ends at the
  next comma. In 0.1.0 an unterminated quote from a client swallowed the elements a
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
