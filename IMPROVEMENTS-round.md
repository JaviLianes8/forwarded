# forwarded improvement round

Progress:
- [x] Brainstorm ranked improvements (this file)
- [x] Pin the ground truth: RFC 7239, RFC 9110, RFC 3986, MDN X-Forwarded-For, proxy references
- [x] Grammar-aware scanner: quoting only at value start, per-line parsing, resync after errors
- [x] Strict mode with `ForwardedError`: RFC 7239 grammar, duplicates, per-parameter syntax
- [x] Typed node identifiers: `Node`, `parse_node`, IPv4, bracketed IPv6, `unknown`, obfuscated
- [x] Safe builder: header injection guard, node, host and proto validation, `Node` values
- [x] X-Forwarded-For family: list parsing, lenient entries, conversion to `Forwarded`
- [x] Client resolution: rightmost untrusted, trusted networks or hop count, proto and host
- [x] Contracts: RFC examples read from the pinned files, typing, README examples, installed wheel
- [x] Docs and packaging: README, CHANGELOG, docstrings, metadata, sdist contents
- [x] Gates: ruff format, ruff check, mypy --strict, pytest
- [x] Mutation run: removing guarded logic makes the suite fail
- [x] Independent review findings fixed with regression tests
- [ ] Pull request opened, guard clean

## Starting point

`0.1.0` gives `parse` and `build`. Compared with the sources below:

- `parse` treats a double quote anywhere as the start of a quoted-string. An unterminated
  quote sent by a client swallows the element a proxy appends after it: with
  `for=1.1.1.1;x="` from the client and `, for=2.2.2.2` from the proxy, the result is one
  element whose `for` is the client's choice. Anyone reading the client address from it
  can be spoofed.
- Several header lines can only be passed pre-joined, so a quote in one line leaks into
  the next, although RFC 9110 lists never span field lines.
- There is no strict mode: a caller cannot tell a valid header from garbage, duplicates
  (forbidden by RFC 7239 section 4) are silently merged, and `for`, `by`, `host` and
  `proto` values are never checked against sections 5 and 6.
- `for` and `by` come back as raw strings: every caller re-implements the bracket and
  port split of section 6, the case-insensitive `unknown`, and obfuscated identifiers.
- `build` writes anything: a value holding CR or LF injects a header, a bare IPv6 address
  is quoted but not bracketed (invalid per section 6), and two keys that differ only in
  case produce a forbidden duplicate.
- Nothing helps with the actual job: picking the client address from a chain of proxies
  without trusting what the client wrote, for `Forwarded` or for the far more common
  `X-Forwarded-For`.

## Sources (fetched 2026-10-13)

- RFC 7239, https://www.rfc-editor.org/rfc/rfc7239.txt (sha256 f15c45c9...a40d): grammar
  (section 4), parameters (5), node identifiers (6), HTTP lists and the X-Forwarded-For
  transition (7.1, 7.4), example usage (7.5), security (8.1). Errata page
  https://www.rfc-editor.org/errata/rfc7239 read: 5275 (reported) spells out the comma
  list the ABNF leaves to RFC 7230; 7973 was rejected and confirms names are
  case-insensitive.
- RFC 9110 sections 5.5 (obs-text), 5.6.1 (lists and recipient rules for empty elements),
  5.6.2 (token), 5.6.3 (OWS), 5.6.4 (quoted-string), 7.2 (Host),
  https://www.rfc-editor.org/rfc/rfc9110.txt.
- RFC 3986 sections 3.1 (scheme), 3.2.2 (IPv4address, IPv6address, IP-literal, reg-name),
  3.2.3 (port), https://www.rfc-editor.org/rfc/rfc3986.txt.
- MDN, X-Forwarded-For, mdn/content commit 9a3fb53f53855a17cbbf0aae4b99d71af83f00dc: the
  list spans several header lines, IPv6 is written bare, the two trusted selection
  methods (trusted proxy count, trusted proxy list searched from the right).
- nginx `ngx_http_realip_module` documentation (https://nginx.org/en/docs/http/ngx_http_realip_module.html)
  and `src/http/ngx_http_core_module.c` at commit 2b5c2b605b5df669da5dec6749dcc76c07d1315d
  (`ngx_http_get_forwarded_addr_internal`): with `real_ip_recursive on` the walk goes from
  the right, skips trusted addresses, accepts `addr`, `addr:port` and `[v6]:port`, and
  ends on the leftmost entry when every address is trusted.
- Werkzeug `ProxyFix` (`src/werkzeug/middleware/proxy_fix.py` at commit
  15fc22b699ecacd04824092453c0cd2a8c4a3a67): with N trusted proxies the value is the N-th
  from the right, or nothing when the list is shorter; the same rule for X-Forwarded-Proto
  and X-Forwarded-Host.
- None of these files is committed. `tests/upstream/MANIFEST.json` records URL, revision,
  size, sha256 and licence for the ones the tests read, `scripts/fetch_upstream.py`
  fetches and checks them into the ignored `tests/upstream/` folder, and their tests skip
  while they are absent. The proxy references are cited above and the behaviour tests
  written from them are hand-written and labelled as such.

## Ranked improvements

1. **Spoofing-resistant client resolution.** `client_from_forwarded` and
   `client_from_x_forwarded` walk the chain from the right (the peer address last), skip
   trusted proxies given as networks (IPv4 and IPv4-mapped IPv6 match the same networks) or as a
   hop count, and return the first untrusted node with the `proto` and `host` that the
   first trusted proxy recorded. An untrusted peer means the headers are ignored. A
   malformed entry at the boundary gives `None`, never a guess.
2. **Grammar-aware scanner.** A quoted-string starts only where a value starts; each header
   line is its own list; after an error the scanner resumes at the first comma after the
   failing value, so a client cannot hide or forge the elements proxies append.
3. **Strict mode.** `parse(header, strict=True)` raises `ForwardedError` (a `ValueError`
   with the offset) for anything outside the RFC 7239 grammar, duplicate parameters, and
   `for`/`by`/`host`/`proto` values that break sections 5 and 6. The lenient default keeps
   the 0.1.0 results for well-formed headers.
4. **Typed node identifiers.** `Node` (frozen: `ip`, `name`, `port`) and `parse_node`:
   IPv4 without leading zeros, bracketed IPv6 without zone, case-insensitive `unknown`,
   obfuscated names and ports, `str(node)` writes the RFC form back.
5. **Safe builder.** `build` refuses values that cannot be carried in a header (CR, LF,
   other controls, code points above U+00FF), names that are not tokens, case-insensitive
   duplicates, empty elements, and invalid `for`/`by`/`host`/`proto` values. It accepts
   `Node` values, so an IPv6 address is bracketed and quoted for free.
6. **X-Forwarded-For family.** `parse_x_forwarded` joins every header line into one list
   (MDN), and `convert_x_forwarded_for` performs the RFC 7239 section 7.4 transition,
   bracketing bare IPv6 and writing `unknown` for entries that are not addresses, so
   positions stay intact.
7. **Contracts.** The RFC examples and the MDN X-Forwarded-For lines are read from the
   pinned files at test time; README examples run; public types are checked with mypy;
   the installed wheel is driven from an empty folder.
8. **Docs and packaging.** README with executed examples, an API table checked against
   `__all__`, a security section on trust; CHANGELOG; classifiers and keywords; sdist
   without planning notes or third-party files.

## Out of scope

- A command line: the library is called from server code with the request in hand, and a
  shell filter over headers has no real user.
- Other non-standard headers (`X-Real-IP`, `Front-End-Https`, `X-Forwarded-Ssl`): they are
  single values that need no codec.
- Framework middleware: Starlette, Django and Werkzeug each have their own hook; the
  resolver takes plain strings so any of them can call it.
- The PROXY protocol: it is a transport preamble, not an HTTP header.

## Verification

- Gates on CPython 3.13.2 (this PC) and 3.14.6 (a second Windows machine, fresh clone):
  `ruff format --check .`, `ruff check .`, `mypy --strict src` (and `src tests`) and
  `pytest`. With `FORWARDED_E2E=1` the installed-wheel test builds the wheel and sdist,
  checks their contents (no planning notes, no fetched files, the manifest and fetch
  script present), installs the wheel in a fresh venv and drives the API from an empty
  folder. The suite also passes without the fetched files, skipping their tests.
- Guarded logic was removed one piece at a time. First run (77 mutations): six alive,
  four of them unreachable or equivalent code (a duplicate removal the dict already did,
  a qdtext check after the quote and backslash branches, a strip the callers already do,
  a hops clause the empty network list already covered), now removed; one missing test
  for junk between a bracket and a port, now added. After the review fixes the run was
  redone with 80 mutations covering the new code: two alive, killed by a test that gives
  proto and host different counts and one that checks the message for an unclosed
  bracket.
- The review regression tests were run against the code before the fixes: the new cases
  fail there, and the many-parameters test does not finish within two minutes.

## Review fixes

An independent review attacked the branch; each finding below is fixed with a test that
fails on the code before the fix:

- Quadratic time on many parameters in one element (the duplicate check compared each
  pair with every earlier one; 60k parameters took minutes). Names are now kept in a set.
- X-Forwarded-Proto and -Host reused the X-Forwarded-For hop count, so with only the edge
  proxy setting them a client-written value was picked. They now have their own counts
  (`proto_hops`, `host_hops`, default 1, as `ProxyFix` does), and a count larger than the
  trusted proxies passed gives `None`.
- Docs said a broken quoted-string ends at the next comma; they now state the real rule
  (the first comma after its opening quote) and a test pins it.
- `bytes` headers get a clear `TypeError`; the `trusted` error message no longer says "str"
  for `bytes`.
- Peer addresses: a zone is dropped from IPv6 only (`192.0.2.1%zz` and surrounding
  whitespace are rejected), and `[fe80::1%eth0]:80` is read.
- An IPv4 peer now matches a trusted network written in IPv4-mapped IPv6 form.
- Strict mode accepted no whitespace between an empty pair and the comma
  (`for=a; ,by=b`), which the grammar allows; it does now. The docstring says plainly
  that rejecting a header without any parameter is a choice of this library.
- The README warns that the all-trusted fallback returns an entry nobody vouches for.
- Not changed: a bare `str` for `trusted` still type-checks (a `str` is an iterable of
  `str`) and is rejected at run time with `TypeError`.
