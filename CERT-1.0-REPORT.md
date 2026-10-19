# forwarded 1.0.0 certification report

The 1.0.0 certification bar (19 items) applied to forwarded. PyPI has 0.2.0, which is
byte for byte the `main` branch at c3ade28 (the wheel's modules and the sdist's files
compared with the tree), so every change listed here is a change against the PyPI release.

Progress:
- [x] Branch `release/1.0.0` created from `main` (c3ade28, same code as PyPI 0.2.0)
- [x] Baseline gates on 0.2.0
- [x] API review and 1.0.0 changes (item 1)
- [x] Errors, typing, docstrings and doctests (items 2 to 5)
- [x] Ground truth: specifications fetched live, reference implementations (item 7)
- [x] Contract, fuzz and author mutation round (items 6, 9, 18)
- [x] Docs: README, GUIDE, CHANGELOG (items 11, 12)
- [x] Packaging, e2e and upgrade from PyPI 0.2.0, every Python (items 8, 10, 13, 14)
- [x] Gates (item 15)
- [x] PR #3 and trace guard CLEAN
- [ ] Five QA lenses report PASS (item 19)
- [ ] Independent reviewer reports PASS (item 16)

## Scorecard

| # | Item | Result |
| --- | --- | --- |
| 1 | Public API reviewed for stability | PASS: the ten names of 0.2.0 kept with their signatures, parameter names and defaults, pinned by `tests/test_contract_api.py`; every behaviour change in CHANGELOG and GUIDE |
| 2 | `__all__` exact, no private imports in docs | PASS: `tests/test_contract.py` |
| 3 | Docstrings with runnable examples, doctests | PASS: 12 doctests; the README examples run and their printed output is compared (`tests/test_docs.py`) |
| 4 | Typed end to end | PASS: `mypy --strict src tests`, `py.typed` shipped, inferred types checked from a consumer snippet (`tests/test_typing.py`) |
| 5 | Typed, documented, bounded errors | PASS: `ForwardedError` (a `ValueError`) with `position`, `ValueError` and `TypeError` as documented in the GUIDE, messages quote at most 80 characters |
| 6 | Contract tests of every public name | PASS |
| 7 | Real ground truth | PASS: six fetched sources with a hash manifest, grammars compiled from the fetched RFC text, proxy-addr and forwarded-parse under Node.js, Werkzeug, uvicorn, Hypercorn and aiohttp run live, PyPI 0.2.0 |
| 8 | Real e2e from the wheel | PASS: installed wheel driven from an empty folder with `-I`, upgrade in place from PyPI 0.2.0 (the library has no CLI) |
| 9 | Seeded fuzz, no crash, hang or blowup | PASS |
| 10 | Supported Pythons | PASS: CPython 3.10.19, 3.11.5, 3.12.12, 3.13.2, 3.14.2 and 3.14.2 free-threaded; 3.13 free-threaded is not installed here |
| 11 | README and `twine check` | PASS: `twine check --strict` on wheel and sdist, absolute links only |
| 12 | Dated CHANGELOG section | PASS: 1.0.0, 2026-10-19 |
| 13 | pyproject 1.0.0, Production/Stable | PASS |
| 14 | sdist and wheel contents | PASS |
| 15 | Gates each exit 0 | PASS: see Gates |
| 16 | Independent reviewer | pending |
| 17 | PR and trace guard | PR #3 from `release/1.0.0`, trace guard CLEAN; merge and publish left to the maintainer |
| 18 | Contracts bite (mutations) | PASS: author round of 19 mutants, all killed (two after a new contract) |
| 19 | Five independent QA lenses | pending |

## Baseline on 0.2.0 (before any change)

On this PC: `ruff format --check .`, `ruff check .`, `mypy --strict src` and
`mypy --strict src tests` exit 0. On the laptop, from a clone of c3ade28 with the fetched
specifications and `FORWARDED_E2E=1`: 302 passed on its own CPython 3.14.6, and on each
interpreter of this PC (copied there): 302 passed on 3.10.19, 3.12.12, 3.13.2, 3.14.2 and
3.14.2t, but 1 failed on 3.11.5 (`test_an_ipv4_mapped_peer_outside_the_network_is_not_trusted`:
CPython 3.11.5 writes `::ffff:b00:1` where the others write `::ffff:11.0.0.1`).

Defects found in 0.2.0, each reproduced against it:

- Spoofing through an IPv6 trust network (the flaw of CVE-2026-90711 in proxy-addr):
  `trusted=["::ffff:10.0.0.0/8"]` (meant as `::ffff:10.0.0.0/104`) was read as `::/8`,
  and an IPv4 address matched any IPv6 network holding its IPv4-mapped form, so with
  that setting, or `::/1` or `::/0`, every IPv4 client was a trusted proxy and its own
  `X-Forwarded-For` or `Forwarded` entry became the client address.
- `str(Node)`, `build` and `convert_x_forwarded_for` wrote IPv4-mapped addresses
  differently depending on the interpreter (`::ffff:c000:201` on CPython 3.11.5).
- `AttributeError` instead of `TypeError` for `Node(name=5)`, `parse_node(None)`,
  `build({"for": "_a"})` and `build("for=_a")`; `build([None])` raised
  `ForwardedError` (an empty element); `parse_node(b"x")` gave a confusing message.
- Error messages quoted the whole input: 1 MB for `parse_node` and a peer address of
  1 MB, 300 KB for `build` names and values and for strict `host` values; a trusted
  item whose `repr` fails raised that failure, and `trusted=[10**5000]` raised
  `ValueError` from the digit limit instead of `TypeError`.
- `Client` accepted any field values (`Client("x")`, `proxies=-1`); `Node` stored
  `str` and `int` subclasses as given.
- The README named the first parameter of `client_from_x_forwarded` `header`; it is
  `x_forwarded_for`.
- No public docstring had a runnable example; the README linked LICENSE relatively,
  which breaks on PyPI; there was no GUIDE; `release.ps1` refused any upload once the
  name existed on PyPI.

## API review (item 1)

Kept: the ten public names of 0.2.0 with their signatures, parameter names and defaults,
now pinned by `tests/test_contract_api.py`, which also checks the signatures shown in the
README table. Changed, all listed in the CHANGELOG and the GUIDE ("Upgrading from
0.2.0"): the IPv6 trust rules (an IPv6 network covers IPv4 addresses only when it is a
genuine IPv4-mapped network, and `::ffff:a.b.c.d` with a prefix under 96 raises
`ValueError`), RFC 5952 text for IPv4-mapped addresses on every Python version,
`forwarded.<Name>` as the module of the public classes (0.2.0 pickles still load), field
checks in `Client`, plain `str`, `int` and `ipaddress` values in `Node` and `Client`,
`TypeError` for every argument of the wrong type, and messages that quote at most 80
characters. Internal: the trust rules moved to `_trust.py` so every file stays under 200
lines. Each 0.2.0 defect above was re-run against 1.0.0 and is gone.

## Ground truth (item 7)

Fetched on 2026-10-18 by `scripts/fetch_upstream.py` into the ignored `tests/upstream`
folder; `tests/upstream/MANIFEST.json` records URL, revision, size, sha256 and licence and
the tests check the hash before reading. Nothing fetched is committed or shipped.

- RFC 7239 (https://www.rfc-editor.org/rfc/rfc7239.txt): the section 4, 6, 7.1, 7.4 and
  7.5 examples are cut from the text and parsed; every `Forwarded:` example passes the
  strict parser (`tests/test_sources.py`).
- RFC 7239, RFC 9110 and RFC 3986 ABNF (`tests/test_spec_grammar.py`): an independent
  matcher (`tests/abnf.py`, `tests/grammar.py`) compiles the grammar printed in the
  fetched texts at test time; strict parsing accepts exactly what the grammar accepts on
  3 seeds of 6,000 generated headers, and node identifiers (30,000), `host` values
  (20,000) and bare IPv6 entries (20,000) agree with it. `tchar`, `qdtext` and the URI
  `scheme` rule are read from the text and compared character by character.
- RFC 5952 (https://www.rfc-editor.org/rfc/rfc5952.txt): its example addresses and the
  section 5 mixed notation, on every interpreter (`tests/test_spec_rfc5952.py`).
- RFC 7239 errata page (https://www.rfc-editor.org/errata/rfc7239, as served on
  2026-10-18): 5067 and 5275 reported, 7973 rejected, none verified, so the RFC text
  stands; the two that touch the grammar are checked against the parser.
- MDN X-Forwarded-For page (mdn/content commit 9a3fb53): its header examples and its
  client and proxy example.
- Reference implementations run live in this certification:
  - Node.js: forwarded-parse 2.1.2 on 30,000 seeded headers; proxy-addr 2.0.8 (npm,
    published 2026-09-15, the release that fixed CVE-2026-90711; advisory
    https://github.com/advisories/GHSA-jqcg-44mw-7w3h, read 2026-10-19) address by
    address on 20,000 trust lists, 5,000 trust walks and 3,000 hop counts
    (`tests/test_oracles_node.py`).
  - Python: Werkzeug 3.1.9 `ProxyFix`, uvicorn 0.54.0, Hypercorn 0.18.0 and aiohttp
    3.14.5, 3,000 seeded cases each inside the domain both sides define
    (`tests/test_oracles_python.py`); the differences outside it are in GUIDE.md.
  - PyPI 0.2.0: installed from PyPI in the upgrade e2e test, where it shows the `::/1`
    spoofing and 1.0.0 does not.
- Hand-written data is labelled as such in each module docstring (`test_trust.py`,
  `test_spoofing.py`, `generators.py`, `addresses.py`).

## Fuzz and hostile input (item 9)

`tests/test_fuzz.py`: fixed seeds, 10,000 to 20,000 inputs per property over every public
function: only the documented errors are raised, messages stay short, `build` output reads
back through strict parsing, and every parser runs in linear time (timed at two sizes on
hostile shapes such as an unterminated quote, long element chains and 1 MB values).
`tests/test_spoofing.py`: client text cannot hide or forge the element a proxy appends.

## Author mutation round (item 18)

M1 to M18: each applied alone to a fresh clone of the pushed branch on another machine,
full suite run with `-x`, doctests and a 300 s per-test limit. M14 survived the first
round; the contract `test_build_rejects_elements_that_are_not_mappings_with_type_error`
was added (8654242) and kills it. M19 mutates the documentation: the README table showed
the 0.2.0 parameter name, which no test caught; `tests/test_contract_api.py` (ed429b2)
now fails on it.

| # | Mutation | Caught by |
| --- | --- | --- |
| M1 | an IPv4-mapped peer never matches IPv4 networks | `test_client.py::test_an_ipv4_mapped_peer_matches_an_ipv4_network` |
| M2 | a `::ffff:a.b.c.d/104` network never covers IPv4 | `test_client.py::test_an_ipv4_mapped_peer_matches_an_ipv4_network` |
| M3 | `hops` off by one | doctest of `client_from_forwarded` |
| M4 | an all-trusted chain counts one proxy too many | `test_client.py::test_when_everything_is_trusted_the_leftmost_entry_is_the_client` |
| M5 | `::ffff:10.0.0.0/8` silently accepted as `::/8` | `test_trust.py::test_an_ipv4_mapped_network_with_a_short_prefix_raises` |
| M6 | IPv4 matches IPv6 networks holding its mapped form (the CVE) | `test_trust.py::test_a_wide_ipv6_network_never_covers_ipv4_peers` |
| M7 | X-Forwarded-Proto/Host count reaches a client value | `test_client_xff.py::test_an_untrusted_peer_ignores_the_header` |
| M8 | error messages quote 8,000 characters | `test_fuzz.py::test_every_parser_runs_in_linear_time` |
| M9 | port range narrowed to 65535 | `test_fuzz.py::test_parsers_return_or_raise_forwarded_error_only` |
| M10 | `build` keeps parameter name case | doctest of `build` |
| M11 | an unconvertible X-Forwarded-For entry becomes `_unknown` | doctest of `convert_x_forwarded_for` |
| M12 | lenient parse keeps the first duplicate | doctest of `parse` |
| M13 | an unterminated quote swallows the rest of the line | `test_spoofing.py::test_the_appended_element_survives_whatever_the_client_sent` |
| M14 | `ForwardedError` instead of `TypeError` for a non-mapping element | `test_build.py::test_build_rejects_elements_that_are_not_mappings_with_type_error` |
| M15 | Kelvin sign spelling read as `unknown` | `test_node.py::test_unknown_with_a_kelvin_sign_is_not_unknown` |
| M16 | the zone of an IPv6 peer object is kept | `test_client.py::test_peer_forms` |
| M17 | strict mode accepts whitespace before `;` | `test_spec_errata.py::test_erratum_5275_list_form_is_what_strict_mode_reads` |
| M18 | bracketed IPv6 identifiers not parsed | doctest of `build` |
| M19 | README shows `client_from_x_forwarded(header, ...)` | `test_contract_api.py::test_the_readme_api_table_shows_the_real_signatures` |

## Packaging, e2e and Pythons (items 8, 10, 13, 14)

- On another machine (CPython 3.14.2), from a clone with the fetched sources and
  `FORWARDED_E2E=1`: `python -m build` gives `forwarded-1.0.0.tar.gz` and
  `forwarded-1.0.0-py3-none-any.whl`; `twine check --strict` passes both; pytest exits 0,
  skipping only the reference packages not installed there.
- The e2e tests build both archives, inspect them, install the wheel in a fresh venv and
  drive every public name from an empty folder with `-I`; then install 0.2.0 from PyPI,
  show its `::/1` spoofing, upgrade in place to the built wheel and check the fix and a
  0.2.0 pickle. The library has no command-line interface.
- Wheel: the eleven modules, `py.typed`, METADATA, WHEEL, RECORD and `licenses/LICENSE`.
  Sdist: sources, tests, `tests/upstream/MANIFEST.json` only, scripts, README, GUIDE,
  CHANGELOG, CONTRIBUTING, LICENSE, pyproject; no fetched file, no report, no scratch.
- Interpreters from `requires-python` (3.10) up, at 8654242 with `FORWARDED_E2E=1`:
  CPython 3.10.19, 3.11.5, 3.12.12 and 3.14.2 on the laptop with the fetched sources,
  the Node.js references, the four Python references and mypy present: 392 passed, 0
  skipped each. CPython 3.13.2 and 3.14.2 free-threaded (GIL disabled) on another
  machine: 392 passed, 12 skipped each (the references and the mypy typing tests, whose
  packages are not installed there). 3.13 free-threaded is not installed on this PC.
  ed429b2 adds only the signature contract and README and CHANGELOG text; the full suite
  was run again at the final head (see Gates).

## Gates (item 15)

On this PC at the final head: `ruff format --check .` (ruff 0.17.0), `ruff check .`,
`mypy --strict src` and `mypy --strict src tests` each exit 0. `pytest` exits 0 on the
runs above and on the final-head run below.

Final-head run at 649ef07 on the laptop (CPython 3.14.6), from a fresh clone of GitHub:
`scripts/fetch_upstream.py` fetched all six sources again on 2026-10-19 and every hash
matched the manifest; forwarded-parse 2.1.2 and proxy-addr 2.0.8 from npm, Werkzeug
3.1.9, uvicorn 0.54.0, Hypercorn 0.18.0, aiohttp 3.14.5 and mypy installed;
`FORWARDED_E2E=1`: 417 passed, 0 skipped (doctests, the signature contract, the wheel
e2e and the upgrade from PyPI 0.2.0 included).
