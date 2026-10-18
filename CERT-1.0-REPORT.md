# forwarded 1.0.0 certification report

The 1.0.0 certification bar (19 items) applied to forwarded. PyPI has 0.2.0, which is
byte for byte the `main` branch at c3ade28 (the wheel's modules and the sdist's files
compared with the tree), so every change listed here is a change against the PyPI release.

Progress:
- [x] Branch `release/1.0.0` created from `main` (c3ade28, same code as PyPI 0.2.0)
- [x] Baseline gates on 0.2.0
- [ ] API review and 1.0.0 changes (item 1)
- [ ] Errors, typing, docstrings and doctests (items 2 to 5)
- [ ] Ground truth: specifications fetched live, reference implementations (item 7)
- [ ] Contract, fuzz and author mutation round (items 6, 9, 18)
- [ ] Docs: README, GUIDE, CHANGELOG (items 11, 12)
- [ ] Packaging, e2e and upgrade from PyPI 0.2.0, every Python (items 8, 10, 13, 14)
- [ ] Gates (item 15)
- [ ] PR and trace guard CLEAN
- [ ] Five QA lenses report PASS (item 19)
- [ ] Independent reviewer reports PASS (item 16)

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
