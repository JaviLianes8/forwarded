# forwarded 1.0.0 certification report

The 1.0.0 certification bar (19 items) applied to forwarded. PyPI has 0.2.0, which is
byte for byte the `main` branch at c3ade28 (the wheel's modules and the sdist's files
compared with the tree), so every change listed here is a change against the PyPI release.

Progress:
- [x] Branch `release/1.0.0` created from `main` (c3ade28, same code as PyPI 0.2.0)
- [ ] Baseline gates on 0.2.0
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
