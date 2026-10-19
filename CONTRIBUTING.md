# Contributing

Thanks for taking the time. This project keeps a small, predictable shape.

## Setup

```
pip install -r requirements-dev.txt
```

## Before you open a pull request

- Keep public API in `src/forwarded/__init__.py`; internals live in `_`-prefixed modules.
- Add a test for the behaviour you change. Tests inject time, disk and network; they
  never touch the real thing.
- Run `python scripts/fetch_upstream.py` once so the tests against the RFCs run instead
  of skipping (the files stay out of git). The reference implementations are optional
  too: `pip install werkzeug==3.1.9 uvicorn==0.54.0 hypercorn==0.18.0 aiohttp==3.14.5`
  and `npm install --prefix tests/upstream forwarded-parse@2.1.2 proxy-addr@2.0.8`.
- Run `scripts/check.ps1` (format, lint, types, tests) and make sure it passes. Set
  `FORWARDED_E2E=1` to also build the wheel and test the installed package.
- One logical change per commit, imperative subject line.

Open an issue first if the change is large or shifts the public API.
