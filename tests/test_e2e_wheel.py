"""Build the wheel, install it in a throwaway venv and drive the installed package.

Slow and needs the build backend, so it runs only with FORWARDED_E2E=1.
"""

from __future__ import annotations

import os
import subprocess
import sys
import venv
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.skipif(
    os.environ.get("FORWARDED_E2E") != "1", reason="set FORWARDED_E2E=1 to build and install"
)

PROGRAM = r"""
import importlib.metadata, importlib.resources, pickle
from ipaddress import ip_address
import forwarded
from forwarded import (
    Client, ForwardedError, Node, build, client_from_forwarded, client_from_x_forwarded,
    convert_x_forwarded_for, parse, parse_node, parse_x_forwarded,
)

assert "site-packages" in forwarded.__file__, forwarded.__file__
assert importlib.metadata.version("forwarded") == forwarded.__version__
assert importlib.resources.files("forwarded").joinpath("py.typed").is_file()

spoofed = 'for=192.0.2.66;x="' + ', for="[2001:db8::7]:4711";proto=https'
assert parse(spoofed)[-1] == {"for": "[2001:db8::7]:4711", "proto": "https"}
client = client_from_forwarded(spoofed, "::ffff:10.0.0.1", trusted=["10.0.0.0/8"])
assert client == Client(Node(ip=ip_address("2001:db8::7"), port=4711), "https", None, 1), client
xff = client_from_x_forwarded("1.1.1.1, 203.0.113.9", "10.0.0.1", proto="https", hops=1)
assert xff is not None and str(xff.node) == "203.0.113.9" and xff.proto == "https"
assert client_from_x_forwarded("203.0.113.9, junk", "10.0.0.1", hops=1) is None
assert convert_x_forwarded_for("192.0.2.43, 2001:db8:cafe::17") == (
    'for=192.0.2.43, for="[2001:db8:cafe::17]"'
)
assert parse_x_forwarded(["a, b", "c"]) == ["a", "b", "c"]
node = parse_node("[2001:db8::1]:80")
assert build([{"for": node}]) == 'for="[2001:db8::1]:80"'
assert pickle.loads(pickle.dumps(node)) == node
for call in (
    lambda: parse("for=_a;for=_b", strict=True),
    lambda: build([{"host": "a\r\nX-Admin: 1"}]),
    lambda: parse_node("2001:db8::1"),
):
    try:
        call()
    except ForwardedError as error:
        assert isinstance(error, ValueError)
    else:
        raise AssertionError("expected ForwardedError")
print("e2e ok")
"""


def _run(*cmd: str | Path, cwd: Path | None = None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run([str(c) for c in cmd], cwd=cwd, capture_output=True, check=False)


def _build(tmp_path: Path) -> Path:
    dist = tmp_path / "dist"
    built = _run(sys.executable, "-m", "build", "--outdir", dist, ROOT)
    assert built.returncode == 0, built.stderr
    return dist


def _venv(path: Path) -> Path:
    venv.create(path, with_pip=True)
    return path / ("Scripts" if sys.platform == "win32" else "bin") / "python"


def test_installed_wheel_end_to_end(tmp_path: Path) -> None:
    dist = _build(tmp_path)
    (wheel,) = dist.glob("forwarded-*.whl")
    (sdist,) = dist.glob("forwarded-*.tar.gz")
    names = zipfile.ZipFile(wheel).namelist()
    assert "forwarded/py.typed" in names
    assert not any(name.startswith(("tests/", "scripts/")) for name in names)
    listing = _run(sys.executable, "-m", "tarfile", "-l", sdist).stdout.decode()
    assert "IMPROVEMENTS-round" not in listing
    assert "tests/upstream/MANIFEST.json" in listing
    for fetched in ("rfc7239.txt", "rfc9110.txt", "rfc3986.txt", "mdn-x-forwarded-for.md"):
        assert fetched not in listing, fetched
    assert "tests/test_sources.py" in listing
    assert "scripts/fetch_upstream.py" in listing

    python = _venv(tmp_path / "venv")
    installed = _run(python, "-m", "pip", "install", "-q", wheel)
    assert installed.returncode == 0, installed.stderr

    # Run from an empty folder so the source tree cannot shadow the install.
    work = tmp_path / "work"
    work.mkdir()
    result = _run(python, "-I", "-c", PROGRAM, cwd=work)
    assert result.returncode == 0, result.stderr
    assert result.stdout.decode().strip() == "e2e ok"


UPGRADE = r"""
import pickle, sys
import forwarded
from forwarded import client_from_x_forwarded, parse_node
saved = sys.argv[1]
client = client_from_x_forwarded("6.6.6.6", "203.0.113.9", trusted=["::/1"])
if forwarded.__version__ == "0.2.0":
    open(saved, "wb").write(pickle.dumps(parse_node("[2001:db8::1]:80")))
    print("0.2.0", client.node)
else:
    assert pickle.loads(open(saved, "rb").read()) == parse_node("[2001:db8::1]:80")
    print(forwarded.__version__, client.node)
"""


def test_upgrade_from_the_pypi_release(tmp_path: Path) -> None:
    (wheel,) = _build(tmp_path).glob("forwarded-*.whl")
    python = _venv(tmp_path / "venv")
    saved = tmp_path / "node.pickle"
    work = tmp_path / "work"
    work.mkdir()
    old = _run(python, "-m", "pip", "install", "-q", "--no-cache-dir", "forwarded==0.2.0")
    assert old.returncode == 0, old.stderr
    before = _run(python, "-I", "-c", UPGRADE, saved, cwd=work)
    # 0.2.0 let an IPv6 network trust every IPv4 client (CVE-2026-90711 in proxy-addr).
    assert before.stdout.decode().split() == ["0.2.0", "6.6.6.6"], before.stderr
    new = _run(python, "-m", "pip", "install", "-q", "--upgrade", wheel)
    assert new.returncode == 0, new.stderr
    after = _run(python, "-I", "-c", UPGRADE, saved, cwd=work)
    assert after.stdout.decode().split() == ["1.0.0", "203.0.113.9"], after.stderr
