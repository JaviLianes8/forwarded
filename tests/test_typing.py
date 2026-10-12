"""The public API is typed: mypy infers the documented types and rejects wrong ones."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"

SNIPPET = """
from forwarded import Node, build, client_from_forwarded, client_from_x_forwarded, parse
from forwarded import convert_x_forwarded_for, parse_node, parse_x_forwarded
reveal_type(parse("for=_a"))
reveal_type(build([{"for": "_a"}]))
reveal_type(parse_node("_a"))
reveal_type(parse_node("_a").ip)
reveal_type(parse_node("_a").port)
reveal_type(client_from_forwarded(None, "10.0.0.1"))
reveal_type(client_from_x_forwarded(None, "10.0.0.1"))
reveal_type(parse_x_forwarded(["a"]))
reveal_type(convert_x_forwarded_for("a"))
parse("for=_a", True)
build([{"for": 1}])
client_from_forwarded(None, "10.0.0.1", hops="1")
parse(b"for=_a")
build([{"for": Node(name="_a")}])
"""


@pytest.fixture(scope="module")
def mypy_output(tmp_path_factory: pytest.TempPathFactory) -> str:
    folder = tmp_path_factory.mktemp("typing")
    target = folder / "snippet.py"
    target.write_text(SNIPPET, encoding="utf-8")
    config = folder / "mypy.ini"
    config.write_text(f"[mypy]\nmypy_path = {SRC.as_posix()}\n", encoding="utf-8")
    cache = str(folder / "cache")
    args = ["--strict", "--config-file", str(config), "--cache-dir", cache, str(target)]
    try:
        from mypy import api
    except ImportError:
        # The interpreter running pytest may lack mypy while the one on PATH has it.
        program = shutil.which("mypy")
        if program is None:
            pytest.skip("mypy is not installed")
        result = subprocess.run([program, *args], capture_output=True, text=True, check=False)
        return result.stdout + result.stderr
    out, err, _ = api.run(args)
    return str(out) + str(err)


def test_functions_return_plain_types(mypy_output: str) -> None:
    assert [_revealed(mypy_output, line) for line in (4, 5, 6, 9, 10, 11, 12)] == [
        "list[dict[str, str]]",
        "str",
        "forwarded._node.Node",
        "forwarded._client.Client | None",
        "forwarded._client.Client | None",
        "list[str]",
        "str",
    ]


def test_node_fields_are_typed(mypy_output: str) -> None:
    assert _revealed(mypy_output, 7) == "ipaddress.IPv4Address | ipaddress.IPv6Address | None"
    assert _revealed(mypy_output, 8) == "int | str | None"


def test_misuse_is_rejected(mypy_output: str) -> None:
    for line, code in ((13, "call-arg"), (14, "dict-item"), (15, "arg-type"), (16, "arg-type")):
        assert re.search(rf"snippet\.py:{line}: error: .*\[{code}\]", mypy_output), mypy_output


def test_node_values_are_accepted_by_build(mypy_output: str) -> None:
    assert "snippet.py:17:" not in mypy_output, mypy_output


def _revealed(output: str, line: int) -> str:
    match = re.search(rf"snippet\.py:{line}: note: Revealed type is \"(.+)\"", output)
    assert match, output
    # Older mypy releases spell builtins with their module prefix.
    return match.group(1).replace("builtins.", "")
