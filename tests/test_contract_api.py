"""The 1.0.0 signatures: parameter names, kinds and defaults, and the README table that shows them.

Renaming a parameter, moving it past the `*`, or changing a default breaks callers, so each
signature is pinned here as written for 1.0.0.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path

import pytest

import forwarded

README = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")

SIGNATURES = {
    "Client": "(node, proto=None, host=None, proxies=0)",
    "ForwardedError": "(message, position=None)",
    "Node": "(ip=None, name=None, port=None)",
    "build": "(elements)",
    "client_from_forwarded": "(header, remote, *, trusted=(), hops=None)",
    "client_from_x_forwarded": (
        "(x_forwarded_for, remote, *, proto=None, host=None, trusted=(), hops=None, "
        "proto_hops=1, host_hops=1)"
    ),
    "convert_x_forwarded_for": "(header)",
    "parse": "(header, *, strict=False)",
    "parse_node": "(value)",
    "parse_x_forwarded": "(header)",
}


def _plain(name: str) -> str:
    """The signature without annotations or return type: names, kinds and defaults."""
    parameters = inspect.signature(getattr(forwarded, name)).parameters.values()
    return str(
        inspect.Signature(
            [p.replace(annotation=inspect.Parameter.empty) for p in parameters],
        )
    )


def test_every_public_name_has_a_pinned_signature() -> None:
    assert sorted(SIGNATURES) == sorted(forwarded.__all__)


@pytest.mark.parametrize("name", sorted(SIGNATURES))
def test_the_signature_is_the_one_pinned_for_1_0_0(name: str) -> None:
    assert _plain(name) == SIGNATURES[name]


def test_the_readme_api_table_shows_the_real_signatures() -> None:
    table = README.split("## API", 1)[1].split("\n## ", 1)[0]
    shown = dict(re.findall(r"^\| `(\w+)(\([^`]*\))?`", table, flags=re.MULTILINE))
    assert sorted(shown) == sorted(forwarded.__all__)
    for name, signature in shown.items():
        if signature:
            assert signature == SIGNATURES[name], name


def test_the_classes_are_frozen_and_the_error_is_a_value_error() -> None:
    node = forwarded.Node(name="_a")
    with pytest.raises(AttributeError):
        node.name = "_b"  # type: ignore[misc]
    client = forwarded.Client(node)
    with pytest.raises(AttributeError):
        client.proxies = 3  # type: ignore[misc]
    error = forwarded.ForwardedError("bad", 4)
    assert isinstance(error, ValueError)
    assert error.position == 4
