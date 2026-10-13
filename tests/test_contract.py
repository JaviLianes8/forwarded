from __future__ import annotations

import importlib.resources

import forwarded

# The public API. Add every exported name here as the library grows; this list is the
# contract and the test below fails if the module and this list disagree.
PUBLIC_API: list[str] = [
    "Client",
    "ForwardedError",
    "Node",
    "build",
    "client_from_forwarded",
    "client_from_x_forwarded",
    "convert_x_forwarded_for",
    "parse",
    "parse_node",
    "parse_x_forwarded",
]


def test_all_lists_exactly_the_public_api() -> None:
    assert sorted(forwarded.__all__) == sorted(PUBLIC_API)


def test_every_exported_name_resolves() -> None:
    for name in forwarded.__all__:
        assert hasattr(forwarded, name)


def test_exported_objects_live_in_private_modules() -> None:
    for name in forwarded.__all__:
        module = getattr(forwarded, name).__module__
        assert module.startswith("forwarded._"), (name, module)


def test_version_is_a_three_part_string() -> None:
    parts = forwarded.__version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)


def test_the_package_ships_type_information() -> None:
    assert importlib.resources.files("forwarded").joinpath("py.typed").is_file()


def test_forwarded_error_is_a_value_error() -> None:
    assert issubclass(forwarded.ForwardedError, ValueError)
