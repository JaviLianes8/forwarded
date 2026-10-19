from __future__ import annotations

from ipaddress import ip_address

import pytest

from forwarded import ForwardedError, Node, build, parse


def test_build_single_element() -> None:
    assert build([{"for": "192.0.2.60"}]) == "for=192.0.2.60"


def test_build_keeps_token_values_bare() -> None:
    assert build([{"for": "192.0.2.60", "proto": "http"}]) == "for=192.0.2.60;proto=http"


def test_build_quotes_ipv6_identifier_with_port() -> None:
    assert build([{"for": "[2001:db8:cafe::17]:4711"}]) == 'for="[2001:db8:cafe::17]:4711"'


def test_build_quotes_a_host_with_a_port() -> None:
    assert build([{"host": "example.com:8080"}]) == 'host="example.com:8080"'


def test_build_joins_multiple_elements_with_comma_space() -> None:
    elements = [{"for": "192.0.2.43"}, {"for": "198.51.100.17"}]
    assert build(elements) == "for=192.0.2.43, for=198.51.100.17"


def test_build_lower_cases_parameter_names() -> None:
    assert build([{"For": "_x", "PROTO": "https"}]) == "for=_x;proto=https"


def test_build_escapes_quotes_and_backslashes_in_an_extension_value() -> None:
    assert build([{"note": 'a"b\\c'}]) == r'note="a\"b\\c"'
    assert parse(build([{"note": 'a"b\\c'}])) == [{"note": 'a"b\\c'}]


def test_build_of_no_elements_is_empty() -> None:
    assert build([]) == ""


def test_build_writes_a_node_in_rfc_form() -> None:
    node = Node(ip=ip_address("2001:db8::1"), port=8080)
    assert build([{"for": node, "by": Node(name="_proxy")}]) == 'for="[2001:db8::1]:8080";by=_proxy'


def test_build_accepts_any_iterable_of_mappings() -> None:
    assert build({"for": f"_{n}"} for n in range(2)) == "for=_0, for=_1"


def test_round_trip_parse_build_parse() -> None:
    header = 'by=203.0.113.43;for="[2001:db8::1]:8080";host="example.com:8080";proto=https'
    assert build(parse(header)) == header


def test_round_trip_multiple_elements() -> None:
    header = 'for=192.0.2.43, for="[2001:db8:cafe::17]"'
    assert build(parse(header)) == header


@pytest.mark.parametrize("char", ["\r", "\n", "\x00", "\x7f", "\x1b", "\u0100", "\U0001f600"])
def test_build_refuses_characters_a_header_cannot_carry(char: str) -> None:
    with pytest.raises(ForwardedError, match="cannot carry"):
        build([{"note": f"a{char}b"}])


def test_build_refuses_header_injection_through_a_value() -> None:
    with pytest.raises(ForwardedError):
        build([{"host": "example.com\r\nX-Admin: 1"}])


def test_build_allows_tab_space_and_obs_text_in_an_extension() -> None:
    assert build([{"note": "a\tb \xe9"}]) == 'note="a\tb \xe9"'


@pytest.mark.parametrize("name", ["", "a b", "a=b", "for;", "na\u00efve", '"for"'])
def test_build_refuses_names_that_are_not_tokens(name: str) -> None:
    with pytest.raises(ForwardedError, match="not a token"):
        build([{name: "x"}])


def test_build_refuses_names_that_differ_only_in_case() -> None:
    with pytest.raises(ForwardedError, match="twice"):
        build([{"for": "_a", "FOR": "_b"}])


def test_build_refuses_an_empty_element() -> None:
    with pytest.raises(ForwardedError, match="at least one"):
        build([{"for": "_a"}, {}])


@pytest.mark.parametrize(
    "pair",
    [
        {"for": "2001:db8::1"},
        {"for": "example.com"},
        {"by": "192.0.2.1:http"},
        {"for": ""},
        {"host": "exa mple.com"},
        {"host": "a:b"},
        {"proto": "1http"},
        {"proto": "ht tp"},
    ],
)
def test_build_refuses_registered_values_of_the_wrong_syntax(pair: dict[str, str]) -> None:
    with pytest.raises(ForwardedError):
        build([pair])


def test_build_errors_are_value_errors_without_an_offset() -> None:
    with pytest.raises(ValueError) as caught:
        build([{"for": "nope"}])
    assert isinstance(caught.value, ForwardedError)
    assert caught.value.position is None
    assert "offset" not in str(caught.value)


@pytest.mark.parametrize("element", [{1: "x"}, {"for": 1}, {"for": None}])
def test_build_rejects_values_of_the_wrong_type(element: dict[object, object]) -> None:
    with pytest.raises(TypeError):
        build([element])  # type: ignore[list-item]


@pytest.mark.parametrize(
    "elements", [[None], ["for=_a"], [[("for", "_a")]], "for=_a", {"for": "_a"}, 5, None]
)
def test_build_rejects_elements_that_are_not_mappings_with_type_error(elements: object) -> None:
    with pytest.raises(TypeError, match="mapping") as caught:
        build(elements)  # type: ignore[arg-type]
    assert not isinstance(caught.value, ValueError)
