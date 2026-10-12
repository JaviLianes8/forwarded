from __future__ import annotations

import pytest

from forwarded import parse


def test_single_element_with_one_parameter() -> None:
    assert parse("for=192.0.2.60") == [{"for": "192.0.2.60"}]


def test_single_element_with_several_parameters() -> None:
    header = "for=192.0.2.60;proto=http;by=203.0.113.43"
    assert parse(header) == [{"for": "192.0.2.60", "proto": "http", "by": "203.0.113.43"}]


def test_multiple_comma_separated_elements_keep_order() -> None:
    header = "for=192.0.2.43, for=198.51.100.17"
    assert parse(header) == [{"for": "192.0.2.43"}, {"for": "198.51.100.17"}]


def test_quoted_ipv6_for_value_comes_back_bare() -> None:
    assert parse('for="[2001:db8:cafe::17]:4711"') == [{"for": "[2001:db8:cafe::17]:4711"}]


def test_comma_and_semicolon_inside_a_quoted_value_do_not_split() -> None:
    assert parse('host="a,b;c", for=_x') == [{"host": "a,b;c"}, {"for": "_x"}]


def test_parameter_names_are_lower_cased() -> None:
    assert parse("For=x;PROTO=https") == [{"for": "x", "proto": "https"}]


def test_obfuscated_identifiers_are_preserved() -> None:
    assert parse("for=_hidden, for=_SEVKISEK") == [{"for": "_hidden"}, {"for": "_SEVKISEK"}]


def test_escaped_quote_and_backslash_inside_a_quoted_value() -> None:
    assert parse(r'host="a\"b\\c"') == [{"host": 'a"b\\c'}]


def test_malformed_segments_are_skipped() -> None:
    assert parse("for=192.0.2.60; garbage ;;proto=http") == [{"for": "192.0.2.60", "proto": "http"}]


def test_empty_header_yields_no_elements() -> None:
    assert parse("") == []


def test_empty_list_elements_are_ignored() -> None:
    assert parse(" , for=_a ,, ,for=_b,") == [{"for": "_a"}, {"for": "_b"}]


def test_lenient_mode_allows_whitespace_around_delimiters() -> None:
    assert parse("for = _a ; proto = https") == [{"for": "_a", "proto": "https"}]


def test_lenient_mode_keeps_the_last_duplicate() -> None:
    assert parse("for=_a;FOR=_b;proto=http") == [{"proto": "http", "for": "_b"}]


def test_an_empty_value_is_skipped() -> None:
    assert parse("for=;proto=http") == [{"proto": "http"}]


def test_an_element_without_a_readable_pair_is_dropped() -> None:
    assert parse("junk, for=_a, ;;") == [{"for": "_a"}]


def test_several_lines_form_one_list() -> None:
    assert parse(["for=_a", "for=_b, for=_c"]) == [{"for": "_a"}, {"for": "_b"}, {"for": "_c"}]


def test_lines_can_come_from_any_iterable() -> None:
    assert parse(line for line in ("for=_a", "for=_b")) == [{"for": "_a"}, {"for": "_b"}]


def test_no_lines_yield_no_elements() -> None:
    assert parse([]) == []


def test_a_quote_inside_a_token_does_not_open_a_quoted_string() -> None:
    assert parse('note=a"b, for=_x') == [{"note": 'a"b'}, {"for": "_x"}]


def test_a_quote_inside_a_name_does_not_open_a_quoted_string() -> None:
    assert parse('n"x=1, for=_x') == [{"for": "_x"}]


def test_non_str_lines_are_rejected() -> None:
    with pytest.raises(TypeError, match="must be str"):
        parse([b"for=_a"])  # type: ignore[list-item]
