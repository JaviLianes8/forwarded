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


def test_comma_inside_a_quoted_value_does_not_split_the_element() -> None:
    assert parse('host="a,b"') == [{"host": "a,b"}]


def test_parameter_names_are_lower_cased() -> None:
    assert parse("For=x;PROTO=https") == [{"for": "x", "proto": "https"}]


def test_host_and_proto_and_by_together() -> None:
    header = 'by=203.0.113.43;for=192.0.2.60;host="example.com:8080";proto=https'
    assert parse(header) == [
        {
            "by": "203.0.113.43",
            "for": "192.0.2.60",
            "host": "example.com:8080",
            "proto": "https",
        }
    ]


def test_obfuscated_identifiers_are_preserved() -> None:
    assert parse("for=_hidden, for=_SEVKISEK") == [{"for": "_hidden"}, {"for": "_SEVKISEK"}]


def test_escaped_quote_inside_a_quoted_value() -> None:
    assert parse(r'host="a\"b"') == [{"host": 'a"b'}]


def test_malformed_segments_are_skipped() -> None:
    assert parse("for=192.0.2.60; garbage ;;proto=http") == [{"for": "192.0.2.60", "proto": "http"}]


def test_empty_header_yields_no_elements() -> None:
    assert parse("") == []


def test_trailing_comma_does_not_add_an_empty_element() -> None:
    assert parse("for=192.0.2.60,") == [{"for": "192.0.2.60"}]
