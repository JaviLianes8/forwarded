from forwarded import build, parse


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
    assert build([{"For": "x", "PROTO": "https"}]) == "for=x;proto=https"


def test_build_escapes_quotes_in_a_value() -> None:
    assert build([{"host": 'a"b'}]) == r'host="a\"b"'


def test_build_of_no_elements_is_empty() -> None:
    assert build([]) == ""


def test_round_trip_parse_build_parse() -> None:
    header = 'by=203.0.113.43;for="[2001:db8::1]:8080";host="example.com:8080";proto=https'
    assert build(parse(header)) == header


def test_round_trip_multiple_elements() -> None:
    header = 'for=192.0.2.43, for="[2001:db8:cafe::17]"'
    assert build(parse(header)) == header
