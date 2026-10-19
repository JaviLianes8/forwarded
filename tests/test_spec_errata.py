"""RFC 7239 errata as listed on the RFC Editor's page, fetched (tests/upstream/MANIFEST.json).

No erratum is verified, so the RFC text stands. The two that touch the grammar are read
from the page and checked against the parser.
"""

from __future__ import annotations

import re

from forwarded import parse


def test_no_erratum_of_rfc_7239_is_verified(rfc7239_errata: str) -> None:
    statuses = dict(re.findall(r"Errata-ID: (\d+)\s+Status:\s+(\w+)", rfc7239_errata))
    assert statuses == {"5067": "Reported", "5275": "Reported", "7973": "Rejected"}


def test_erratum_5275_list_form_is_what_strict_mode_reads(rfc7239_errata: str) -> None:
    # The reported correction spells out the comma list that RFC 9110 section 5.6.1 gives.
    rule = 'Forwarded = forwarded-element *(OWS "," OWS forwarded-element)'
    assert rule in " ".join(rfc7239_errata.split())
    for separator in (",", ", ", " ,", "\t,\t", " , "):
        header = f"for=192.0.2.43{separator}for=198.51.100.17"
        assert parse(header, strict=True) == [{"for": "192.0.2.43"}, {"for": "198.51.100.17"}]


def test_erratum_7973_was_rejected_because_names_are_case_insensitive(
    rfc7239_errata: str,
) -> None:
    rejected = rfc7239_errata.split("Errata-ID: 7973", 1)[1]
    assert "Rejected" in rejected
    assert "The parameter names are case-insensitive" in rejected
    header = 'For="[2001:db8:cafe::17]:4711";PROTO=https'
    assert parse(header, strict=True) == [{"for": "[2001:db8:cafe::17]:4711", "proto": "https"}]
