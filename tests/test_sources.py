"""Check the library against the pinned Permissions Policy spec, features list and CSP3.

The files are read from tests/upstream (URL, size and sha256 in MANIFEST.json); these
tests skip until `python scripts/fetch_upstream.py` has fetched them.
"""

from __future__ import annotations

import html
import re

from permspolicy import (
    EXPERIMENTAL_FEATURES,
    PROPOSED_FEATURES,
    RETIRED_FEATURES,
    STANDARDIZED_FEATURES,
    is_source_expression,
    parse,
    parse_allow,
)
from permspolicy._attr import _FEATURE_ID


def _headers(spec: str) -> list[str]:
    return re.findall(r"Permissions-Policy</a>: (.+?)(?:</pre>)?$", spec, flags=re.MULTILINE)


def test_the_feature_sets_hold_exactly_the_listed_names(features_md: str) -> None:
    sections = dict(re.findall(r"^## (\w+) Features\n(.*?)(?=^## )", features_md, re.M | re.S))
    listed = {
        title: {name.strip() for name in re.findall(r"^\| `([^`]+)`", body, flags=re.M)}
        for title, body in sections.items()
    }
    assert listed == {
        "Standardized": STANDARDIZED_FEATURES,
        "Proposed": PROPOSED_FEATURES,
        "Experimental": EXPERIMENTAL_FEATURES,
        "Retired": RETIRED_FEATURES,
    }


def test_the_feature_identifier_rule_matches_the_abnf(spec: str) -> None:
    rule = re.search(r"feature-identifier</dfn> = (.+)", spec)
    assert rule is not None and rule.group(1).strip() == '1*( ALPHA / DIGIT / "-")'
    allowed = {chr(c) for c in range(128) if chr(c).isalnum() or chr(c) == "-"}
    assert {chr(c) for c in range(256) if _FEATURE_ID.fullmatch(chr(c))} == allowed


def test_the_allow_list_keywords_are_the_ones_handled(spec: str) -> None:
    rule = re.search(r"allow-list-value</dfn> = (.+)", spec)
    assert rule is not None
    assert re.findall(r"\"([^\"]+)\"", rule.group(1)) == ["*", "'self'", "'src'", "'none'"]
    policy = parse_allow("a *; b 'self'; c 'src'; d 'none'")
    assert [allowlist.entries() for allowlist in policy.values()] == [
        ("*",),
        ("self",),
        ("src",),
        (),
    ]


def test_the_header_examples_parse_strictly(spec: str) -> None:
    headers = _headers(spec)
    assert len(headers) == 6
    for header in headers:
        assert parse(header, strict=True) == parse(header)
    # Expected meaning from the examples of the spec introduction (see MANIFEST.json).
    assert all(allowlist.disabled for allowlist in parse(headers[0]).values())
    wildcard = parse(headers[3])["geolocation"]
    for origin in ("https://geo.example.com", "https://new.geo2.example.com"):
        assert wildcard.allows(origin)
    assert wildcard.allows("https://example.com")
    assert not parse('geolocation=("https://*.example.com")')["geolocation"].allows(
        "https://example.com"
    )
    ports = parse(headers[5])["geolocation"]
    assert ports.allows("https://example.com:444") and ports.allows("https://example.com:445")
    assert not parse(headers[1])["geolocation"].allows("https://example.com:444")


def _attribute(spec: str, start: str) -> str:
    match = re.search(rf'allow(?:</a>)?="({re.escape(start)}[^"]*)"', spec)
    assert match is not None, start
    return html.unescape(match.group(1))


def test_the_allow_attribute_examples(spec: str) -> None:
    components = parse_allow(_attribute(spec, "camera https://app1"), strict=True)
    assert components["camera"].allows("https://app1.site.com")
    assert components["microphone"].allows("https://app3.site.com")
    assert not components["camera"].allows("https://app2.site.com")
    assert not components["camera"].allows("https://doc1.site.com")
    frame = parse_allow(_attribute(spec, "fullscreen https://example.com"), strict=True)
    assert not frame["fullscreen"].allows("https://example.net", src_origin="https://example.net")
    sync = parse_allow("sync-xhr")
    assert sync["sync-xhr"].allows("https://any.example", src_origin="https://any.example")
    maps = parse_allow(_attribute(spec, "geolocation"))
    assert maps["geolocation"].allows("https://other.com", src_origin="https://other.com/map")


def test_the_source_grammar_examples_of_csp3(csp: str) -> None:
    for label in ("Schemes", "Hosts"):
        line = re.search(rf"; {label}: (.+)", csp)
        assert line is not None
        examples = re.findall(r'"([^"]+)"', line.group(1))
        assert len(examples) == 3
        assert all(is_source_expression(example) for example in examples), examples
    assert is_source_expression("xn--tdaaaaaa.de")
    assert not is_source_expression("\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc.de")


def test_the_host_char_and_port_rules_of_csp3(csp: str) -> None:
    host_char = re.search(r"host-char</dfn>\s+= (.+)", csp)
    port = re.search(r"port-part</dfn>\s+= (.+)", csp)
    assert host_char is not None and port is not None
    assert 'ALPHA</a> / <a>DIGIT</a> / "-"' in host_char.group(1)
    assert re.sub(r"<[^>]+>", "", port.group(1)).strip() == '1*DIGIT / "*"'
    for code in range(128):
        char = chr(code)
        expected = char.isalnum() or char in "-./"  # "." splits labels, "/" starts a path
        assert is_source_expression(f"a{char}b.example") is expected, repr(char)


def test_the_matching_notes_of_csp3(csp: str) -> None:
    assert "`https://example.com/` do not match the URL `http://example.com/`" in csp
    assert not parse('a=("https:" "https://example.com/")')["a"].allows("http://example.com/")
    assert parse('a=("http:")')["a"].allows("https://example.com")
    note = "`*.example.com` <a>`host-part` matches</a>\n  `www.example.com`"
    assert note in csp
    assert parse('a=("*.example.com")')["a"].allows("https://www.example.com")
