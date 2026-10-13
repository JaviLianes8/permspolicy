"""Origins, source expressions and the "matches" algorithm."""

from __future__ import annotations

import pytest

from permspolicy import Allowlist, is_source_expression, serialize_origin


@pytest.mark.parametrize(
    ("url", "origin"),
    [
        ("https://a.example", "https://a.example"),
        ("HTTPS://A.Example:443/path?q#f", "https://a.example"),
        ("http://a.example:80", "http://a.example"),
        ("http://a.example:0080", "http://a.example"),
        ("https://a.example:8443", "https://a.example:8443"),
        ("https://a.example:", "https://a.example"),
        ("ws://a.example:80", "ws://a.example"),
        ("wss://a.example:443", "wss://a.example"),
        ("ftp://a.example:21", "ftp://a.example"),
        ("https://user:pw@a.example/", "https://a.example"),
        ("https:a.example", "https://a.example"),
        ("https:" + chr(92) * 2 + "a.example" + chr(92) + "x", "https://a.example"),
        ("  https://a.example\t ", "https://a.example"),
        ("https://a.exa\nmple", "https://a.example"),
        ("https://127.0.0.1:8000", "https://127.0.0.1:8000"),
        ("https://a.example.", "https://a.example."),
        ("https://*.a.example", "https://*.a.example"),
        ("blob:https://a.example/uuid", "https://a.example"),
        ("https://a.example:0", "https://a.example:0"),
        ("https://a.example:65535", "https://a.example:65535"),
    ],
)
def test_origins_of_urls(url: str, origin: str) -> None:
    assert serialize_origin(url) == origin


@pytest.mark.parametrize(
    "url",
    [
        "a.example",
        "data:text/plain,x",
        "file:///etc/passwd",
        "custom://a.example",
        "blob:data:x",
        "blob:ftp://a.example",
        "https://",
        "https:///",
        "https://a.example:65536",
        "https://a.example:999999999999999999999",
        "https://a.example:8x",
        "https://a.example:\u0661",
        "https://[::1]",
        "https://\u00e9.example",
        "https://a%41.example",
        "https://a b.example",
        "https://0x7f.1",
        "https://127.1",
        "https://1.2.3.256",
        "https://01.2.3.4",
        "https://1.2.3.4.",
        "1https://a.example",
        "'self'",
    ],
)
def test_urls_without_a_tuple_origin(url: str) -> None:
    assert serialize_origin(url) is None


@pytest.mark.parametrize(
    "text",
    [
        "https:",
        "custom-scheme.v2+x:",
        "a.example",
        "*.a.example",
        "*",
        "https://*",
        "https://*.a.example:*",
        "https://a.example:443/p/",
        "https://a.example/a%20b/c:d@e",
        "a-b.example.",
        "127.0.0.1",
    ],
)
def test_valid_source_expressions(text: str) -> None:
    assert is_source_expression(text)


@pytest.mark.parametrize(
    "text",
    [
        "",
        "'self'",
        "'none'",
        "https://a.example;x",
        "https://a.example/a,b",
        "https://a.example//x",
        "https://a_b.example",
        "https://*a.example",
        "https://a.*.example",
        "https://[::1]",
        "https://a.example:8x",
        "https://a.example/%zz",
        "1https:",
        "https://a.example\n",
        "\u00e9.example",
        None,
    ],
)
def test_invalid_source_expressions(text: object) -> None:
    assert not is_source_expression(text)


@pytest.mark.parametrize(
    ("expression", "origin", "allowed"),
    [
        ("https://a.example", "https://a.example", True),
        ("https://a.example", "https://A.EXAMPLE:443/x", True),
        ("https://a.example", "http://a.example", False),
        ("http://a.example", "https://a.example", True),
        ("ws://a.example", "https://a.example", True),
        ("wss://a.example", "https://a.example", True),
        ("wss://a.example", "http://a.example", False),
        ("https://a.example", "https://a.example:8443", False),
        ("https://a.example:8443", "https://a.example:8443", True),
        ("https://a.example:443", "https://a.example", True),
        ("http://a.example:443", "https://a.example", True),
        ("https://a.example:*", "https://a.example:1", True),
        ("https://a.example:99999999", "https://a.example", False),
        ("https://*.a.example", "https://b.a.example", True),
        ("https://*.a.example", "https://a.example", False),
        ("https://*.A.example", "https://c.b.a.example", True),
        ("https://*", "https://b.example", True),
        ("*", "https://b.example", True),
        ("a.example", "https://a.example", True),
        ("a.example", "wss://a.example", True),
        ("https:", "https://b.example", True),
        ("http:", "https://b.example", True),
        ("https:", "http://b.example", False),
        ("https://a.example/", "https://a.example", True),
        ("https://a.example/x", "https://a.example", False),
        ("https://a.example/x/", "https://a.example", False),
        ("https://127.0.0.1", "https://127.0.0.1", False),
        ("https://a.example", "data:x", False),
        ("https://a.example", "not a url", False),
    ],
)
def test_matching_follows_csp_rules(expression: str, origin: str, allowed: bool) -> None:
    assert Allowlist.of(expression).allows(origin) is allowed


def test_self_and_src_match_only_when_included_and_given() -> None:
    page, frame = "https://page.example", "https://frame.example"
    assert Allowlist.of("self").allows(page, self_origin=page + "/doc")
    assert not Allowlist.of("self").allows(page)
    assert not Allowlist.of("self").allows(frame, self_origin=page)
    assert not Allowlist.nobody().allows(page, self_origin=page)
    assert Allowlist.of("src").allows(frame, src_origin=frame)
    assert not Allowlist.of("src").allows(frame)
    assert not Allowlist.of("self").allows(frame, src_origin=frame)


def test_the_wildcard_allows_even_an_opaque_origin() -> None:
    assert Allowlist.everyone().allows("null")
    assert not Allowlist.of("self", "https:").allows("null", self_origin="null")
