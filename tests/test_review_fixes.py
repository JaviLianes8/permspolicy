"""Regression tests for review findings and for mutants the first mutation run left alive."""

from __future__ import annotations

import time

import pytest

from permspolicy import (
    Allowlist,
    PermissionsPolicyError,
    Policy,
    build,
    parse,
    parse_allow,
    serialize_origin,
)
from permspolicy._sfwrite import serialize_string


def test_strings_spelled_like_keywords_are_hosts_not_keywords() -> None:
    policy = parse('a=("*"), b=("self"), c="self", d="*"')
    assert policy["a"] == Allowlist(expressions=("*",)) and not policy["a"].wildcard
    assert policy["b"] == Allowlist(expressions=("self",))
    assert policy["c"] == Allowlist(expressions=("self",))
    assert policy["d"] == Allowlist(expressions=("*",))
    assert build(policy) == 'a=("*"), b=("self"), c=("self"), d=("*")'


def test_the_string_star_matches_any_origin_ip_addresses_included() -> None:
    star = Allowlist(expressions=("*",))
    assert star.allows("http://192.168.1.1") and star.allows("wss://a.example")


def test_a_src_only_allowlist_is_not_disabled() -> None:
    assert not Allowlist(includes_src=True).disabled


def test_repeated_entries_cost_linear_time() -> None:
    entries = " ".join(f'"https://h{index}.example"' for index in range(20000))
    start = time.perf_counter()
    assert len(parse(f"camera=({entries} {entries})")["camera"].expressions) == 20000
    origins = " ".join(f"https://h{index}.example" for index in range(20000))
    assert len(parse_allow(f"camera {origins} {origins}")["camera"].expressions) == 20000
    assert time.perf_counter() - start < 2.0


@pytest.mark.parametrize(
    ("url", "origin"),
    [
        ("blob:blob:https://a.example", None),
        ("blob:BLOB:https://a.example", None),
        ("http://xn--a.example", None),
        ("http://xn--zz.example", None),
        ("http://xn--.example", None),
        ("http://xn--tdaaaaaa.de", "http://xn--tdaaaaaa.de"),
        ("https://a.0bc", "https://a.0bc"),
        ("https://u@v@c.example", "https://c.example"),
        ("https://a.example:" + "9" * 5000, None),
    ],
)
def test_origin_edge_cases(url: str, origin: str | None) -> None:
    assert serialize_origin(url) == origin


def test_type_errors_are_consistent() -> None:
    with pytest.raises(TypeError):
        Allowlist.everyone().allows(123)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        Policy([("a", "*")])  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        build([("a", "*")])  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        parse({"a": 1})
    with pytest.raises(TypeError):
        Allowlist(expressions=(1,))  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("expression", "origin", "allowed"),
    [
        ("HTTPS:", "https://a.example", True),
        ("http:", "wss://a.example", False),
        ("https://A.Example", "https://a.example", True),
        ("https://a.example:443", "https://a.example:8443", False),
        ("https://a.example:8443", "https://a.example", False),
        ("https://a.example/a/b/", "https://a.example", False),
        ("https://a.example:" + "4" * 5000, "https://a.example", False),
    ],
)
def test_matching_edge_cases(expression: str, origin: str, allowed: bool) -> None:
    assert Allowlist.of(expression).allows(origin) is allowed


NBSP = chr(0xA0)


def test_only_ascii_whitespace_separates_attribute_tokens() -> None:
    policy = parse_allow("camera\x0b'self'; mic" + NBSP + "*")
    assert list(policy) == ["camera\x0b'self'", "mic" + NBSP + "*"]
    assert policy["camera\x0b'self'"] == Allowlist(includes_src=True)


def test_the_last_of_repeated_parameters_wins() -> None:
    assert parse("a=();report-to=x;report-to=y").report_to == {"a": "y"}


@pytest.mark.parametrize("text", ["a\r\nb", chr(0xE9), "\x7f", "a\tb"])
def test_the_string_writer_refuses_what_a_string_cannot_carry(text: str) -> None:
    with pytest.raises(PermissionsPolicyError):
        serialize_string(text)
