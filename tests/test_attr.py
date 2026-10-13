"""The iframe allow attribute and the legacy Feature-Policy header."""

from __future__ import annotations

import pytest

from permspolicy import (
    Allowlist,
    PermissionsPolicyError,
    Policy,
    build,
    build_allow,
    build_feature_policy,
    parse_allow,
    parse_feature_policy,
)


def test_a_feature_alone_allows_the_src_origin() -> None:
    assert parse_allow("camera") == Policy({"camera": Allowlist(includes_src=True)})


def test_keywords_ignore_case_and_urls_become_origins() -> None:
    policy = parse_allow("geolocation 'SELF' 'Src' HTTPS://A.example:443/x https://a.example")
    assert policy["geolocation"] == Allowlist(False, True, True, ("https://a.example",))


def test_star_anywhere_allows_every_origin() -> None:
    assert parse_allow("fullscreen 'self' *")["fullscreen"] == Allowlist.everyone()


def test_none_and_unparsable_entries_leave_an_empty_allowlist() -> None:
    policy = parse_allow("camera 'none'; mic data:x a.example 'self ' https://[::1]")
    assert policy["camera"].disabled and policy["mic"].disabled


def test_declarations_split_on_semicolons_and_ascii_whitespace() -> None:
    policy = parse_allow(";;  camera\t'self'\n;\x0cgeolocation\r*; ")
    assert list(policy) == ["camera", "geolocation"]
    assert policy["camera"] == Allowlist(includes_self=True)


def test_the_last_of_repeated_features_wins() -> None:
    policy = parse_allow("camera *; mic; camera 'none'")
    assert list(policy) == ["camera", "mic"] and policy["camera"].disabled


def test_feature_policy_has_no_src() -> None:
    policy = parse_feature_policy("camera; geolocation 'self' 'src' https://a.example/p")
    assert policy["camera"].disabled
    assert policy["geolocation"] == Allowlist.of("self", "https://a.example")


def test_origins_outside_the_source_grammar_are_dropped() -> None:
    assert parse_allow("camera https://a_b.example")["camera"].disabled


@pytest.mark.parametrize(
    "value", ["came!ra 'self'", "camera a.example", "camera 'src2'", "camera https://[::1]"]
)
def test_strict_mode_refuses_what_the_algorithm_drops(value: str) -> None:
    with pytest.raises(PermissionsPolicyError):
        parse_allow(value, strict=True)


def test_strict_mode_keeps_none_and_refuses_src_in_feature_policy() -> None:
    assert parse_allow("camera 'none'", strict=True)["camera"].disabled
    with pytest.raises(PermissionsPolicyError):
        parse_feature_policy("camera 'src'", strict=True)


def test_non_string_input_raises_type_error() -> None:
    with pytest.raises(TypeError):
        parse_allow(b"camera")  # type: ignore[arg-type]


def test_build_allow_writes_keywords_quoted_and_none_for_empty() -> None:
    policy = Policy(
        {
            "geolocation": ["self", "https://a.example"],
            "camera": [],
            "fullscreen": "*",
            "mic": "src",
        }
    )
    value = "geolocation 'self' https://a.example; camera 'none'; fullscreen *; mic 'src'"
    assert build_allow(policy) == value
    assert parse_allow(value) == policy


def test_build_feature_policy_round_trips_and_refuses_src() -> None:
    value = "geolocation 'self' https://a.example:8443; camera 'none'"
    assert build_feature_policy(parse_feature_policy(value)) == value
    with pytest.raises(PermissionsPolicyError, match="src"):
        build_feature_policy({"camera": "src"})


@pytest.mark.parametrize(
    "entry", ["https:", "a.example", "https://a.example:443", "https://a.example/"]
)
def test_build_allow_refuses_entries_the_attribute_would_drop(entry: str) -> None:
    with pytest.raises(PermissionsPolicyError, match="serialized origin"):
        build_allow({"camera": [entry]})


def test_build_allow_refuses_report_to_and_bad_names() -> None:
    with pytest.raises(PermissionsPolicyError, match="report-to"):
        build_allow(Policy({"camera": []}, report_to={"camera": "e"}))
    with pytest.raises(PermissionsPolicyError):
        build_allow({"came ra": []})


def test_a_legacy_policy_converts_to_a_header() -> None:
    policy = parse_feature_policy("geolocation 'self' https://a.example; camera 'none'")
    assert build(policy) == 'geolocation=(self "https://a.example"), camera=()'
