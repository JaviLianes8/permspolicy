"""The header builder: valid output only, nothing it writes can break the field."""

from __future__ import annotations

import pytest

from permspolicy import Allowlist, PermissionsPolicyError, Policy, build, parse


def test_self_and_an_origin() -> None:
    header = build({"geolocation": ["self", "https://a.example"]})
    assert header == 'geolocation=(self "https://a.example")'


def test_empty_star_and_a_single_entry() -> None:
    assert build({"camera": []}) == "camera=()"
    assert build({"fullscreen": "*"}) == "fullscreen=*"
    assert build({"geolocation": "self"}) == "geolocation=(self)"


def test_features_are_joined_in_order() -> None:
    assert build({"b": ["self"], "a": []}) == "b=(self), a=()"
    assert build({}) == ""


def test_report_to_is_written_as_a_parameter() -> None:
    policy = Policy({"geolocation": ["self"], "camera": []}, report_to={"camera": "ep"})
    assert build(policy) == "geolocation=(self), camera=();report-to=ep"


def test_a_policy_round_trips() -> None:
    header = 'geolocation=(self "https://*.a.example"), camera=(), fullscreen=*;report-to=e'
    assert build(parse(header)) == header


@pytest.mark.parametrize(
    "entry",
    [
        "https://a.example\r\nSet-Cookie: a",
        'https://a.example") , b=(*',
        "'self'",
        "https://a.example path",
        "\u00e9.example",
        "",
    ],
)
def test_entries_that_are_not_sources_are_refused(entry: str) -> None:
    with pytest.raises(PermissionsPolicyError):
        build({"camera": [entry]})


@pytest.mark.parametrize("name", ["Camera", "bad name", "", "a\r\nb", "1a", "a,b"])
def test_names_that_are_not_keys_are_refused(name: str) -> None:
    with pytest.raises(PermissionsPolicyError):
        build({name: []})


def test_a_non_string_name_raises_type_error() -> None:
    with pytest.raises(TypeError):
        build({1: []})  # type: ignore[dict-item]


def test_star_mixed_with_entries_is_refused() -> None:
    with pytest.raises(PermissionsPolicyError):
        build({"geolocation": ["*", "self"]})


def test_src_cannot_appear_in_a_header() -> None:
    with pytest.raises(PermissionsPolicyError, match="src"):
        build({"camera": Allowlist(includes_src=True)})


@pytest.mark.parametrize("endpoint", ["a b", "", "1x", "e\r\n", "\u00e9"])
def test_a_report_to_that_is_not_a_token_is_refused(endpoint: str) -> None:
    with pytest.raises(PermissionsPolicyError):
        build(Policy({"camera": []}, report_to={"camera": endpoint}))
