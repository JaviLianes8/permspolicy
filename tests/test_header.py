"""Parsing the Permissions-Policy header as the spec reads it."""

from __future__ import annotations

import pytest

from permspolicy import Allowlist, PermissionsPolicyError, Policy, parse


def test_self_and_an_origin() -> None:
    policy = parse('geolocation=(self "https://a.example")')
    assert policy["geolocation"] == Allowlist(False, True, False, ("https://a.example",))


def test_an_empty_inner_list_disables_the_feature() -> None:
    assert parse("camera=()")["camera"].disabled


def test_star_alone_or_inside_a_list_means_every_origin() -> None:
    assert parse("fullscreen=*")["fullscreen"] == Allowlist.everyone()
    assert parse('fullscreen=(self * "https://a.example")')["fullscreen"].wildcard


def test_the_bare_token_self() -> None:
    assert parse("geolocation=self")["geolocation"] == Allowlist(includes_self=True)


def test_a_bare_string_holding_a_source_expression() -> None:
    assert parse('payment="https://a.example"')["payment"].expressions == ("https://a.example",)


@pytest.mark.parametrize("value", ['"not a source"', "1", "?1", "other", ":AA==:", "@1", '%"x"'])
def test_a_member_of_any_other_form_is_ignored(value: str) -> None:
    assert parse(f"a=(), b={value}") == Policy({"a": []})


def test_a_member_without_a_value_is_ignored() -> None:
    assert list(parse("geolocation, camera=()")) == ["camera"]


def test_invalid_items_inside_a_list_are_dropped() -> None:
    policy = parse('camera=("https://a.example" 1 ?1 src "x y" self "https://a.example")')
    assert policy["camera"] == Allowlist.of("self", "https://a.example")


@pytest.mark.parametrize(
    "header",
    [
        'geolocation=(self "https://a.example"), @@@',
        "Geo=()",
        "camera=(self",
        "camera=(), ",
        'camera=("https://a.example" , self)',
        "camera=() geolocation=()",
        "camera=(\u00e9)",
        "\tcamera=()",
    ],
)
def test_a_field_that_fails_to_parse_is_ignored_whole(header: str) -> None:
    assert parse(header) == Policy()
    with pytest.raises(PermissionsPolicyError) as caught:
        parse(header, strict=True)
    assert caught.value.offset is not None


def test_report_to_is_read_when_it_is_a_token() -> None:
    policy = parse('geolocation=self;report-to=ep, camera=();report-to="x";other=1')
    assert policy.report_to == {"geolocation": "ep"}
    assert policy["camera"].disabled


def test_the_last_of_repeated_features_wins() -> None:
    policy = parse("camera=*, geolocation=(), camera=()")
    assert list(policy) == ["camera", "geolocation"]
    assert policy["camera"].disabled


def test_several_field_lines_are_joined() -> None:
    policy = parse(["camera=()", b"geolocation=self"])
    assert list(policy) == ["camera", "geolocation"]


def test_bytes_are_read_as_ascii_and_other_octets_fail() -> None:
    assert parse(b"camera=()") == Policy({"camera": []})
    assert parse(b"camera=(\xff)") == Policy()
    assert parse(bytearray(b"camera=*"))["camera"].wildcard


def test_a_line_break_is_not_data() -> None:
    assert parse("a=()\r\nb=*") == Policy()


def test_empty_input_is_an_empty_policy() -> None:
    assert parse("") == Policy()
    assert parse([]) == Policy()
    assert parse("   ", strict=True) == Policy()


@pytest.mark.parametrize("bad", [None, 1, [1], [None]])
def test_other_input_types_raise_type_error(bad: object) -> None:
    with pytest.raises(TypeError):
        parse(bad)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "header",
    [
        "a=1",
        'a=("x y")',
        "a=(self src)",
        'a=self;report-to="x"',
        "a",
        'a=" "',
    ],
)
def test_strict_mode_refuses_what_the_spec_ignores(header: str) -> None:
    with pytest.raises(PermissionsPolicyError):
        parse(header, strict=True)


def test_strict_mode_accepts_valid_policies_and_unknown_parameters() -> None:
    header = 'a=(self "https://*.a.example:*/p/" "https:");report-to=ep;x=1, b=*'
    policy = parse(header, strict=True)
    assert policy == parse(header)
    assert policy.report_to == {"a": "ep"}
