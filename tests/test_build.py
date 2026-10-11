import pytest

from permspolicy import PermissionsPolicyError, build, parse


def test_build_self_and_origin_quotes_the_origin() -> None:
    header = build({"geolocation": ["self", "https://a.example"]})
    assert header == 'geolocation=(self "https://a.example")'


def test_build_empty_allowlist_is_parentheses() -> None:
    assert build({"camera": []}) == "camera=()"


def test_build_star_is_bare() -> None:
    assert build({"fullscreen": ["*"]}) == "fullscreen=*"


def test_build_joins_features_with_commas() -> None:
    header = build({"geolocation": ["self"], "camera": []})
    assert header == "geolocation=(self), camera=()"


def test_build_escapes_quotes_in_an_origin() -> None:
    assert build({"x": ['a"b']}) == 'x=("a\\"b")'


def test_build_rejects_star_mixed_with_other_entries() -> None:
    with pytest.raises(PermissionsPolicyError):
        build({"geolocation": ["*", "self"]})


def test_build_rejects_an_invalid_feature_name() -> None:
    with pytest.raises(PermissionsPolicyError):
        build({"bad name": ["self"]})


def test_build_of_empty_mapping_is_empty() -> None:
    assert build({}) == ""


@pytest.mark.parametrize(
    "header",
    [
        'geolocation=(self "https://a.example"), camera=(), fullscreen=*',
        'payment=("https://a.example" "https://b.example")',
        "microphone=(self)",
    ],
)
def test_round_trip_parse_then_build(header: str) -> None:
    assert build(parse(header)) == header
