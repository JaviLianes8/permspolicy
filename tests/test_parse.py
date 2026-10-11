import pytest

from permspolicy import parse


def test_parse_self_and_origin() -> None:
    header = 'geolocation=(self "https://a.example")'
    assert parse(header) == {"geolocation": ["self", "https://a.example"]}


def test_parse_empty_allowlist_disables_the_feature() -> None:
    assert parse("camera=()") == {"camera": []}


def test_parse_star_means_any_origin() -> None:
    assert parse("fullscreen=*") == {"fullscreen": ["*"]}


def test_parse_multiple_features() -> None:
    header = "geolocation=(self), camera=(), fullscreen=*"
    assert parse(header) == {
        "geolocation": ["self"],
        "camera": [],
        "fullscreen": ["*"],
    }


def test_parse_multiple_quoted_origins() -> None:
    header = 'payment=("https://a.example" "https://b.example")'
    assert parse(header) == {"payment": ["https://a.example", "https://b.example"]}


def test_parse_unescapes_quoted_strings() -> None:
    assert parse('x=("a\\"b")') == {"x": ['a"b']}


def test_parse_tolerates_extra_whitespace() -> None:
    header = '  geolocation = ( self   "https://a.example" ) '
    assert parse(header) == {"geolocation": ["self", "https://a.example"]}


def test_parse_skips_members_without_a_value() -> None:
    assert parse("geolocation, camera=()") == {"camera": []}


def test_parse_ignores_a_comma_inside_a_quoted_origin() -> None:
    assert parse('x=("https://a.example,b")') == {"x": ["https://a.example,b"]}


def test_parse_accepts_a_bare_token_without_parentheses() -> None:
    assert parse("geolocation=self") == {"geolocation": ["self"]}


def test_parse_of_empty_header_is_empty() -> None:
    assert parse("") == {}
    assert parse("   ") == {}


@pytest.mark.parametrize("bad", ["=()", ", ,", "   ,   "])
def test_parse_of_malformed_input_does_not_raise(bad: str) -> None:
    assert isinstance(parse(bad), dict)
