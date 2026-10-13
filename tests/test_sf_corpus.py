"""Run the httpwg structured field test corpus against the dictionary parser and writers.

The corpus files are fetched into tests/upstream/sf (see MANIFEST.json); these tests skip
until `python scripts/fetch_upstream.py` has fetched them. List tests are out of scope:
the Permissions-Policy field is a Dictionary.
"""

from __future__ import annotations

import base64
import json
from decimal import Decimal
from typing import Any

import pytest
from conftest import read_upstream

from permspolicy import PermissionsPolicyError
from permspolicy._sf import Date, DisplayString, Reader, Token
from permspolicy._sfdict import parse_dictionary, parse_item
from permspolicy._sfwrite import is_token, serialize_key, serialize_string

FILES = [
    "binary",
    "boolean",
    "date",
    "dictionary",
    "display-string",
    "examples",
    "item",
    "key-generated",
    "large-generated",
    "number",
    "number-generated",
    "param-dict",
    "string",
    "string-generated",
    "token",
    "token-generated",
]


def _plain(value: Any) -> Any:
    """Convert a parsed value to the corpus JSON shape."""
    if isinstance(value, bool):
        return value
    if isinstance(value, Date):
        return {"__type": "date", "value": int(value)}
    if isinstance(value, Token):
        return {"__type": "token", "value": str(value)}
    if isinstance(value, DisplayString):
        return {"__type": "displaystring", "value": str(value)}
    if isinstance(value, bytes):
        return {"__type": "binary", "value": base64.b32encode(value).decode()}
    if isinstance(value, list):
        return [[_plain(item), _params(params)] for item, params in value]
    return value


def _params(params: dict[str, Any]) -> list[list[Any]]:
    return [[key, _plain(value)] for key, value in params.items()]


def _expected(value: Any) -> Any:
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, list):
        return [_expected(item) for item in value]
    return value


def _run_item(text: str) -> Any:
    r = Reader(text)
    if not text.isascii():
        raise r.fail("structured fields are ASCII")
    r.skip(" ")
    item, params = parse_item(r)
    r.skip(" ")
    if not r.done():
        raise r.fail("trailing text")
    return [_plain(item), _params(params)]


def _cases(name: str) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = json.loads(read_upstream(f"sf/{name}.json"))
    return [case for case in cases if case["header_type"] != "list"]


@pytest.mark.parametrize("name", FILES)
def test_the_corpus_file_parses_as_expected(name: str) -> None:
    checked = 0
    for case in _cases(name):
        text = ", ".join(case["raw"])
        must_fail = case.get("must_fail", False)
        try:
            if case["header_type"] == "dictionary":
                parsed = parse_dictionary(text)
                got: Any = [[key, [_plain(v), _params(p)]] for key, (v, p) in parsed.items()]
            else:
                got = _run_item(text)
        except PermissionsPolicyError as error:
            assert must_fail or case.get("can_fail", False), case["name"]
            assert error.offset is not None, case["name"]
        else:
            assert not must_fail, case["name"]
            assert got == _expected(case["expected"]), case["name"]
        checked += 1
    assert checked > 0


def _parses_as_one_key(key: str) -> bool:
    try:
        return list(parse_dictionary(f"{key}=1")) == [key]
    except PermissionsPolicyError:
        return False


def test_the_key_writer_accepts_exactly_the_keys_the_parser_reads() -> None:
    good = bad = 0
    for case in _cases("key-generated"):
        key = case["raw"][0].partition("=")[0]
        if _parses_as_one_key(key):
            assert serialize_key(key) == key, case["name"]
            good += 1
        else:
            with pytest.raises(PermissionsPolicyError):
                serialize_key(key)
            bad += 1
    assert good > 50 and bad > 50


def test_strings_serialize_to_their_canonical_form() -> None:
    checked = 0
    for case in _cases("string-generated") + _cases("string"):
        expected = case.get("expected")
        if case.get("must_fail") or not isinstance(expected, list) or expected[1]:
            continue
        if not isinstance(expected[0], str):
            continue
        assert serialize_string(expected[0]) == (case.get("canonical") or case["raw"])[0]
        checked += 1
    assert checked > 50


def test_tokens_that_parse_are_tokens_to_the_writer() -> None:
    checked = 0
    for case in _cases("token-generated") + _cases("token"):
        expected = case.get("expected")
        if case.get("must_fail") or not isinstance(expected, list):
            continue
        value = expected[0]
        if isinstance(value, dict) and value.get("__type") == "token":
            assert is_token(value["value"]), case["name"]
            checked += 1
    assert checked > 20
