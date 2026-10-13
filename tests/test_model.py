"""Allowlist and Policy: validated, immutable values."""

from __future__ import annotations

import dataclasses

import pytest

from permspolicy import Allowlist, PermissionsPolicyError, Policy


def test_of_reads_keywords_and_expressions_in_order_without_repeats() -> None:
    allowlist = Allowlist.of("https://b.example", "self", "src", "https://b.example", "https:")
    assert allowlist == Allowlist(False, True, True, ("https://b.example", "https:"))
    assert allowlist.entries() == ("self", "src", "https://b.example", "https:")


def test_everyone_and_nobody() -> None:
    assert Allowlist.everyone().entries() == ("*",)
    assert Allowlist.nobody().disabled and not Allowlist.everyone().disabled
    assert Allowlist.of("*") == Allowlist.everyone()


@pytest.mark.parametrize(
    "fields",
    [
        {"wildcard": True, "includes_self": True},
        {"wildcard": True, "includes_src": True},
        {"wildcard": True, "expressions": ("https:",)},
        {"expressions": ("https:", "https:")},
        {"expressions": ("'self'",)},
    ],
)
def test_contradictory_or_invalid_fields_are_refused(fields: dict[str, object]) -> None:
    with pytest.raises(PermissionsPolicyError):
        Allowlist(**fields)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "fields", [{"wildcard": 1}, {"includes_self": "yes"}, {"expressions": ["https:"]}]
)
def test_wrong_field_types_raise_type_error(fields: dict[str, object]) -> None:
    with pytest.raises(TypeError):
        Allowlist(**fields)  # type: ignore[arg-type]


def test_of_refuses_non_strings_and_quoted_keywords() -> None:
    with pytest.raises(TypeError):
        Allowlist.of(1)  # type: ignore[arg-type]
    with pytest.raises(PermissionsPolicyError, match="'self'"):
        Allowlist.of("'self'")


def test_an_allowlist_is_frozen_and_hashable() -> None:
    allowlist = Allowlist.of("self")
    with pytest.raises(dataclasses.FrozenInstanceError):
        allowlist.wildcard = True  # type: ignore[misc]
    assert hash(allowlist) == hash(Allowlist(includes_self=True))


def test_a_policy_converts_entries_and_keeps_order() -> None:
    policy = Policy({"b": "*", "a": ("self",), "c": Allowlist.nobody()})
    assert list(policy) == ["b", "a", "c"] and len(policy) == 3
    assert policy["a"] == Allowlist(includes_self=True)
    assert "c" in policy and "z" not in policy


def test_a_policy_is_read_only() -> None:
    policy = Policy({"a": []}, report_to={"a": "e"})
    with pytest.raises(TypeError):
        policy._features["b"] = Allowlist()  # type: ignore[index]
    with pytest.raises(TypeError):
        policy.report_to["a"] = "x"  # type: ignore[index]


def test_policy_equality_includes_report_to() -> None:
    assert Policy({"a": []}) == Policy({"a": Allowlist()})
    assert Policy({"a": []}) != Policy({"a": []}, report_to={"a": "e"})
    assert Policy({"a": []}) != {"a": Allowlist()}
    assert Policy().__eq__(object()) is NotImplemented


def test_a_policy_is_not_hashable() -> None:
    with pytest.raises(TypeError):
        hash(Policy())


def test_the_repr_shows_features_and_endpoints() -> None:
    assert repr(Policy()) == "Policy({})"
    assert "report_to={'a': 'e'}" in repr(Policy({"a": []}, report_to={"a": "e"}))


@pytest.mark.parametrize(("features", "report_to"), [({}, {"a": "e"}), ({"a": []}, {"a": 1})])
def test_report_to_needs_the_feature_and_a_string(
    features: dict[str, list[str]], report_to: dict[str, object]
) -> None:
    with pytest.raises(PermissionsPolicyError):
        Policy(features, report_to=report_to)  # type: ignore[arg-type]


def test_bad_feature_names_and_values_raise_type_error() -> None:
    with pytest.raises(TypeError):
        Policy({1: []})  # type: ignore[dict-item]
    with pytest.raises(TypeError):
        Policy({"a": 1})  # type: ignore[dict-item]


def test_unknown_lists_names_outside_the_features_list() -> None:
    policy = Policy({"camera": [], "made-up": [], "document-domain": []})
    assert policy.unknown() == ("made-up", "document-domain")
    assert policy.unknown(["made-up"]) == ("camera", "document-domain")
