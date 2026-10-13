"""The Permissions-Policy header: a structured field Dictionary of feature to allowlist."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from ._errors import PermissionsPolicyError
from ._model import Allowlist, AllowlistLike, Policy
from ._sf import BareItem, DisplayString, Params, Token
from ._sfdict import parse_dictionary
from ._sfwrite import is_token, serialize_key, serialize_string
from ._source import is_source_expression

FieldValue = str | bytes | bytearray | Iterable[str | bytes]


def _line(value: object) -> str:
    if isinstance(value, (bytes, bytearray)):
        # Latin-1 maps every octet, so a non-ASCII octet reaches the parser and fails there.
        return bytes(value).decode("latin-1")
    if isinstance(value, str):
        return value
    raise TypeError(f"a field line is str or bytes, got {type(value).__name__}")


def _join(header: object) -> str:
    if isinstance(header, (str, bytes, bytearray)):
        return _line(header)
    if isinstance(header, Iterable):
        # RFC 9651 section 4.2: field lines are combined with a comma before parsing.
        return ", ".join(_line(line) for line in header)
    raise TypeError(f"a header is str, bytes or field lines, got {type(header).__name__}")


def _is_string(item: object) -> bool:
    return isinstance(item, str) and not isinstance(item, (Token, DisplayString))


def _allowlist(
    name: str, value: BareItem | list[tuple[BareItem, Params]], strict: bool
) -> Allowlist | None:
    if isinstance(value, Token) and value == "*":
        return Allowlist.everyone()
    if isinstance(value, Token) and value == "self":
        return Allowlist(includes_self=True)
    if _is_string(value) and is_source_expression(value):
        return Allowlist(expressions=(str(value),))
    if not isinstance(value, list):
        if strict:
            raise PermissionsPolicyError(f"{name}: {value!r} is not an allowlist")
        return None  # the spec ignores a member of any other form
    items = [item for item, _ in value]
    if any(isinstance(item, Token) and item == "*" for item in items):
        return Allowlist.everyone()
    found_self = False
    expressions: list[str] = []
    for item in items:
        if isinstance(item, Token) and item == "self":
            found_self = True
        elif _is_string(item) and is_source_expression(item):
            if item not in expressions:
                expressions.append(str(item))
        elif strict:
            raise PermissionsPolicyError(f"{name}: {item!r} is not an allowlist entry")
    return Allowlist(includes_self=found_self, expressions=tuple(expressions))


def parse(header: FieldValue, *, strict: bool = False) -> Policy:
    """Parse a Permissions-Policy (or Permissions-Policy-Report-Only) field value.

    ``header`` is the value as str or bytes, or a sequence of field lines, which are
    joined with a comma. A value that is not a valid structured field Dictionary is
    ignored as a whole and gives an empty Policy, as browsers do; within a valid
    Dictionary, entries the spec ignores are dropped. With ``strict=True`` both cases
    raise :class:`PermissionsPolicyError` instead, with ``offset`` set for syntax errors.
    Feature names are not filtered: see :meth:`Policy.unknown`.
    """
    text = _join(header)
    try:
        members = parse_dictionary(text)
    except PermissionsPolicyError:
        if strict:
            raise
        return Policy()
    features: dict[str, Allowlist] = {}
    report_to: dict[str, str] = {}
    for name, (value, params) in members.items():
        allowlist = _allowlist(name, value, strict)
        if allowlist is None:
            continue
        features[name] = allowlist
        endpoint = params.get("report-to")
        if isinstance(endpoint, Token):
            report_to[name] = str(endpoint)
        elif endpoint is not None and strict:
            raise PermissionsPolicyError(f"{name}: report-to must be a Token, got {endpoint!r}")
    return Policy(features, report_to)


def build(policy: Policy | Mapping[str, AllowlistLike]) -> str:
    """Serialize a policy as a Permissions-Policy field value.

    ``policy`` is a :class:`Policy` or a mapping of feature name to an
    :class:`Allowlist` or its entries (``["self", "https://a.example"]``, ``"*"``, ``[]``).
    Feature names must be structured field keys (lower case), entries must be ``*``,
    ``self`` or source expressions and ``report-to`` endpoints Tokens; anything else
    raises :class:`PermissionsPolicyError`, so the result always parses back to the same
    policy and cannot carry a line break. ``src`` exists only in the ``allow`` attribute
    and is refused here.
    """
    if not isinstance(policy, Policy):
        policy = Policy(policy)
    members: list[str] = []
    for name, allowlist in policy.items():
        key = serialize_key(name)
        if allowlist.includes_src:
            raise PermissionsPolicyError(f"{name}: 'src' cannot appear in a header")
        if allowlist.wildcard:
            value = "*"
        else:
            entries = ["self"] * allowlist.includes_self
            entries += [serialize_string(expression) for expression in allowlist.expressions]
            value = "(" + " ".join(entries) + ")"
        endpoint = policy.report_to.get(name)
        if endpoint is not None:
            if not is_token(endpoint):
                raise PermissionsPolicyError(f"{name}: report-to {endpoint!r} is not a Token")
            value += f";report-to={endpoint}"
        members.append(f"{key}={value}")
    return ", ".join(members)
