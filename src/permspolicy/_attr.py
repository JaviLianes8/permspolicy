"""The ASCII policy syntax of the iframe ``allow`` attribute and the legacy Feature-Policy."""

from __future__ import annotations

import re
from collections.abc import Mapping

from ._errors import PermissionsPolicyError
from ._model import Allowlist, AllowlistLike, Policy
from ._origin import ascii_lower, serialize_origin
from ._source import is_source_expression

_FEATURE_ID = re.compile(r"[A-Za-z0-9-]+")
_ASCII_WHITESPACE = re.compile(r"[\t\n\f\r ]+")
_NONE = "'none'"


def _directive(value: str, *, attribute: bool, strict: bool) -> Policy:
    """Run "Parse policy directive"; ``attribute`` says whether a target origin exists."""
    if not isinstance(value, str):
        raise TypeError(f"a policy directive is a str, got {type(value).__name__}")
    directive: dict[str, Allowlist] = {}
    for declaration in value.split(";"):
        tokens = [token for token in _ASCII_WHITESPACE.split(declaration) if token]
        if not tokens:
            continue
        name, targetlist = tokens[0], tokens[1:]
        if strict and not _FEATURE_ID.fullmatch(name):
            raise PermissionsPolicyError(f"{name!r} is not a feature identifier")
        if "*" in targetlist:
            directive[name] = Allowlist.everyone()
            continue
        has_self, has_src = False, attribute and not targetlist
        origins: list[str] = []
        for element in targetlist:
            keyword = ascii_lower(element)
            if keyword == "'self'":
                has_self = True
            elif attribute and keyword == "'src'":
                has_src = True
            else:
                origin = serialize_origin(element)
                if origin is not None and is_source_expression(origin):
                    if origin not in origins:
                        origins.append(origin)
                elif strict and keyword != _NONE:
                    raise PermissionsPolicyError(f"{name}: {element!r} is not an origin")
        directive[name] = Allowlist(False, has_self, has_src, tuple(origins))
    return Policy(directive)


def parse_allow(value: str, *, strict: bool = False) -> Policy:
    """Parse an iframe ``allow`` attribute, such as ``"camera; geolocation 'self'"``.

    Declarations are split on ``;`` and then on ASCII whitespace. ``'self'`` and ``'src'``
    are matched without regard to case, a feature with no entries allows the ``src``
    origin, ``*`` anywhere allows every origin, and other entries are read as URLs and
    reduced to their origin (``https://a.example/x`` gives ``https://a.example``).
    Entries that are not URLs with a tuple origin, ``'none'`` included, are dropped;
    ``strict=True`` raises :class:`PermissionsPolicyError` for them (except ``'none'``)
    and for names that are not feature identifiers.
    """
    return _directive(value, attribute=True, strict=strict)


def parse_feature_policy(value: str, *, strict: bool = False) -> Policy:
    """Parse a legacy ``Feature-Policy`` header value, such as ``"camera 'none'; fullscreen *"``.

    The syntax is the one of :func:`parse_allow`, read without a target origin as the spec
    algorithm does: ``'src'`` is dropped and a feature with no entries is disabled.
    """
    return _directive(value, attribute=False, strict=strict)


def _serialize(policy: Policy | Mapping[str, AllowlistLike], *, attribute: bool) -> str:
    if not isinstance(policy, Policy):
        policy = Policy(policy)
    if policy.report_to:
        raise PermissionsPolicyError("report-to exists only in the Permissions-Policy header")
    declarations: list[str] = []
    for name, allowlist in policy.items():
        if not _FEATURE_ID.fullmatch(name):
            raise PermissionsPolicyError(f"{name!r} is not a feature identifier")
        if allowlist.includes_src and not attribute:
            raise PermissionsPolicyError(f"{name}: 'src' exists only in the allow attribute")
        for expression in allowlist.expressions:
            # The attribute reads entries with the URL parser, which drops anything that is
            # not a URL (a bare host, a scheme alone): refuse those instead of losing them.
            if serialize_origin(expression) != expression:
                raise PermissionsPolicyError(f"{name}: {expression!r} is not a serialized origin")
        entries = ["'self'"] * allowlist.includes_self + ["'src'"] * allowlist.includes_src
        entries += list(allowlist.expressions)
        if allowlist.wildcard:
            entries = ["*"]
        declarations.append(f"{name} {' '.join(entries) or _NONE}")
    return "; ".join(declarations)


def build_allow(policy: Policy | Mapping[str, AllowlistLike]) -> str:
    """Serialize a policy as an iframe ``allow`` attribute value.

    An empty allowlist is written ``'none'`` (an empty one would mean ``'src'``). Entries
    must be serialized origins (``https://a.example``); ``report-to`` and names that are
    not feature identifiers raise :class:`PermissionsPolicyError`.
    """
    return _serialize(policy, attribute=True)


def build_feature_policy(policy: Policy | Mapping[str, AllowlistLike]) -> str:
    """Serialize a policy as a legacy ``Feature-Policy`` value; ``src`` is refused."""
    return _serialize(policy, attribute=False)
