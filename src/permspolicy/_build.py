"""Serialize a mapping of feature to allowlist into a Permissions-Policy header."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence

from ._errors import PermissionsPolicyError

_FEATURE = re.compile(r"[a-zA-Z*][a-zA-Z0-9_.*-]*")
_BARE_KEYWORDS = frozenset({"self"})


def build(features: Mapping[str, Sequence[str]]) -> str:
    """Build a Permissions-Policy header from ``{feature: allowlist}``.

    ``["*"]`` serializes to ``*`` (any origin), ``[]`` to ``()`` (disabled), and
    a list of entries to a quoted allowlist, with ``self`` left as a bare token
    and every origin wrapped in a quoted string. Raises
    :class:`PermissionsPolicyError` on an invalid feature name or a ``*`` mixed
    with other entries.
    """
    members = []
    for name, allowlist in features.items():
        members.append(f"{_check_name(name)}={_render(name, list(allowlist))}")
    return ", ".join(members)


def _check_name(name: str) -> str:
    if not _FEATURE.fullmatch(name):
        raise PermissionsPolicyError(f"invalid feature name: {name!r}")
    return name


def _render(name: str, allowlist: list[str]) -> str:
    if "*" in allowlist:
        if allowlist != ["*"]:
            raise PermissionsPolicyError(f"'*' cannot be combined with other entries in {name!r}")
        return "*"
    if not allowlist:
        return "()"
    return "(" + " ".join(_render_item(item) for item in allowlist) + ")"


def _render_item(item: str) -> str:
    if item in _BARE_KEYWORDS:
        return item
    escaped = item.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'
