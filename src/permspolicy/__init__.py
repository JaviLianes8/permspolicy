"""Parse, build and check Permissions-Policy headers and iframe allow attributes."""

from __future__ import annotations

from ._attr import build_allow, build_feature_policy, parse_allow, parse_feature_policy
from ._errors import PermissionsPolicyError
from ._features import (
    EXPERIMENTAL_FEATURES,
    KNOWN_FEATURES,
    PROPOSED_FEATURES,
    RETIRED_FEATURES,
    STANDARDIZED_FEATURES,
)
from ._header import build, parse
from ._model import Allowlist, Policy
from ._origin import serialize_origin
from ._source import is_source_expression

__version__ = "0.2.0"

__all__ = [
    "EXPERIMENTAL_FEATURES",
    "KNOWN_FEATURES",
    "PROPOSED_FEATURES",
    "RETIRED_FEATURES",
    "STANDARDIZED_FEATURES",
    "Allowlist",
    "PermissionsPolicyError",
    "Policy",
    "build",
    "build_allow",
    "build_feature_policy",
    "is_source_expression",
    "parse",
    "parse_allow",
    "parse_feature_policy",
    "serialize_origin",
]
