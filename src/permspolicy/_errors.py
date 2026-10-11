"""Error raised when a Permissions-Policy value cannot be serialized."""

from __future__ import annotations


class PermissionsPolicyError(ValueError):
    """A feature name or allowlist cannot be turned into a valid header."""
