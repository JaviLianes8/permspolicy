"""Parse and build the HTTP Permissions-Policy header with a typed, zero-dependency API."""

from __future__ import annotations

from ._build import build
from ._errors import PermissionsPolicyError
from ._parse import parse

__version__ = "0.1.0"

__all__ = ["PermissionsPolicyError", "build", "parse"]
