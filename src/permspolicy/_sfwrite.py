"""Structured field serialization for the item types a policy carries (RFC 9651 4.1)."""

from __future__ import annotations

from ._errors import PermissionsPolicyError
from ._sf import ALPHA, KEY_CHARS, LCALPHA, TOKEN_CHARS


def serialize_key(key: str) -> str:
    """Return ``key`` when it is a valid Dictionary or Parameter key."""
    if not key or (key[0] not in LCALPHA and key[0] != "*"):
        raise PermissionsPolicyError(f"{key!r} is not a structured field key")
    if any(char not in KEY_CHARS for char in key):
        raise PermissionsPolicyError(f"{key!r} is not a structured field key")
    return key


def is_token(value: str) -> bool:
    """True when ``value`` can be written as a structured field Token."""
    if not value or (value[0] not in ALPHA and value[0] != "*"):
        return False
    return all(char in TOKEN_CHARS for char in value[1:])


def serialize_string(value: str) -> str:
    """Serialize a String, refusing what a String cannot carry (CR, LF, non-ASCII)."""
    if any(not " " <= char <= "~" for char in value):
        raise PermissionsPolicyError(f"{value!r} holds characters a String cannot carry")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
