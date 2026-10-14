"""Error raised for a policy that cannot be built or a value that fails a strict parse."""

from __future__ import annotations


class PermissionsPolicyError(ValueError):
    """A policy that cannot be serialized, or a value that fails a strict parse.

    ``offset`` is the position in the field value where a strict parse stopped, or None
    when the error is not about a position in a value.
    """

    def __init__(self, message: str, offset: int | None = None) -> None:
        super().__init__(message)
        self.offset = offset
