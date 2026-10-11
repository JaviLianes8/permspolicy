"""Read a Permissions-Policy header into a mapping of feature to allowlist."""

from __future__ import annotations

Allowlist = list[str]


def parse(header: str) -> dict[str, Allowlist]:
    """Parse a Permissions-Policy header into ``{feature: allowlist}``.

    An allowlist is a list of tokens and origins: ``["*"]`` means any origin,
    ``[]`` means the feature is disabled, and ``["self", "https://a.example"]``
    lists specific allowlist entries. Malformed members are skipped rather than
    raising, so a partial header still yields whatever is well formed.
    """
    result: dict[str, Allowlist] = {}
    for member in _split_members(header):
        name, _, raw = member.partition("=")
        name = name.strip()
        if not name or "=" not in member:
            continue
        result[name] = _parse_value(raw.strip())
    return result


def _split_members(header: str) -> list[str]:
    """Split the header on top-level commas, respecting quotes and parentheses."""
    members: list[str] = []
    current: list[str] = []
    in_quotes = False
    depth = 0
    escaped = False
    for char in header:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\" and in_quotes:
            current.append(char)
            escaped = True
        elif char == '"':
            in_quotes = not in_quotes
            current.append(char)
        elif char == "(" and not in_quotes:
            depth += 1
            current.append(char)
        elif char == ")" and not in_quotes and depth > 0:
            depth -= 1
            current.append(char)
        elif char == "," and not in_quotes and depth == 0:
            members.append("".join(current))
            current = []
        else:
            current.append(char)
    members.append("".join(current))
    return [m for m in members if m.strip()]


def _parse_value(raw: str) -> Allowlist:
    if raw == "*":
        return ["*"]
    if raw.startswith("(") and raw.endswith(")"):
        return _parse_items(raw[1:-1])
    if not raw:
        return []
    return _parse_items(raw)


def _parse_items(inner: str) -> Allowlist:
    items: list[str] = []
    token: list[str] = []
    in_quotes = False
    escaped = False
    quoted = False
    for char in inner:
        if escaped:
            token.append(char)
            escaped = False
        elif char == "\\" and in_quotes:
            escaped = True
        elif char == '"':
            in_quotes = not in_quotes
            quoted = True
        elif char.isspace() and not in_quotes:
            if quoted or token:
                items.append("".join(token))
            token = []
            quoted = False
        else:
            token.append(char)
    if quoted or token:
        items.append("".join(token))
    return items
