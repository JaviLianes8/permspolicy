"""CSP source expressions: the grammar of an allowlist entry and how it matches an origin."""

from __future__ import annotations

import re
from typing import NamedTuple
from urllib.parse import unquote_to_bytes

from ._origin import DEFAULT_PORTS, Origin, ascii_lower

# CSP3 section 2.3.1: scheme-source and host-source. The pattern is the ABNF, written out.
_SCHEME = r"[A-Za-z][A-Za-z0-9+\-.]*"
_HOST = r"\*|(?:\*\.)?[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.?"
_PCHAR = r"(?:[A-Za-z0-9\-._~!$&'()*+=:@]|%[0-9A-Fa-f]{2})"
# path-absolute (RFC 3986 section 3.3) without ";" and ",", as CSP3 asks.
_PATH = rf"/(?:{_PCHAR}+(?:/{_PCHAR}*)*)?"
_SCHEME_SOURCE = re.compile(rf"({_SCHEME}):")
_HOST_SOURCE = re.compile(rf"(?:({_SCHEME})://)?({_HOST})(?::([0-9]+|\*))?({_PATH})?")


class Source(NamedTuple):
    """A parsed source expression; ``host`` is None for a scheme-source."""

    scheme: str | None
    host: str | None
    port: str | None
    path: str


def parse_source(text: str) -> Source | None:
    """Split a scheme-source or host-source into its parts, or None when it is neither."""
    match = _SCHEME_SOURCE.fullmatch(text)
    if match:
        return Source(match.group(1), None, None, "")
    match = _HOST_SOURCE.fullmatch(text)
    if match:
        return Source(match.group(1), match.group(2), match.group(3), match.group(4) or "")
    return None


def is_source_expression(text: object) -> bool:
    """True when ``text`` is a valid permissions-source-expression.

    That is a CSP3 ``scheme-source`` (``https:``) or ``host-source``
    (``https://*.a.example:443/path``, ``a.example``), the only entries an allowlist
    String may hold. Keywords such as ``'self'`` are not source expressions here.
    """
    return isinstance(text, str) and parse_source(text) is not None


def _scheme_matches(pattern: str, scheme: str) -> bool:
    pattern = ascii_lower(pattern)
    upgrades = {"http": ("https",), "ws": ("wss", "http", "https"), "wss": ("https",)}
    return pattern == scheme or scheme in upgrades.get(pattern, ())


def _host_matches(pattern: str, host: str) -> bool:
    if host.replace(".", "").isdigit():
        return False  # an IPv4 address is not a domain, and only domains match
    if pattern == "*":
        return True
    if pattern.startswith("*."):
        return host.endswith(ascii_lower(pattern[1:]))
    return ascii_lower(pattern) == host


def _port_matches(pattern: str | None, origin: Origin) -> bool:
    if pattern == "*":
        return True
    digits = None if pattern is None else pattern.lstrip("0") or "0"
    if digits is not None and len(digits) > 5:
        return False  # larger than any port, and int() of a huge string is refused
    wanted = None if digits is None else int(digits)
    if wanted == origin.port:
        return True
    return origin.port is None and wanted == DEFAULT_PORTS[origin.scheme]


def _path_matches(pattern: str, path: str) -> bool:
    if not pattern or (pattern == "/" and not path):
        return True
    exact = not pattern.endswith("/")
    pieces, targets = pattern.split("/"), path.split("/")
    if len(pieces) > len(targets) or (exact and len(pieces) != len(targets)):
        return False
    if not exact:
        pieces.pop()
    pairs = zip(pieces, targets[: len(pieces)], strict=True)
    return all(unquote_to_bytes(a) == unquote_to_bytes(b) for a, b in pairs)


def source_matches(text: str, origin: Origin) -> bool:
    """Run CSP3 "Does url match expression in origin" for the URL of ``origin``.

    The Permissions Policy "matches" algorithm passes the candidate origin as both the
    URL (its serialization, whose path is "/") and the origin, with a redirect count of 0.
    """
    source = parse_source(text)
    if source is None:
        return False
    if source.scheme is not None and not _scheme_matches(source.scheme, origin.scheme):
        return False
    if source.host is None:
        return True
    return (
        _host_matches(source.host, origin.host)
        and _port_matches(source.port, origin)
        and _path_matches(source.path, "/")
    )
