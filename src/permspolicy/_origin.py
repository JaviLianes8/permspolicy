"""Reduce a URL to its origin, for the special schemes whose origin is a tuple."""

from __future__ import annotations

import re
from typing import NamedTuple

DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443, "ftp": 21}
_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*")
# WHATWG URL: forbidden domain code points (C0 controls, space, DEL and these delimiters).
_FORBIDDEN = frozenset("#%/:<>?@[\\]^|") | {chr(code) for code in range(0x21)} | {"\x7f"}
_DECIMAL = re.compile(r"0|[1-9][0-9]{0,2}")
_C0_OR_SPACE = "".join(chr(code) for code in range(0x21))
_LOWER = {code: code + 32 for code in range(ord("A"), ord("Z") + 1)}


class Origin(NamedTuple):
    """A tuple origin: lower-case scheme and host, and a port that is None when default."""

    scheme: str
    host: str
    port: int | None

    def serialize(self) -> str:
        port = "" if self.port is None else f":{self.port}"
        return f"{self.scheme}://{self.host}{port}"


def ascii_lower(text: str) -> str:
    # str.lower() also folds non-ASCII letters (the Kelvin sign becomes "k").
    return text.translate(_LOWER)


def _ends_in_number(last: str) -> bool:
    # WHATWG URL "ends in a number": all digits, or 0x followed by hex digits (maybe none).
    if last.isdigit():
        return True
    return last.startswith("0x") and all(char in "0123456789abcdef" for char in last[2:])


def _host(text: str) -> str | None:
    if not text or not text.isascii() or any(char in _FORBIDDEN for char in text):
        # Non-ASCII hosts need IDNA processing and IPv6 literals hold brackets; neither is
        # reduced here, so the entry is refused rather than guessed.
        return None
    host = ascii_lower(text)
    labels = host.split(".")
    last = labels[-2] if labels[-1] == "" and len(labels) > 1 else labels[-1]
    if _ends_in_number(last):
        # A host ending in a number is an IPv4 address. Only the dotted decimal form is
        # accepted; the WHATWG short and hex forms are refused, not normalized.
        parts = host.split(".")
        if len(parts) != 4 or not all(_DECIMAL.fullmatch(p) and int(p) < 256 for p in parts):
            return None
    return host


def parse_origin(url: str) -> Origin | None:
    """Return the tuple origin of ``url``, or None when it fails or the origin is opaque."""
    if not isinstance(url, str):
        raise TypeError(f"a URL is a str, got {type(url).__name__}")
    text = url.strip(_C0_OR_SPACE).replace("\t", "").replace("\n", "").replace("\r", "")
    scheme, colon, rest = text.partition(":")
    if not colon or not _SCHEME.fullmatch(scheme):
        return None
    scheme = ascii_lower(scheme)
    if scheme == "blob":
        inner = parse_origin(rest)
        return inner if inner is not None and inner.scheme in ("http", "https") else None
    if scheme not in DEFAULT_PORTS:
        return None
    rest = rest.lstrip("/\\")
    authority = re.split(r"[/\\?#]", rest, maxsplit=1)[0]
    hostport = authority.rpartition("@")[2]
    host_text, _, port_text = hostport.partition(":")
    host = _host(host_text)
    if host is None or any(char not in "0123456789" for char in port_text):
        return None
    digits = port_text.lstrip("0") or ("0" if port_text else "")
    if len(digits) > 5 or (digits and int(digits) > 65535):
        return None
    port = int(digits) if digits else None
    return Origin(scheme, host, None if port == DEFAULT_PORTS[scheme] else port)


def serialize_origin(url: str) -> str | None:
    """Serialize the origin of ``url`` (``https://a.example:8443``), or None.

    None means the URL does not parse or its origin is opaque (``data:``, ``file:``, a
    custom scheme). Only http, https, ws, wss and ftp have tuple origins, plus ``blob:``
    URLs whose inner URL is http or https. Hosts are lower-cased and a default port is
    dropped. Non-ASCII hosts, IPv6 literals and short IPv4 forms are refused.
    """
    origin = parse_origin(url)
    return None if origin is None else origin.serialize()
