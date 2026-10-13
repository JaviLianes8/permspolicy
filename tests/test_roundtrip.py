"""Seeded random policies round trip, and random text never raises an undocumented error."""

from __future__ import annotations

import contextlib
import random
import string

from permspolicy import (
    Allowlist,
    PermissionsPolicyError,
    Policy,
    build,
    build_allow,
    build_feature_policy,
    parse,
    parse_allow,
    parse_feature_policy,
    serialize_origin,
)

SCHEMES = ["http", "https", "ws", "wss", "ftp"]
LABEL = string.ascii_lowercase + string.digits + "-"


def _origin(rng: random.Random) -> str:
    while True:
        host = ".".join("".join(rng.choices(LABEL, k=rng.randint(1, 6))) for _ in range(2))
        port = rng.choice(["", f":{rng.randint(1, 65535)}"])
        origin = serialize_origin(f"{rng.choice(SCHEMES)}://{host}{port}")
        if origin is not None:  # hosts ending in a number must be IPv4 and mostly are not
            return origin


def _expression(rng: random.Random) -> str:
    kind = rng.randrange(4)
    if kind == 0:
        return rng.choice(SCHEMES) + ":"
    if kind == 1:
        return "*." + _origin(rng).split("://", 1)[1]
    if kind == 2:
        return _origin(rng) + rng.choice(["", "/", "/a/", "/a%20b"])
    return _origin(rng)


def _allowlist(rng: random.Random, expression: bool) -> Allowlist:
    if rng.random() < 0.1:
        return Allowlist.everyone()
    pick = _expression if expression else _origin
    entries = {pick(rng) for _ in range(rng.randint(0, 4))}
    return Allowlist(False, rng.random() < 0.5, False, tuple(sorted(entries)))


def _name(rng: random.Random) -> str:
    return rng.choice(string.ascii_lowercase) + "".join(rng.choices(LABEL, k=rng.randint(0, 8)))


def test_random_headers_round_trip_strictly() -> None:
    rng = random.Random(9651)
    for _ in range(3000):
        features = {_name(rng): _allowlist(rng, True) for _ in range(rng.randint(0, 5))}
        endpoints = {name: _name(rng) for name in features if rng.random() < 0.3}
        policy = Policy(features, endpoints)
        assert parse(build(policy), strict=True) == policy


def test_random_attributes_round_trip_strictly() -> None:
    rng = random.Random(2024)
    for _ in range(2000):
        policy = Policy({_name(rng): _allowlist(rng, False) for _ in range(rng.randint(0, 5))})
        assert parse_allow(build_allow(policy), strict=True) == policy
        assert parse_feature_policy(build_feature_policy(policy), strict=True) == policy


def test_random_text_never_raises_anything_else() -> None:
    rng = random.Random(1)
    alphabet = string.printable + "\x00\x7f\u00e9\u212a()\"';=,*"
    for _ in range(5000):
        text = "".join(rng.choices(alphabet, k=rng.randint(0, 40)))
        for read in (parse, parse_allow, parse_feature_policy):
            read(text)
            with contextlib.suppress(PermissionsPolicyError):
                read(text, strict=True)
        serialize_origin(text)
        assert isinstance(Allowlist.everyone().allows(text), bool)
