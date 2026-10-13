from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

UPSTREAM = Path(__file__).resolve().parent / "upstream"


def read_upstream(name: str) -> str:
    """Return a third-party reference file as text.

    The files are not committed: `python scripts/fetch_upstream.py` fetches them. Their
    tests skip while a file is absent and fail if it differs from the manifest.
    """
    path = UPSTREAM / name
    if not path.is_file():
        pytest.skip(f"{name} is not fetched; run python scripts/fetch_upstream.py")
    entry = json.loads((UPSTREAM / "MANIFEST.json").read_text(encoding="utf-8"))[name]
    body = path.read_bytes()
    assert hashlib.sha256(body).hexdigest() == entry["sha256"], f"{name} differs from MANIFEST"
    return body.decode("utf-8")


@pytest.fixture(scope="session")
def spec() -> str:
    """The Permissions Policy spec source, see tests/upstream/MANIFEST.json."""
    return read_upstream("permissions-policy.bs")


@pytest.fixture(scope="session")
def features_md() -> str:
    """The policy-controlled features list, see tests/upstream/MANIFEST.json."""
    return read_upstream("features.md")


@pytest.fixture(scope="session")
def csp() -> str:
    """The CSP3 spec source, see tests/upstream/MANIFEST.json."""
    return read_upstream("csp.bs")


@pytest.fixture(scope="session")
def rfc9651() -> str:
    """RFC 9651, see tests/upstream/MANIFEST.json."""
    return read_upstream("rfc9651.txt")
