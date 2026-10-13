"""Build the wheel, install it in a throwaway venv and drive the installed package.

Slow and needs the build backend, so it runs only with PERMSPOLICY_E2E=1.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import venv
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.skipif(
    os.environ.get("PERMSPOLICY_E2E") != "1", reason="set PERMSPOLICY_E2E=1 to build and install"
)

PROGRAM = r"""
import importlib.metadata, importlib.resources
import permspolicy
from permspolicy import (
    KNOWN_FEATURES, RETIRED_FEATURES, Allowlist, PermissionsPolicyError, Policy, build,
    build_allow, build_feature_policy, is_source_expression, parse, parse_allow,
    parse_feature_policy, serialize_origin,
)

assert "site-packages" in permspolicy.__file__, permspolicy.__file__
assert importlib.metadata.version("permspolicy") == permspolicy.__version__
assert importlib.resources.files("permspolicy").joinpath("py.typed").is_file()

policy = parse(['geolocation=(self "https://*.a.example");report-to=ep', b"camera=()"])
assert policy["geolocation"].allows("https://b.a.example")
assert policy["geolocation"].allows("https://s.example", self_origin="https://s.example")
assert policy.report_to == {"geolocation": "ep"} and policy["camera"].disabled
assert parse(build(policy), strict=True) == policy
assert parse("camera=(), @") == Policy()
frame = parse_allow("camera; geolocation 'self' https://a.example/x")
assert frame["camera"] == Allowlist(includes_src=True)
assert build_allow(frame) == "camera 'src'; geolocation 'self' https://a.example"
legacy = parse_feature_policy("fullscreen *; usb 'none'")
assert build(legacy) == "fullscreen=*, usb=()"
assert build_feature_policy(legacy) == "fullscreen *; usb 'none'"
assert serialize_origin("HTTPS://A.example:443/p") == "https://a.example"
assert is_source_expression("https:") and not is_source_expression("'self'")
assert "camera" in KNOWN_FEATURES and "document-domain" in RETIRED_FEATURES
for call in (
    lambda: parse("camera=(self", strict=True),
    lambda: build({"camera": ["https://a.example\r\nSet-Cookie: a"]}),
    lambda: build({"camera": Allowlist(includes_src=True)}),
):
    try:
        call()
    except PermissionsPolicyError as error:
        assert isinstance(error, ValueError)
    else:
        raise AssertionError("expected PermissionsPolicyError")
print("e2e ok")
"""


def _run(
    *cmd: str | Path, cwd: Path | None = None, stdin: bytes = b""
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [str(c) for c in cmd], cwd=cwd, input=stdin, capture_output=True, check=False
    )


def test_installed_wheel_end_to_end(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    built = _run(sys.executable, "-m", "build", "--outdir", dist, ROOT)
    assert built.returncode == 0, built.stderr
    (wheel,) = dist.glob("permspolicy-*.whl")
    (sdist,) = dist.glob("permspolicy-*.tar.gz")
    names = zipfile.ZipFile(wheel).namelist()
    assert "permspolicy/py.typed" in names and "permspolicy/__main__.py" in names
    assert not any(name.startswith(("tests/", "scripts/")) for name in names)
    entry_points = next(name for name in names if name.endswith("entry_points.txt"))
    text = zipfile.ZipFile(wheel).read(entry_points).decode()
    assert "permspolicy = permspolicy._cli:main" in text
    listing = _run(sys.executable, "-m", "tarfile", "-l", sdist).stdout.decode()
    assert "IMPROVEMENTS-round" not in listing and "scratchpad" not in listing
    assert "tests/upstream/MANIFEST.json" in listing
    assert ".bs" not in listing and "rfc9651" not in listing and "upstream/sf" not in listing
    assert "features.md" not in listing
    assert "tests/test_sources.py" in listing and "scripts/fetch_upstream.py" in listing

    env_dir = tmp_path / "venv"
    venv.create(env_dir, with_pip=True)
    bindir = env_dir / ("Scripts" if sys.platform == "win32" else "bin")
    python = bindir / "python"
    installed = _run(python, "-m", "pip", "install", "-q", wheel)
    assert installed.returncode == 0, installed.stderr

    # Run from an empty folder so the source tree cannot shadow the install.
    work = tmp_path / "work"
    work.mkdir()
    result = _run(python, "-I", "-c", PROGRAM, cwd=work)
    assert result.returncode == 0, result.stderr
    assert result.stdout.decode().strip() == "e2e ok"

    script = bindir / ("permspolicy.exe" if sys.platform == "win32" else "permspolicy")
    for command in ([script], [python, "-m", "permspolicy"]):
        shown = _run(*command, "--origin", "https://a.example", cwd=work, stdin=b"camera=*\n")
        assert shown.returncode == 0, shown.stderr
        report = json.loads(shown.stdout)
        assert report["features"]["camera"] == {"allowlist": ["*"], "allows_origin": True}
    converted = _run(script, "--feature-policy", "--to-header", "camera 'self'", cwd=work)
    assert converted.returncode == 0 and converted.stdout.decode().strip() == "camera=(self)"
    failed = _run(script, "--strict", "camera=(self", cwd=work)
    assert failed.returncode == 1 and b"permspolicy: " in failed.stderr
