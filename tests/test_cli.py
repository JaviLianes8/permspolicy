"""The command line: JSON report, conversions, strict and check exit codes."""

from __future__ import annotations

import io
import json
import sys

import pytest

from permspolicy._cli import main

NONE = {"wildcard": False, "self": False, "src": False, "expressions": []}


def test_a_host_named_self_is_not_the_keyword(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = _run(['camera=(self "self")'], capsys)
    assert code == 0
    assert json.loads(out)["features"]["camera"] == {**NONE, "self": True, "expressions": ["self"]}


def _run(
    args: list[str], capsys: pytest.CaptureFixture[str], stdin: bytes | None = None
) -> tuple[int, str, str]:
    if stdin is not None:
        sys.stdin = io.TextIOWrapper(io.BytesIO(stdin))
    try:
        code = main(args)
    finally:
        sys.stdin = sys.__stdin__
    out, err = capsys.readouterr()
    return code, out, err


def test_the_report_lists_allowlists_endpoints_and_unknown_names(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, out, _ = _run(["camera=();report-to=e, madeup=*"], capsys)
    assert code == 0
    assert json.loads(out) == {
        "features": {
            "camera": {**NONE, "report_to": "e"},
            "madeup": {**NONE, "wildcard": True},
        },
        "unknown": ["madeup"],
    }


def test_origin_checks_use_self_and_src(capsys: pytest.CaptureFixture[str]) -> None:
    args = ["--allow", "camera; mic 'self'", "--origin", "https://f.example"]
    code, out, _ = _run([*args, "--src-origin", "https://f.example"], capsys)
    features = json.loads(out)["features"]
    assert code == 0 and features["camera"]["allows_origin"] is True
    assert features["mic"]["allows_origin"] is False
    code, out, _ = _run([*args, "--self-origin", "https://f.example"], capsys)
    features = json.loads(out)["features"]
    assert features["camera"]["allows_origin"] is False
    assert features["mic"]["allows_origin"] is True


def test_value_from_standard_input(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = _run(["--to-allow"], capsys, stdin=b"  geolocation=(self)\r\n")
    assert code == 0 and out == "geolocation 'self'\n"


def test_non_ascii_input_does_not_crash(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = _run([], capsys, stdin=b"camera=(\xff)")
    assert code == 0 and json.loads(out)["features"] == {}


def test_conversions(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = _run(["--feature-policy", "--to-header", "camera 'none'"], capsys)
    assert code == 0 and out == "camera=()\n"


@pytest.mark.parametrize(
    "args",
    [
        ["--strict", "camera=(self"],
        ["--allow", "--strict", "camera a.example"],
        ["--feature-policy", "--strict", "camera 'src'"],
        ["--allow", "--to-header", "camera"],
        ["--to-allow", 'camera=("https:")'],
    ],
)
def test_invalid_values_exit_one_with_a_message(
    args: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, err = _run(args, capsys)
    assert code == 1 and out == "" and err.startswith("permspolicy: ")


def test_check_exits_one_on_unknown_features(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = _run(["--check", "camera=(), geolocaton=()"], capsys)
    assert code == 1 and "geolocaton" in err and json.loads(out)["unknown"] == ["geolocaton"]
    assert _run(["--check", "camera=()"], capsys)[0] == 0


@pytest.mark.parametrize(
    "args", [["--allow", "--feature-policy", "x"], ["--to-header", "--to-allow", "x"]]
)
def test_conflicting_options_are_a_usage_error(
    args: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as caught:
        main(args)
    assert caught.value.code == 2
