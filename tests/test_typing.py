"""The public API is typed: mypy infers the documented types and rejects wrong ones."""

from __future__ import annotations

import re
import shutil
import subprocess

import pytest
from conftest import UPSTREAM

SRC = UPSTREAM.parents[1] / "src"

SNIPPET = """
from permspolicy import Allowlist, Policy, build, build_allow, parse, parse_allow
from permspolicy import KNOWN_FEATURES, is_source_expression, serialize_origin
reveal_type(parse("camera=()"))
reveal_type(parse("camera=()")["camera"])
reveal_type(parse("camera=()").report_to)
reveal_type(build({"camera": []}))
reveal_type(parse_allow("camera"))
reveal_type(Allowlist.of("self").allows("https://a.example"))
reveal_type(Allowlist.of("self").expressions)
reveal_type(serialize_origin("https://a.example"))
reveal_type(KNOWN_FEATURES)
reveal_type(Policy().unknown())
parse("camera=()", True)
parse(1)
Allowlist.of(1)
Allowlist.of("self").allows("https://a.example", "https://b.example")
build({"camera": 1})
parse([b"camera=()", "geolocation=self"], strict=True)
build(Policy({"camera": "*"}, report_to={"camera": "e"}))
is_source_expression(None)
"""


@pytest.fixture(scope="module")
def mypy_output(tmp_path_factory: pytest.TempPathFactory) -> str:
    folder = tmp_path_factory.mktemp("typing")
    target = folder / "snippet.py"
    target.write_text(SNIPPET, encoding="utf-8")
    config = folder / "mypy.ini"
    config.write_text(f"[mypy]\nmypy_path = {SRC.as_posix()}\n", encoding="utf-8")
    cache = str(folder / "cache")
    args = ["--strict", "--config-file", str(config), "--cache-dir", cache, str(target)]
    try:
        from mypy import api
    except ImportError:
        # The interpreter running pytest may lack mypy while the one on PATH has it.
        program = shutil.which("mypy")
        if program is None:
            pytest.skip("mypy is not installed")
        result = subprocess.run([program, *args], capture_output=True, text=True, check=False)
        return result.stdout + result.stderr
    out, err, _ = api.run(args)
    return str(out) + str(err)


def _revealed(output: str, line: int) -> str:
    match = re.search(rf"snippet\.py:{line}: note: Revealed type is \"(.+)\"", output)
    assert match, output
    # Older mypy releases spell builtins with their module prefix.
    return match.group(1).replace("builtins.", "")


def test_functions_return_plain_types(mypy_output: str) -> None:
    revealed = [_revealed(mypy_output, line) for line in range(4, 14)]
    assert revealed == [
        "permspolicy._model.Policy",
        "permspolicy._model.Allowlist",
        "typing.Mapping[str, str]",
        "str",
        "permspolicy._model.Policy",
        "bool",
        "tuple[str, ...]",
        "str | None",
        "frozenset[str]",
        "tuple[str, ...]",
    ]


def test_misuse_is_rejected(mypy_output: str) -> None:
    for line, code in ((14, "call-arg"), (15, "arg-type"), (16, "arg-type"), (17, "call-arg")):
        assert re.search(rf"snippet\.py:{line}: error: .*\[{code}\]", mypy_output), mypy_output
    assert re.search(r"snippet\.py:18: error: .*\[dict-item\]", mypy_output), mypy_output


def test_documented_calls_type_check(mypy_output: str) -> None:
    for line in (19, 20, 21):
        assert f"snippet.py:{line}:" not in mypy_output, mypy_output
