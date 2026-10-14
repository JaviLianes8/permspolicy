"""Command line: show a policy as JSON, check its feature names, or convert its syntax."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from ._attr import build_allow, parse_allow, parse_feature_policy
from ._errors import PermissionsPolicyError
from ._header import build, parse
from ._model import Policy

EXIT_INVALID = 1


def _report(policy: Policy, args: argparse.Namespace) -> dict[str, object]:
    features: dict[str, object] = {}
    for name, allowlist in policy.items():
        # Separate fields, so a host named "self" cannot be read as the keyword.
        entry: dict[str, object] = {
            "wildcard": allowlist.wildcard,
            "self": allowlist.includes_self,
            "src": allowlist.includes_src,
            "expressions": list(allowlist.expressions),
        }
        if name in policy.report_to:
            entry["report_to"] = policy.report_to[name]
        if args.origin is not None:
            entry["allows_origin"] = allowlist.allows(
                args.origin, self_origin=args.self_origin, src_origin=args.src_origin
            )
        features[name] = entry
    return {"features": features, "unknown": list(policy.unknown())}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="permspolicy",
        description="Read a Permissions-Policy value (or, with --allow or --feature-policy, "
        "the other syntax) from the argument or standard input and print it as JSON, or "
        "convert it. Exit status 1 means an invalid value in --strict mode, a policy the "
        "target syntax cannot hold, or unknown features with --check; 2 a usage error.",
    )
    parser.add_argument("value", nargs="?", help="the value (default: standard input)")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--allow", action="store_true", help="read an iframe allow attribute")
    source.add_argument(
        "--feature-policy", action="store_true", help="read a legacy Feature-Policy value"
    )
    target = parser.add_mutually_exclusive_group()
    target.add_argument("--to-header", action="store_true", help="print a Permissions-Policy")
    target.add_argument("--to-allow", action="store_true", help="print an allow attribute")
    parser.add_argument("--strict", action="store_true", help="reject what the spec ignores")
    parser.add_argument("--check", action="store_true", help="exit 1 on unknown features")
    parser.add_argument("--origin", help="report whether each feature allows this origin")
    parser.add_argument("--self-origin", help="origin of the document holding the policy")
    parser.add_argument("--src-origin", help="origin of the iframe src (with --allow)")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line; returns the process exit code."""
    args = _parser().parse_args(argv)
    # ISO-8859-1 maps every octet, so no input byte can stop the program before parsing.
    text = args.value if args.value is not None else sys.stdin.buffer.read().decode("latin-1")
    text = text.strip(" \t\r\n")
    try:
        if args.allow:
            policy = parse_allow(text, strict=args.strict)
        elif args.feature_policy:
            policy = parse_feature_policy(text, strict=args.strict)
        else:
            policy = parse(text, strict=args.strict)
        if args.to_header:
            print(build(policy))
        elif args.to_allow:
            print(build_allow(policy))
        else:
            print(json.dumps(_report(policy, args), indent=2))
    except PermissionsPolicyError as error:
        print(f"permspolicy: {error}", file=sys.stderr)
        return EXIT_INVALID
    if args.check and policy.unknown():
        print(f"permspolicy: unknown features: {', '.join(policy.unknown())}", file=sys.stderr)
        return EXIT_INVALID
    return 0
