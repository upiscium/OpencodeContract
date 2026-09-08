#!/usr/bin/env python3
"""Canonical OpencodeContract command-line interface."""

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

from policy_audit import (
    PROFILE_AGENT_DIRS,
    audit_profile,
    audit_profiles,
    format_summary,
    invalid_consumer_roots,
    result_exit_code,
)
from validate_policy import ROOT, load_policy, validate_policy


def _load_valid_policy() -> tuple[dict, list[str]]:
    errors = validate_policy(ROOT)
    if errors:
        return {}, errors
    documents, parse_errors = load_policy(ROOT)
    return documents, parse_errors


def _print_result(lines: list[str], counts: Counter[str]) -> None:
    for line in lines:
        print(line)
    print(format_summary(counts))


def _policy_error(errors: list[str]) -> int:
    for error in errors:
        print(f"DIFF POLICY_INVALID {error}")
    print(format_summary(Counter(DIFF=len(errors))))
    return 1


def _validate() -> int:
    errors = validate_policy(ROOT)
    if errors:
        for error in errors:
            print(f"ERROR {error}")
        print(f"INVALID ({len(errors)} error(s))")
        return 1
    print("VALID policy contract")
    return 0


def _audit_consumer(profile: str, consumer: Path, strict: bool) -> int:
    consumer = consumer.resolve()
    if not consumer.is_dir():
        print(f"ERROR consumer path is not a directory: {consumer}")
        return 2
    documents, errors = _load_valid_policy()
    if errors:
        return _policy_error(errors)
    lines, counts = audit_profile(profile, consumer, documents)
    _print_result(lines, counts)
    return result_exit_code(lines, counts, strict)


def _audit_consumers(dotnix: Path, templates: Path, strict: bool) -> int:
    roots = {"global": dotnix.resolve(), "agent-core": templates.resolve()}
    invalid = invalid_consumer_roots(roots)
    if invalid:
        for path in invalid:
            print(f"ERROR consumer path is not a directory: {path}")
        return 2
    documents, errors = _load_valid_policy()
    if errors:
        return _policy_error(errors)
    lines, counts = audit_profiles(roots, documents)
    _print_result(lines, counts)
    return result_exit_code(lines, counts, strict)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="opencode-contract", description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("validate", help="validate the policy contract")

    single = subparsers.add_parser("audit-consumer", help="audit one explicitly bound consumer profile")
    single.add_argument("--profile", choices=sorted(PROFILE_AGENT_DIRS), required=True)
    single.add_argument("--consumer", type=Path, required=True)
    single.add_argument("--strict", action="store_true")

    dual = subparsers.add_parser("audit-consumers", help="audit global and Agent-Core consumers")
    dual.add_argument("--dotnix", type=Path, required=True)
    dual.add_argument("--templates", type=Path, required=True)
    dual.add_argument("--strict", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "validate":
        return _validate()
    if args.command == "audit-consumer":
        return _audit_consumer(args.profile, args.consumer, args.strict)
    if args.command == "audit-consumers":
        return _audit_consumers(args.dotnix, args.templates, args.strict)
    raise AssertionError(f"unhandled command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
