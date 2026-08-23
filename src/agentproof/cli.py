"""Dependency-free command-line interface for AgentProof."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .github import GitHubFetchError
from .models import Severity
from .reporters import render_report
from .rules import all_rules
from .scanner import ScanError, ScanOptions, scan


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentproof",
        description="Static security and engineering quality checks for AI Agent, MCP, and Skills repositories.",
    )
    parser.add_argument("--version", action="version", version=f"AgentProof {__version__}")
    subcommands = parser.add_subparsers(dest="command", required=True)

    scan_parser = subcommands.add_parser("scan", help="scan a local path or public GitHub repository")
    scan_parser.add_argument("target", nargs="?", default=".")
    scan_parser.add_argument(
        "--format", choices=("table", "json", "markdown", "html", "sarif"), default="table"
    )
    scan_parser.add_argument("--output", "-o", type=Path)
    scan_parser.add_argument(
        "--fail-on", choices=("critical", "high", "medium", "low", "none"), default="high"
    )
    scan_parser.add_argument("--exclude", action="append", default=[], help="glob to exclude; repeatable")
    scan_parser.add_argument(
        "--disable-rule", action="append", default=[], help="rule ID to disable; repeatable"
    )
    scan_parser.add_argument("--config", type=Path, help="path to an AgentProof TOML config")
    scan_parser.add_argument("--max-file-size", type=int, help="maximum decoded text file size in bytes")
    scan_parser.add_argument("--max-files", type=int, default=10_000)
    scan_parser.add_argument("--no-quality", action="store_true", help="skip repository quality checks")
    scan_parser.add_argument("--no-color", action="store_true")

    subcommands.add_parser("rules", help="list the built-in rules")
    return parser


def _threshold(value: str) -> Severity | None:
    return None if value == "none" else Severity[value.upper()]


def _print_rules() -> int:
    for rule in all_rules():
        print(f"{rule.rule_id:<7} {rule.severity.label():<9} {rule.category:<18} {rule.title}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "rules":
        return _print_rules()

    options = ScanOptions(
        excludes=args.exclude,
        disabled_rules=set(args.disable_rule),
        config_path=args.config,
        max_file_size=args.max_file_size,
        max_files=args.max_files,
        project_quality=not args.no_quality,
    )
    try:
        result = scan(args.target, options)
        output = render_report(result, args.format, color=not args.no_color and sys.stdout.isatty())
    except (ScanError, GitHubFetchError, OSError, ValueError) as exc:
        print(f"agentproof: error: {exc}", file=sys.stderr)
        return 2

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output, encoding="utf-8")
        print(f"AgentProof report written to {args.output}")
    else:
        print(output)
    return 1 if result.should_fail(_threshold(args.fail_on)) else 0


if __name__ == "__main__":
    raise SystemExit(main())
