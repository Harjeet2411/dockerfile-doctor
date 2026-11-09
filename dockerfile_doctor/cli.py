"""Command line: ``dockerfile-doctor Dockerfile [more files]``."""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .parser import parse
from .report import to_json, to_sarif, to_text
from .rules import RULES, SEVERITY_ORDER, lint


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dockerfile-doctor",
        description="Find security and image-size problems in Dockerfiles, with a fix for each.",
    )
    p.add_argument("files", nargs="*", default=["Dockerfile"], help="Dockerfiles to check (default: ./Dockerfile)")
    p.add_argument("-f", "--format", choices=["text", "json", "sarif"], default="text")
    p.add_argument("--ignore", action="append", default=[], metavar="RULE", help="skip a rule, e.g. --ignore DD202 (repeatable, or comma-separated)")
    p.add_argument("--fail-on", choices=["error", "warning", "info", "never"], default="error",
                   help="exit 1 when a finding is at least this severe (default: error)")
    p.add_argument("--list-rules", action="store_true", help="print every rule and exit")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list_rules:
        for r in RULES:
            print(f"{r.id}  {r.severity:<7}  {r.title}")
        return 0
    ignore = {i.strip().upper() for chunk in args.ignore for i in chunk.split(",") if i.strip()}
    results = {}
    for path in args.files:
        try:
            with open(path, encoding="utf-8") as fh:
                results[path] = lint(parse(fh.read()), ignore)
        except OSError as exc:
            print(f"dockerfile-doctor: {exc}", file=sys.stderr)
            return 2
    if args.format == "json":
        sys.stdout.write(to_json(results))
    elif args.format == "sarif":
        sys.stdout.write(to_sarif(results))
    else:
        color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
        sys.stdout.write(to_text(results, color))
    if args.fail_on == "never":
        return 0
    threshold = SEVERITY_ORDER[args.fail_on]
    worst = max((SEVERITY_ORDER[f.severity] for fs in results.values() for f in fs), default=-1)
    return 1 if worst >= threshold else 0
