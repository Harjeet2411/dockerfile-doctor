"""Render findings as text, JSON or SARIF (for GitHub code scanning)."""

from __future__ import annotations

import json

from . import __version__
from .rules import RULES, Finding, score

_MARK = {"error": "✖", "warning": "▲", "info": "●"}
_COLOR = {"error": "\033[31m", "warning": "\033[33m", "info": "\033[36m"}
_RESET, _DIM, _BOLD = "\033[0m", "\033[2m", "\033[1m"


def to_text(results: dict[str, list[Finding]], color: bool = False) -> str:
    def c(code, s):
        return f"{code}{s}{_RESET}" if color else s

    out = []
    for path, findings in results.items():
        out.append(c(_BOLD, f"{path}  ·  score {score(findings)}/100"))
        if not findings:
            out.append("  no problems found")
        for f in findings:
            out.append(f"  {f.line:>4}  {c(_COLOR[f.severity], _MARK[f.severity] + ' ' + f.rule)}  {f.message}")
            out.append(c(_DIM, f"        fix: {f.fix}"))
        out.append("")
    counts = {s: sum(f.severity == s for fs in results.values() for f in fs) for s in _MARK}
    out.append(f"{counts['error']} errors, {counts['warning']} warnings, {counts['info']} info")
    return "\n".join(out) + "\n"


def to_json(results: dict[str, list[Finding]]) -> str:
    return json.dumps(
        {path: {"score": score(fs), "findings": [vars(f) for f in fs]} for path, fs in results.items()},
        indent=2,
    ) + "\n"


def to_sarif(results: dict[str, list[Finding]]) -> str:
    level = {"error": "error", "warning": "warning", "info": "note"}
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "dockerfile-doctor",
                "version": __version__,
                "informationUri": "https://github.com/Harjeet2411/dockerfile-doctor",
                "rules": [
                    {"id": r.id, "name": r.title, "shortDescription": {"text": r.title},
                     "defaultConfiguration": {"level": level[r.severity]}}
                    for r in RULES
                ],
            }},
            "results": [
                {
                    "ruleId": f.rule,
                    "level": level[f.severity],
                    "message": {"text": f"{f.message}. Fix: {f.fix}"},
                    "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": path},
                        "region": {"startLine": f.line},
                    }}],
                }
                for path, fs in results.items() for f in fs
            ],
        }],
    }
    return json.dumps(sarif, indent=2) + "\n"
