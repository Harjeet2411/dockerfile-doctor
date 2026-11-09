"""Turn a Dockerfile into a list of instructions grouped by build stage."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_ESCAPE_DIRECTIVE = re.compile(r"^#\s*escape\s*=\s*(\S)\s*$", re.I)


@dataclass
class Instruction:
    line: int  # 1-based line where the instruction starts
    keyword: str  # upper-cased, e.g. "RUN"
    args: str  # everything after the keyword, continuations joined with spaces
    raw: str


@dataclass
class Stage:
    index: int
    image: str  # the image FROM names, including tag or digest
    name: str | None
    line: int
    instructions: list[Instruction] = field(default_factory=list)


@dataclass
class Dockerfile:
    instructions: list[Instruction]
    stages: list[Stage]

    @property
    def final_stage(self) -> Stage | None:
        return self.stages[-1] if self.stages else None


def parse(text: str) -> Dockerfile:
    lines = text.splitlines()
    escape = "\\"
    # Parser directives are only honoured in leading comment lines.
    for line in lines:
        m = _ESCAPE_DIRECTIVE.match(line.strip())
        if m:
            escape = m.group(1)
            continue
        if not line.strip().startswith("#"):
            break

    instructions: list[Instruction] = []
    buf: list[str] = []
    start = 0
    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        # Comment lines inside a continued instruction are dropped, as BuildKit does.
        if stripped.startswith("#") or (not stripped and not buf):
            continue
        if not buf:
            start = lineno
        if stripped.endswith(escape):
            buf.append(stripped[:-1].rstrip())
            continue
        buf.append(stripped)
        instructions.append(_make(start, buf))
        buf = []
    if buf:
        instructions.append(_make(start, buf))

    stages: list[Stage] = []
    for ins in instructions:
        if ins.keyword == "FROM":
            parts = [p for p in ins.args.split() if not p.startswith("--")]
            image = parts[0] if parts else ""
            name = parts[2] if len(parts) >= 3 and parts[1].lower() == "as" else None
            stages.append(Stage(len(stages), image, name, ins.line))
        if stages:
            stages[-1].instructions.append(ins)
    return Dockerfile(instructions, stages)


def _make(start: int, parts: list[str]) -> Instruction:
    joined = " ".join(p for p in parts if p)
    keyword, _, args = joined.partition(" ")
    return Instruction(start, keyword.upper(), args.strip(), joined)
