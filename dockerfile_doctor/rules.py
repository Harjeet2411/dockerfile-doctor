"""Lint rules. Each rule takes a parsed Dockerfile and yields findings."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterator

from .parser import Dockerfile, Instruction

ERROR, WARNING, INFO = "error", "warning", "info"
SEVERITY_ORDER = {INFO: 0, WARNING: 1, ERROR: 2}


@dataclass
class Finding:
    rule: str
    severity: str
    line: int
    message: str
    fix: str


@dataclass
class Rule:
    id: str
    severity: str
    title: str
    check: Callable[[Dockerfile], Iterator[tuple[int, str, str]]]


RULES: list[Rule] = []


def rule(rule_id: str, severity: str, title: str):
    def register(fn):
        RULES.append(Rule(rule_id, severity, title, fn))
        return fn

    return register


def _runs(df: Dockerfile) -> Iterator[Instruction]:
    return (i for i in df.instructions if i.keyword == "RUN")


def _stage_names(df: Dockerfile) -> set[str]:
    return {s.name.lower() for s in df.stages if s.name}


# --- Security ------------------------------------------------------------------


@rule("DD001", WARNING, "Base image is not pinned")
def unpinned_base(df):
    names = _stage_names(df)
    for st in df.stages:
        img = st.image
        if img.lower() in names or img.lower() == "scratch" or "@sha256:" in img:
            continue
        # A ':' after the last '/' is a tag; one before it is a registry port.
        tag = img.rsplit("/", 1)[-1].partition(":")[2]
        if not tag or tag == "latest":
            yield st.line, f"`{img}` floats with whatever `latest` points to today", (
                "Pin a version tag, or better a digest: FROM image:1.2.3@sha256:..."
            )


@rule("DD002", ERROR, "Container runs as root")
def runs_as_root(df):
    final = df.final_stage
    if not final or final.image.lower() == "scratch":
        return
    users = [i for i in final.instructions if i.keyword == "USER"]
    if not users:
        yield final.line, "the final stage never sets USER, so the app runs as root", (
            "Create an unprivileged user and switch to it: RUN useradd -r app && USER app"
        )
    elif users[-1].args.split(":")[0] in ("root", "0"):
        yield users[-1].line, "the last USER in the final stage is root", "Switch to an unprivileged user before CMD"


_SECRET_NAME = re.compile(r"(PASS(WORD|WD)?|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIALS?)", re.I)


def _env_pairs(args: str) -> Iterator[tuple[str, str]]:
    # ENV KEY=value KEY2="v 2"  or the legacy  ENV KEY value
    if "=" not in args.split(" ", 1)[0]:
        key, _, value = args.partition(" ")
        yield key, value.strip()
        return
    for m in re.finditer(r'([A-Za-z_][A-Za-z0-9_]*)=("([^"]*)"|\'([^\']*)\'|(\S*))', args):
        yield m.group(1), next(g for g in m.groups()[2:] if g is not None)


@rule("DD003", ERROR, "Secret baked into the image")
def baked_secret(df):
    for ins in df.instructions:
        if ins.keyword not in ("ENV", "ARG"):
            continue
        for key, value in _env_pairs(ins.args):
            if _SECRET_NAME.search(key) and value and not value.startswith("$"):
                yield ins.line, f"{ins.keyword} {key} has a literal value that anyone who pulls the image can read", (
                    "Pass it at runtime, or use a build secret: RUN --mount=type=secret,id=" + key.lower()
                )


@rule("DD004", WARNING, "Remote script piped into a shell")
def curl_pipe_shell(df):
    pat = re.compile(r"\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|da)?sh\b")
    for ins in _runs(df):
        if pat.search(ins.args):
            yield ins.line, "downloads a script and runs it without checking what it is", (
                "Download to a file, verify a checksum (sha256sum -c), then run it"
            )


@rule("DD005", WARNING, "ADD used where COPY would do")
def add_instead_of_copy(df):
    for ins in df.instructions:
        if ins.keyword != "ADD":
            continue
        srcs = [a for a in ins.args.split() if not a.startswith("--")][:-1]
        if any(s.startswith(("http://", "https://")) for s in srcs):
            yield ins.line, "ADD fetches a URL with no checksum", "Use ADD --checksum=sha256:... or curl + sha256sum"
        elif not any(s.endswith((".tar", ".tar.gz", ".tgz", ".tar.xz", ".tar.bz2")) for s in srcs):
            yield ins.line, "ADD also unpacks archives and fetches URLs, which COPY never does by surprise", "Use COPY"


@rule("DD006", WARNING, "sudo inside the build")
def uses_sudo(df):
    for ins in _runs(df):
        if re.search(r"(^|[;&|]\s*)sudo\b", ins.args):
            yield ins.line, "RUN already runs as the current USER; sudo adds a setuid binary to the image", (
                "Switch USER root for that step instead"
            )


@rule("DD007", WARNING, "SSH port exposed")
def exposes_ssh(df):
    for ins in df.instructions:
        if ins.keyword == "EXPOSE" and any(p.split("/")[0] == "22" for p in ins.args.split()):
            yield ins.line, "running sshd in a container widens the attack surface", "Use docker exec or kubectl exec"


# --- Size and build cache ----------------------------------------------------------


@rule("DD101", WARNING, "apt-get update in its own layer")
def apt_update_alone(df):
    for ins in _runs(df):
        if re.search(r"apt-get\s+update", ins.args) and not re.search(r"apt-get\s+(-\S+\s+)*install", ins.args):
            yield ins.line, "a cached update layer goes stale and later installs fail or pull old packages", (
                "Run update and install in the same RUN: apt-get update && apt-get install -y ..."
            )


@rule("DD102", INFO, "apt-get install pulls recommended packages")
def apt_recommends(df):
    for ins in _runs(df):
        if re.search(r"apt-get\s+(-\S+\s+)*install", ins.args) and "--no-install-recommends" not in ins.args:
            yield ins.line, "recommended packages often add tens of MB you never use", "Add --no-install-recommends"


@rule("DD103", WARNING, "apt package lists left in the image")
def apt_lists(df):
    for ins in _runs(df):
        if re.search(r"apt-get\s+(-\S+\s+)*install", ins.args) and "/var/lib/apt/lists" not in ins.args:
            yield ins.line, "the apt cache stays in this layer even if a later RUN deletes it", (
                "End the same RUN with: && rm -rf /var/lib/apt/lists/*"
            )


@rule("DD104", INFO, "apk add keeps its cache")
def apk_cache(df):
    for ins in _runs(df):
        if re.search(r"\bapk\s+add\b", ins.args) and "--no-cache" not in ins.args:
            yield ins.line, "apk keeps its index in the layer", "Use apk add --no-cache"


@rule("DD105", INFO, "pip keeps its download cache")
def pip_cache(df):
    for ins in _runs(df):
        if re.search(r"\bpip3?\s+install\b", ins.args) and "--no-cache-dir" not in ins.args and "--mount=type=cache" not in ins.args:
            yield ins.line, "pip's cache ends up in the image", "Add --no-cache-dir, or RUN --mount=type=cache,target=/root/.cache/pip"


_INSTALL = re.compile(r"\b(pip3?\s+install|npm\s+(ci|install)|yarn(\s+install)?\b|pnpm\s+install|go\s+mod\s+download|bundle\s+install|composer\s+install|mvn\b|gradle\b)")


@rule("DD106", INFO, "Whole source tree copied before dependencies install")
def copy_before_install(df):
    for st in df.stages:
        copied_all = None
        for ins in st.instructions:
            if ins.keyword in ("COPY", "ADD"):
                srcs = [a for a in ins.args.split() if not a.startswith("--")][:-1]
                if "." in srcs or "./" in srcs:
                    copied_all = copied_all or ins
            elif ins.keyword == "RUN" and copied_all and _INSTALL.search(ins.args):
                yield copied_all.line, "any code change re-runs the dependency install on the next build", (
                    "COPY the lock/requirements file first, install, then COPY the rest"
                )
                break


# --- Runtime behaviour ----------------------------------------------------------------


@rule("DD201", WARNING, "Shell-form CMD or ENTRYPOINT")
def shell_form(df):
    final = df.final_stage
    if not final:
        return
    for ins in final.instructions:
        if ins.keyword in ("CMD", "ENTRYPOINT") and not ins.args.lstrip().startswith("["):
            yield ins.line, f"{ins.keyword} runs under /bin/sh -c, so the app never receives SIGTERM and is killed after the stop timeout", (
                f'Use the exec form: {ins.keyword} ["app", "--flag"]'
            )


@rule("DD202", INFO, "No HEALTHCHECK")
def no_healthcheck(df):
    final = df.final_stage
    if final and final.image.lower() != "scratch" and not any(i.keyword == "HEALTHCHECK" for i in final.instructions):
        yield final.line, "docker and compose cannot tell a hung container from a healthy one", (
            "Add HEALTHCHECK CMD ..., or rely on your orchestrator's probes and ignore DD202"
        )


@rule("DD203", WARNING, "Relative WORKDIR")
def relative_workdir(df):
    for ins in df.instructions:
        if ins.keyword == "WORKDIR" and not ins.args.startswith(("/", "$")):
            yield ins.line, "a relative WORKDIR depends on every earlier WORKDIR", "Use an absolute path"


def lint(df: Dockerfile, ignore: set[str] = frozenset()) -> list[Finding]:
    found = []
    for r in RULES:
        if r.id in ignore:
            continue
        for line, message, fix in r.check(df):
            found.append(Finding(r.id, r.severity, line, message, fix))
    found.sort(key=lambda f: (f.line, -SEVERITY_ORDER[f.severity], f.rule))
    return found


def score(findings: list[Finding]) -> int:
    """A rough 0-100 health score: errors cost 20, warnings 8, info 3."""
    cost = {ERROR: 20, WARNING: 8, INFO: 3}
    return max(0, 100 - sum(cost[f.severity] for f in findings))
