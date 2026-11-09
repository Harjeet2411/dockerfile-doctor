# dockerfile-doctor

[![CI](https://github.com/Harjeet2411/dockerfile-doctor/actions/workflows/ci.yml/badge.svg)](https://github.com/Harjeet2411/dockerfile-doctor/actions/workflows/ci.yml)

Checks a Dockerfile for the security and image-size mistakes that show up in almost every
first draft, and tells you how to fix each one.

```
$ dockerfile-doctor examples/Dockerfile.bad
examples/Dockerfile.bad  ·  score 0/100
     2  ✖ DD002  the final stage never sets USER, so the app runs as root
        fix: Create an unprivileged user and switch to it: RUN useradd -r app && USER app
     2  ▲ DD001  `python` floats with whatever `latest` points to today
        fix: Pin a version tag, or better a digest: FROM image:1.2.3@sha256:...
     2  ● DD202  docker and compose cannot tell a hung container from a healthy one
        fix: Add HEALTHCHECK CMD ..., or rely on your orchestrator's probes and ignore DD202
     3  ✖ DD003  ENV API_KEY has a literal value that anyone who pulls the image can read
        fix: Pass it at runtime, or use a build secret: RUN --mount=type=secret,id=api_key
     5  ▲ DD203  a relative WORKDIR depends on every earlier WORKDIR
        fix: Use an absolute path
     6  ● DD106  any code change re-runs the dependency install on the next build
  ...
2 errors, 8 warnings, 4 info
```

The same file rewritten by following those fixes, [examples/Dockerfile.good](examples/Dockerfile.good),
comes back clean.

## Install

```
pip install git+https://github.com/Harjeet2411/dockerfile-doctor
```

Pure Python 3.9+, no dependencies.

## Usage

```
dockerfile-doctor                                  # ./Dockerfile
dockerfile-doctor services/*/Dockerfile            # several files
dockerfile-doctor --ignore DD202,DD102             # skip rules you have decided against
dockerfile-doctor --fail-on warning                # stricter CI gate (default: error)
dockerfile-doctor -f json                          # for scripts
dockerfile-doctor -f sarif > results.sarif         # for GitHub code scanning
dockerfile-doctor --list-rules
```

Exit codes: 0 clean (below `--fail-on`), 1 findings at or above `--fail-on`, 2 a file could not be read.

### In GitHub Actions

Upload SARIF and the findings show up as code-scanning alerts on the exact Dockerfile line:

```yaml
- run: pip install git+https://github.com/Harjeet2411/dockerfile-doctor
- run: dockerfile-doctor -f sarif --fail-on never Dockerfile > dockerfile.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: dockerfile.sarif
```

## Rules

| Rule | Severity | Catches |
|---|---|---|
| DD001 | warning | Base image without a version tag, or on `latest` |
| DD002 | error | Final stage runs as root (no `USER`, or `USER root`) |
| DD003 | error | Passwords, tokens and keys set with `ENV`/`ARG` |
| DD004 | warning | `curl ... \| sh` with no checksum |
| DD005 | warning | `ADD` for plain files, or for URLs without a checksum |
| DD006 | warning | `sudo` inside `RUN` |
| DD007 | warning | `EXPOSE 22` |
| DD101 | warning | `apt-get update` in its own layer |
| DD102 | info | `apt-get install` without `--no-install-recommends` |
| DD103 | warning | apt lists not removed in the same layer |
| DD104 | info | `apk add` without `--no-cache` |
| DD105 | info | `pip install` without `--no-cache-dir` or a cache mount |
| DD106 | info | `COPY . .` before installing dependencies, which defeats the build cache |
| DD201 | warning | Shell-form `CMD`/`ENTRYPOINT`, so the app never gets SIGTERM |
| DD202 | info | No `HEALTHCHECK` |
| DD203 | warning | Relative `WORKDIR` |

Only the final stage is checked for runtime rules (DD002, DD201, DD202), since that is the image you ship.
The score is a rough guide: 100, minus 20 per error, 8 per warning and 3 per info.

## Limits

- `RUN <<EOF` heredocs are read as a single line, so commands inside them are only partly checked.
- Rules are text patterns, not a shell parser: a `curl | sh` hidden behind a variable won't be caught.

## Development

```
python -m unittest discover -s tests -v
```

## License

MIT
