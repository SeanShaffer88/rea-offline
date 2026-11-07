#!/usr/bin/env python3
"""Run `cargo` and turn every compiler diagnostic into a GitHub annotation.

Used by CI so that compile errors are readable directly from the workflow
run (check-run annotations) without downloading the job log — handy when a
contributor cannot run a local toolchain (e.g. an air-gapped review box) and
still wants the exact file/line/message.

Usage:
  ci-annotate.py <cargo args...>        run cargo, annotate as it goes
  ci-annotate.py --parse build.json     annotate an existing JSON capture
"""
import json
import subprocess
import sys

# GitHub caps annotations per run; keep the interesting ones.
MAX_ERRORS = 40
MAX_MESSAGE = 3500


def emit(level, message, file=None, line=None, col=None):
    # GitHub workflow-command syntax is `::level prop=value,...::message`
    # (note the space before the properties) — without it the whole line is
    # ignored as text and the annotation silently disappears.
    parts = [f"::{level}"]
    if file:
        loc = f" file={file}"
        if line:
            loc += f",line={line}"
        if col:
            loc += f",col={col}"
        parts.append(loc)
    parts.append("::" + message.replace("\n", "%0A"))
    print("".join(parts), flush=True)


def parse_stream(lines, errors_state):
    """Annotate every diagnostic in `lines`; return the error count."""
    errors = warnings = 0
    for raw in lines:
        raw = raw.strip()
        if not raw.startswith("{"):
            continue  # non-JSON chatter (progress bars, "Compiling ...")
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if msg.get("reason") != "compiler-message":
            continue
        diag = msg.get("message", {})
        level = diag.get("level")
        if level not in ("error", "warning"):
            continue
        text = diag.get("message", "")
        rendered = diag.get("rendered") or text
        spans = [s for s in diag.get("spans", []) if s.get("is_primary")]
        span = spans[0] if spans else {}
        snippet = rendered.split("\n")[0][:MAX_MESSAGE]
        if level == "error":
            errors += 1
            if errors <= MAX_ERRORS:
                emit("error", snippet, span.get("file_name"), span.get("line_start"),
                     span.get("column_start"))
        else:
            warnings += 1
            if warnings <= 10:
                emit("warning", snippet, span.get("file_name"), span.get("line_start"),
                     span.get("column_start"))
    errors_state.append(errors)
    return 0


def main(argv):
    if argv and argv[0] == "--parse":
        path = argv[1] if len(argv) > 1 else "build.json"
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                lines = handle.readlines()
        except OSError as exc:
            emit("error", f"cannot read {path}: {exc}")
            print(f"[ci-annotate] cannot read {path}: {exc}", flush=True)
            return 0
        state = []
        parse_stream(lines, state)
        print(f"[ci-annotate] parsed {path}: {state[0] if state else 0} errors", flush=True)
        return 0
    cmd = ["cargo", *argv, "--message-format=json"]
    print(f"[ci-annotate] running: {' '.join(cmd)}", flush=True)
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    with open("build.json", "w", encoding="utf-8") as capture:
        capture.write(proc.stdout)
    with open("build.stderr.txt", "w", encoding="utf-8") as capture:
        capture.write(proc.stderr)
    # Cargo-level failures (manifest errors, bad flags, linker errors) only
    # appear on stderr, so surface them too.
    if proc.returncode != 0 and proc.stderr.strip():
        for line in proc.stderr.strip().splitlines()[:MAX_ERRORS]:
            if line.strip():
                emit("error", f"cargo: {line.strip()}"[:MAX_MESSAGE])
    with open("build.json", encoding="utf-8", errors="replace") as capture:
        state = []
        parse_stream(capture.readlines(), state)
    errors = state[0] if state else 0
    # Non-zero when the build failed. `cargo test` also returns non-zero on
    # failing tests, which is a normal CI failure, not a broken pipeline.
    if proc.returncode != 0:
        emit("error", f"cargo exited with {proc.returncode} ({errors} error diagnostics)")
        return proc.returncode
    print("[ci-annotate] clean", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
