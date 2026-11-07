#!/usr/bin/env python3
"""Summarize captured cargo diagnostics for a CI failure comment.

Reads build.stderr.txt / build.json / test.json (whichever exist) and prints
the human-relevant slice: cargo's own stderr first, then `error[E...]` blocks
with their source snippet, then failing-test names.
"""
import json
import os
import sys
import argparse

MAX_LINES = 120


def cargo_stderr():
    if not os.path.exists("build.stderr.txt"):
        return []
    with open("build.stderr.txt", encoding="utf-8", errors="replace") as handle:
        text = handle.read().strip()
    if not text:
        return []
    return ["--- cargo stderr ---", *text.splitlines()]


def compiler_diagnostics(path):
    out = []
    if not os.path.exists(path):
        return out
    with open(path, encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            raw = raw.strip()
            if not raw.startswith("{"):
                continue
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue
            diag = msg.get("message") or {}
            level = diag.get("level")
            if msg.get("reason") == "compiler-message" and level in ("error", "warning"):
                rendered = (diag.get("rendered") or diag.get("message", "")).rstrip()
                if level == "error":
                    out.append(rendered)
            # Test failures arrive as build-script/compiler "failure" notes
            # plus, for libtest, plain test-harness output on stdout.
    return out


def failed_tests(path):
    out = []
    if not os.path.exists(path):
        return out
    with open(path, encoding="utf-8", errors="replace") as handle:
        lines = [line.rstrip("\n") for line in handle]
    capture = False
    for index, line in enumerate(lines):
        if line.strip() == "failures:":
            capture = True
            continue
        if capture:
            stripped = line.strip()
            if stripped and not stripped.startswith("---"):
                out.append(stripped)
            if stripped.startswith("test result:"):
                capture = False
    return out[:40]


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-lines", type=int, default=MAX_LINES)
    args = parser.parse_args(argv)

    sections = []
    stderr_lines = cargo_stderr()
    if stderr_lines:
        sections.extend(stderr_lines)
    for path in ("build.json", "test.json"):
        for block in compiler_diagnostics(path):
            sections.append(f"--- {path} ---")
            sections.extend(block.splitlines())
    tests = failed_tests("test.json")
    if tests:
        sections.append("--- failing tests ---")
        sections.extend(tests)

    if not sections:
        print("(no diagnostics captured)")
        return 0
    if len(sections) > args.max_lines:
        sections = sections[: args.max_lines] + [f"... truncated ({len(sections)} lines)"]
    print("\n".join(sections))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
