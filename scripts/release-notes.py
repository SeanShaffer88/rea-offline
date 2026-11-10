#!/usr/bin/env python3
"""Build grouped release notes from the README changelog.

A release may ship several version sections at once (v0.16.0 shipped 0.14.0,
0.15.0 and 0.16.0 together; v0.25.0 shipped 0.17.0 through 0.25.0). GitHub's
``--generate-notes`` only lists pull requests, which hides those changelog
sections. This script collects the sections newer than the previous release
tag and writes the same grouped body used for published releases.

Usage:
    python3 scripts/release-notes.py --tag v0.26.0 --output notes.md
    python3 scripts/release-notes.py --tag v0.25.0 --since v0.16.0 --output notes.md

The previous tag is discovered from ``git tag`` unless ``--since`` is given;
``--since`` exists so CI can exercise the generator without a full tag fetch.
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

TAG_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
HEADING_RE = re.compile(r"^### (\d+)\.(\d+)\.(\d+)\s*$", re.MULTILINE)


def parse_version(text):
    """Return (major, minor, patch) for 'v1.2.3' or '1.2.3'."""
    match = TAG_RE.match(text) or VERSION_RE.match(text)
    if not match:
        raise ValueError("expected a vMAJOR.MINOR.PATCH version, got {!r}".format(text))
    return tuple(int(part) for part in match.groups())


def format_version(version):
    return "{}.{}.{}".format(*version)


def previous_release_tag(current):
    """Highest existing v* tag strictly older than `current`."""
    try:
        output = subprocess.check_output(
            ["git", "tag", "--list", "v*", "--sort=-v:refname"],
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    candidates = []
    for tag in output.splitlines():
        tag = tag.strip()
        if not TAG_RE.match(tag):
            continue
        version = parse_version(tag)
        if version < current:
            candidates.append((version, tag))
    if not candidates:
        return None
    candidates.sort(reverse=True)
    return candidates[0][1]


def changelog_sections(readme):
    """Map version tuple -> markdown text of its '### x.y.z' section."""
    marker = "## Changelog"
    if marker not in readme:
        raise ValueError("README.md has no '## Changelog' section")
    body = readme[readme.index(marker) + len(marker):]
    matches = list(HEADING_RE.finditer(body))
    sections = {}
    for index, match in enumerate(matches):
        version = tuple(int(part) for part in match.groups())
        end = matches[index + 1].start() if index + 1 < len(matches) else len(body)
        sections[version] = body[match.start():end].rstrip() + "\n"
    return sections


def build_notes(tag, since, readme):
    current = parse_version(tag)
    previous_tag = since or previous_release_tag(current)
    previous = parse_version(previous_tag) if previous_tag else (0, 0, 0)
    if previous >= current:
        raise ValueError("previous release {} is not older than {}".format(previous_tag, tag))

    sections = changelog_sections(readme)
    if current not in sections:
        raise ValueError(
            "README.md has no '### {}' section for this release".format(format_version(current))
        )
    selected = [version for version in sections if previous < version <= current]
    if not selected:
        raise ValueError("no changelog sections found between {} and {}".format(previous_tag, tag))
    selected.sort(reverse=True)

    first = format_version(selected[-1])
    last = format_version(current)
    shape = previous_tag if previous_tag else "the first release"
    if first == last:
        header = (
            "Release notes for {}. One Windows x64 executable plus a SHA-256 "
            "sidecar, the same shape as {}.\n\n"
        ).format(last, shape)
    else:
        header = (
            "Grouped release covering {} through {} — none of those versions "
            "shipped individually, so their changelog sections are collected here. "
            "One Windows x64 executable plus a SHA-256 sidecar, the same shape as {}.\n\n"
        ).format(first, last, shape)
    # Each section ends with a newline; joining with another newline keeps
    # the blank line the README places between version headings.
    return header + "\n".join(sections[version] for version in selected)


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True, help="release tag, e.g. v0.26.0")
    parser.add_argument("--since", help="override the previous release tag (for tests)")
    parser.add_argument("--output", required=True, help="markdown file to write")
    args = parser.parse_args(argv)

    try:
        notes = build_notes(args.tag, args.since, Path("README.md").read_text(encoding="utf-8"))
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        # GitHub consumes UTF-8, regardless of the Windows process locale.
        # Explicit LF also makes release artifacts byte-identical across hosts.
        with output.open("w", encoding="utf-8", newline="\n") as stream:
            stream.write(notes)
    except (OSError, ValueError) as exc:
        print("release-notes: {}".format(exc), file=sys.stderr)
        return 1
    print("release-notes: wrote {} ({} bytes)".format(args.output, len(notes.encode("utf-8"))))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
