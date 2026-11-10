"""Stdlib-only regression tests; run with python3 -m unittest discover -s scripts -p 'test_*.py'."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("release_notes", Path(__file__).with_name("release-notes.py"))
notes = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(notes)

README = """# Demo
## Changelog
### 0.29.0
- Browse… café 文件 → local paths.
### 0.28.0
- Windows launchers — no upload.
### 0.27.0
- Previous release.
"""


class ReleaseNotesTests(unittest.TestCase):
    def test_grouped_notes_include_only_unreleased_sections_in_descending_order(self):
        text = notes.build_notes("v0.29.0", "v0.27.0", README)
        self.assertIn("0.28.0 through 0.29.0", text)
        self.assertLess(text.index("### 0.29.0"), text.index("### 0.28.0"))
        self.assertNotIn("### 0.27.0", text)
        self.assertIn("café 文件 →", text)

    def test_single_version_is_not_labelled_grouped(self):
        text = notes.build_notes("v0.29.0", "v0.28.0", README)
        self.assertIn("Release notes for 0.29.0", text)
        self.assertNotIn("### 0.28.0", text)

    def test_missing_changelog_or_current_version_is_rejected(self):
        for readme in ["# No changelog", "## Changelog\n### 0.28.0\nold"]:
            with self.assertRaises(ValueError):
                notes.build_notes("v0.29.0", "v0.27.0", readme)

    def test_previous_release_must_be_older(self):
        for since in ["v0.29.0", "v0.30.0"]:
            with self.assertRaises(ValueError):
                notes.build_notes("v0.29.0", since, README)

    def test_invalid_versions_are_rejected(self):
        for version in ["latest", "v0.29", "v0.29.0-beta", "-1.2.3"]:
            with self.assertRaises(ValueError):
                notes.parse_version(version)

    def test_tag_discovery_ignores_current_future_and_prerelease_tags(self):
        with mock.patch.object(notes.subprocess, "check_output", return_value="v0.30.0\nv0.29.0\nv0.28.0-beta\nv0.27.0\nv0.16.0\n"):
            self.assertEqual(notes.previous_release_tag((0, 29, 0)), "v0.27.0")

    def test_first_release_has_no_previous_version_sections(self):
        with mock.patch.object(notes, "previous_release_tag", return_value=None):
            text = notes.build_notes("v0.1.0", None, "## Changelog\n### 0.1.0\n- First.")
        self.assertIn("Release notes for 0.1.0", text)
        self.assertIn("### 0.1.0", text)

    def run_cli(self, readme, output="nested/notes.md", patch_legacy_locale=False):
        # Keep all generated artifacts out of the repository; restore cwd even
        # when assertions fail. The context persists until the caller finishes.
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        directory = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        previous = Path.cwd()
        os.chdir(directory)
        stack.callback(os.chdir, previous)
        Path("README.md").write_bytes(readme)
        if patch_legacy_locale:
            original_open = Path.open

            def legacy_open(path, mode="r", buffering=-1, encoding=None, errors=None, newline=None):
                if "b" not in mode and encoding is None:
                    encoding = "cp1252"
                return original_open(path, mode, buffering, encoding, errors, newline)

            stack.enter_context(mock.patch.object(Path, "open", legacy_open))
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = notes.main(["--tag", "v0.29.0", "--since", "v0.27.0", "--output", output])
        return code, directory / output, stdout.getvalue(), stderr.getvalue()

    def test_cli_emits_utf8_lf_and_actual_byte_count_under_legacy_windows_locale(self):
        code, output, stdout, stderr = self.run_cli(README.replace("\n", "\r\n").encode("utf-8"), patch_legacy_locale=True)
        self.assertEqual(code, 0, stderr)
        data = output.read_bytes()
        self.assertNotIn(b"\r", data)
        self.assertFalse(data.startswith(b"\xef\xbb\xbf"))
        self.assertEqual(data.decode("utf-8"), notes.build_notes("v0.29.0", "v0.27.0", README))
        self.assertIn("({} bytes)".format(len(data)), stdout)

    def test_invalid_utf8_fails_without_creating_output(self):
        code, output, _, stderr = self.run_cli(b"## Changelog\n\xff")
        self.assertEqual(code, 1)
        self.assertFalse(output.exists())
        self.assertIn("release-notes:", stderr)

    def test_invalid_changelog_does_not_overwrite_existing_notes(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "notes.md"
            output.write_bytes(b"existing notes")
            code, _, _, stderr = self.run_cli(b"## Changelog\n### 0.28.0\n- Old", str(output))
            self.assertEqual(code, 1, stderr)
            self.assertEqual(output.read_bytes(), b"existing notes")


if __name__ == "__main__":
    unittest.main()
