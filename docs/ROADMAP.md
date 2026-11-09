# Roadmap

`rea-offline` already supports offline static analysis, installer sandboxing,
snapshot/diff workflows, explainable risk reports, archived evidence, and a
local no-JavaScript GUI. This roadmap prioritizes work that improves delivery
and confidence in those existing capabilities before expanding the analyzer.

## Priorities

### P1 — Versioned Windows releases (automation implemented)

The tagged-release workflow builds and publishes a Windows x64 executable for
each maintainer-created version tag, alongside a SHA-256 checksum and
instructions for verifying the download. It rejects tags that do not match the
crate version. The first public release still requires a maintainer to push a
matching tag. The checksum detects accidental corruption; it does not
authenticate the publisher. Signing and an automatic updater are not part of
this work. Existing releases are not overwritten; corrections require a new
version tag.

### P2 — Validate the supported Windows sandbox boundary (implemented)

Windows CI is pinned to Windows Server 2022 and exercises descendant
termination after a Job Object timeout, registry mount/unmount or reported
unavailability, and cleanup. Windows 7 SP1 through Windows 11 remains an
intended design range rather than a verified support range.

### P3 — Make quality checks actionable (implemented)

The repository is formatted, Clippy is warning-free across all targets, and
both checks are blocking in CI. No lint suppressions or skipped tests were
added to make them pass.

### P4 — Improve analysis coverage deliberately (decision recorded)

The current native analyzer's deep metadata and findings are PE-only. ELF,
ZIP, OLE/MSI, script, text, and unknown/binary labels are identification
results, not claims of deep analysis; ZIP and OLE/MSI contents are not
extracted. Focused tests lock down this boundary. Additional parsers are not
justified by current fixtures or evidence.

### P5 — Keep GUI browsing practical on large reports (baseline measured)

A deterministic 5,000-file synthetic report measures tree construction and
HTML rendering and caps generated output at 8 MiB. The initial local release
baseline was 14 ms and 1,626,363 HTML bytes on the current Windows development
host (timing is environment-specific); no optimization is made without a
measured bottleneck.

## Scope and status

P1–P5 have been addressed in the repository. A release has not been published
by this change. Windows CI validates Server 2022, not every intended desktop
edition or older Windows version. The roadmap is maintained in this repository;
no GitHub issues have been created for these items.
