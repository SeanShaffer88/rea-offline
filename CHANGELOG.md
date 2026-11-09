# Changelog

## [0.13.0] - 2026-11-08

### Added

- Automated version-tagged Windows x64 releases with a SHA-256 checksum.
- Windows sandbox regression coverage for Job Object process-tree termination,
  registry-hive outcomes, and cleanup.
- A documented project roadmap and a large-report GUI rendering baseline.

### Changed

- Made Rust formatting and warning-free Clippy checks blocking in CI.
- Documented the native analyzer's PE-only deep-analysis boundary and its
  identification-only formats.
- Clarified the Windows versions exercised by CI versus intended compatibility
  targets.
