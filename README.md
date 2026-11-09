# rea-offline

**Universal Offline Windows Client & REA Analysis Engine** — inspect local
programs and untrusted `.exe` / `.msi` installers on *any* Windows edition
(including Windows Home), with no Hyper-V, no Windows Sandbox, no drivers,
and no network. Written in Rust with **zero external dependencies**, so it
builds on a fully air-gapped machine.

## Modes

**A. Local program inspection** — static/binary analysis of an installed
app or a single file:

```bat
rea-offline.exe scan "C:\Program Files\SomeApp" --output report.json
```

**B. Ephemeral sandbox & differential installer inspection** — run an
installer contained, diff what it changed, analyze it, purge everything:

```bat
rea-offline.exe sandbox Downloads\setup.msi --output report.json --timeout 600
```

How Mode B works (blueprint workflow):

1. Creates `%TEMP%\rea_sandbox_<id>\` with `install\`, `work\`, `tmp\`.
2. Mounts a temporary registry hive (`sandbox_reg.dat`, best-effort).
3. Takes a baseline SHA-256 snapshot of the install target.
4. Creates the installer **suspended**, assigns it to a Win32 **Job Object**
   (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, 1 GB default process-memory
   ceiling), then resumes it — closing the job kills the whole tree.
5. Re-snapshots, computes the exact added/modified/deleted delta — for the
   install tree *and* for the whole sandbox, so profile drops are visible.
6. Runs REA over the install tree (external REA if configured, otherwise
   the built-in native analyzer), analyzes the installer binary itself, and
   natively analyzes every file added/modified **outside** the install
   directory (`drops_report`). The verdict is the worst of those three
   parts, so a payload dropped into `AppData` cannot hide behind an empty
   install directory.
7. Unmounts the hive, recursively purges the sandbox, and verifies
   zero residue — on every exit path.

Utilities: `report <report.json>` (render/gate an archived inspection without
rescanning), `snapshot <dir>`, `diff <before.json> <after.json>`, and
`purge <rea_sandbox_dir>` (refuses non-sandbox paths without `--force`).

**C. The window** — a WizTree-shaped view of an analysis: a sortable size
grid on the left, a risk-coloured treemap on the right, and a details pane
with hashes and the rules that fired:

```bat
rea-offline.exe gui "C:\Program Files\SomeApp"
rea-offline.exe gui Downloads\setup.exe --port 9100
rea-offline.exe gui report.json --from-report --output window.html --no-open
```

The window is served from `127.0.0.1` only and contains no JavaScript, no
external assets and no write endpoints. For a sandbox run it merges every
analyzed set into one tree — `install/`, `_installer/` and the profile-relative
drop paths — so the file that decided the verdict is one click away.
See [`docs/GUI.md`](docs/GUI.md).

## Reports

Inspection commands write JSON (schema `3`). `scan`, `sandbox`, `report`, and
`doctor` can also render for a human with `--format text` or `--format markdown`:

```
{
  "schema_version": 3,
  "verdict": "high",
  "report": {
    "file_count": 412,
    "risk_score": 41,
    "verdict": "high",
    "summary": { "by_format": {...}, "unsigned_pe_files": 3, ... },
    "rules": {
      "score": 41,
      "verdict": "high",
      "by_severity": { "critical": 0, "high": 2, "medium": 4, ... },
      "rules_fired": [ {"rule": "PE140", "title": "...", "severity": "high", "files": 1} ],
      "findings": [ {
        "rule": "PE140", "title": "Injection API set present (classic remote-thread injection)",
        "severity": "high", "score": 22, "file": "bin/setup.exe",
        "evidence": "VirtualAllocEx + WriteProcessMemory + CreateRemoteThread"
      } ]
    },
    "files": [ {
      "path": "bin/setup.exe", "size": 184320, "format": "PE",
      "sha256": "...", "md5": "...", "imphash": "...",
      "entropy": 7.61, "indicators": [...], "pe": {...}
    } ]
  }
}
```

* **`sha256` / `md5`** — full-file hashes (SHA-256 is the one to trust;
  MD5 is there because many feeds and blocklists still quote it).
* **`imphash`** — MD5 over the normalized import list, the same value
  `pefile`/VirusTotal produce, so a rebuild of a known family lines up even
  when the file hash differs. Verified against upstream pefile's
  `get_imphash()` on reference fixtures (see below).
* **`rules.findings`** — every point of the score is attributable to a named
  rule with the evidence that triggered it. The rulebook is
  [`src/rules.rs`](src/rules.rs) and is small enough to read in one sitting:
  no signatures, no ML, no feeds.

### Sandbox verdicts

A sandbox report carries a top-level `verdict` **and** `risk_score` covering
everything that was analyzed, plus the parts they came from:

```
{
  "verdict": "critical",
  "risk_score": 94,
  "verdict_sources": {
    "installer":    { "risk_score": 6,  "verdict": "low" },
    "install_tree": { "risk_score": 0,  "verdict": "low" },
    "drops":        { "risk_score": 94, "verdict": "critical" }
  },
  "report":           { ... install tree ... },
  "installer_report": { ... the installer binary ... },
  "drops_report":     { ... files added/modified outside install\ ... }
}
```

* The overall score is the **worst** part, not the sum: installers are often
  copied into the install tree, and counting the same binary twice would
  inflate the score without adding evidence.
* `verdict_sources.installer` is `null` when the installer could not be
  analyzed; the reason is recorded in `installer_error`.
* `--fail-on` reads the combined verdict, so an empty install tree no longer
  turns a critical profile drop into a passing pipeline.
* Archived reports are checked against their own sources: an envelope that
  claims a calmer verdict than its worst part is rejected, not rendered.

### Archived reports and coverage

Reopen saved evidence without access to the original machine or target:

```bat
rea-offline.exe report report.json --format markdown --output review.md
rea-offline.exe report report.json --fail-on high --quiet
rea-offline.exe gui report.json --from-report
```

`report` validates the envelope, preserves the original evidence and timestamp,
and never launches REA or rescans the target. Schema-2 archives remain readable;
a risk gate requires a valid verdict. Mistyped, repeated, or command-inappropriate
CLI options are rejected before work begins.

Directory scans disclose unreadable files/directories, failed external REA runs,
and the 32 MiB per-file content-analysis limit in `report.scan_issues` (also
summarized by `summary.complete` and `summary.scan_issue_count`). Text, Markdown,
and the window surface incomplete coverage; these operational issues do not
inflate the risk score. Regular files are analyzed without following symlinks.

`--fail-on <level>` turns the verdict into an exit code (`2` when the verdict
reaches the level), so the same report can gate a CI job or a deployment
script:

```bat
rea-offline.exe scan Downloads\setup.exe --fail-on high --quiet
```

### Coverage: a blind run is not a clean run

A verdict only describes what was actually inspected. Snapshot traversal
records every path it could not read (`issues`, `issue_count`, `complete`),
and a file it could not hash is never reported as `unchanged` — two empty
hashes are not evidence of equality, so it lands in `delta.unverified`
instead. Scan and sandbox reports aggregate all of it into one `coverage`
block naming the phase that went blind:

```json
"coverage": {
  "complete": false,
  "issue_count": 2,
  "unverified_count": 1,
  "issues": [
    {"area": "sandbox snapshot (after)", "path": "AppData/hidden",
     "stage": "traverse", "message": "Permission denied (os error 13)"},
    {"area": "sandbox", "path": "locked.bin", "stage": "compare",
     "message": "contents could not be compared: unreadable in one or both snapshots"}
  ]
}
```

Stages are `traverse` (a directory could not be listed), `entry`, `metadata`,
`path`, `hash` (a file exists but could not be read) and `compare` (present in
both snapshots, contents not comparable). Text, Markdown and the window show
the warning next to the decision, and coverage never inflates the risk score
— it is a statement about the evidence, not about the sample.

### Coverage: a run that did not finish

The delta of a killed installer is real evidence — of a *partial* install.
Nothing in the file tree says so, so how the run ended is part of coverage
too, under the area `installer execution`:

* `timeout` — the installer was killed at `--timeout`. Whatever it had
  already written is still analyzed and reported, but it is not the install
  it was going to perform.
* `exit` — the installer exited with a code that is not success, or its exit
  code could not be read at all. On Windows the documented Windows Installer
  codes `1641` and `3010` count as success: the product is installed and the
  reboot is a request, not a failure.

```json
{"area": "installer execution", "path": "setup.exe", "stage": "timeout",
 "message": "installer was killed at the timeout before it finished; the delta describes a partial install"}
```

Text and Markdown label a failing exit code next to the number it reports, and
`--fail-on-incomplete` (exit `3`) refuses a run that never finished. An archive
whose `execution` block says the installer was killed while its `coverage` says
`complete` is rejected rather than rendered.

`--fail-on-incomplete` makes partial evidence a build failure (exit `3`),
independently of how calm the verdict is:

```bat
rea-offline.exe sandbox setup.exe --fail-on high --fail-on-incomplete
rea-offline.exe report report.json --fail-on-incomplete --quiet
```

Exit codes: `0` pass, `1` error/invalid archive, `2` verdict gate, `3`
incomplete coverage. The verdict gate wins when both trip. An archive that
records no coverage at all is refused by this gate rather than assumed
complete. Archives cannot be edited into looking clean either: `coverage`
is validated against the issues it lists, the per-report `scan_issues` that
produced it, and the `execution` block that says how the run ended, so
flipping `complete` to `true` is rejected.

### imphash compatibility

Import hashing only helps if the digest means the same thing everywhere, so
the normalization follows pefile exactly:

* libraries and functions are visited in **file order** (descriptor order,
  then thunk order) — reordering imports changes the digest;
* the library is lowercased and loses its extension **only** for `.ocx`,
  `.sys` and `.dll`, so `.drv` and `.cpl` keep theirs;
* ordinal imports stay in place, qualified by library, and are resolved
  through pefile's **frozen** imphash tables: `ws2_32.dll!#23` becomes
  `ws2_32.socket`, while an unknown ordinal becomes `kernel32.ord42`;
* entries are joined with `,` and hashed with MD5.

Those frozen tables are checked in (`src/imphash_ordinals.rs`, generated by
`scripts/regen-imphash-ordinals.py` from a pefile checkout — no network needed
to build). They are deliberately *not* pefile's general-purpose ordinal
tables, which have been corrected over the years and now disagree on 147
`ws2_32` ordinals alone; upstream keeps the frozen copy precisely so imphash
stays comparable with VirusTotal, YARA and YARA-X.

`doctor` proves the running build still agrees, offline:

```bat
rea-offline.exe doctor --format markdown
```

reports `imphash self-test (pefile) | yes` alongside the SHA-256 and MD5
self-tests. The reference digests in the test suite were produced by running
upstream pefile on the same fixture binaries.

## Rule engine

Findings come from data already in the report. Each rule has a stable id, a
severity and a score contribution:

| Rule | Fires when | Severity |
|---|---|---|
| `PE001` / `PE000` | Authenticode table absent / present | low / info |
| `PE002` / `PE003` | No ASLR / no NX compatibility | medium |
| `PE004` | SEH disabled | low |
| `PE100` | Section is writable **and** executable | high |
| `PE110` | Section entropy above 7.2 (≥ 1 KiB) | medium |
| `PE120` | ≥ 4 KiB appended after the last section | medium |
| `PE130` | Packer section layout (UPX, MPress, Themida, VMProtect, …) | high |
| `PE131` | No executable section at all (unpacking stub) | medium |
| `PE140` | Injection API combinations (remote thread, hollowing, APC) | high |
| `PE141` | Anti-debugging APIs | medium |
| `PE150` | Every import resolved by ordinal | medium |
| `PE160` / `PE161` | Implausible / zeroed compile timestamp | low |
| `PE170` | Empty import table | medium |
| `ENT001` | Whole file above 7.5 entropy | medium |
| `FMT001` | `MZ` present but the PE headers do not parse | medium |
| `FMT002` | Extension/format mismatch (`.exe` that is a script, PE named `.jpg`, …) | medium |
| `STR001` | Capability strings, rolled up per category | low–medium |

## REA integration

REA ([morluto/rea](https://github.com/morluto/rea)) is invoked locally when
found via `--rea <path>`, the `REA_PATH` environment variable, or a PATH
probe (executable or Node `.js` entry). Its JSON is merged into the report
under `rea_external`. External stdout/stderr are captured through bounded
temporary files (32 MiB / 1 MiB) so a large report cannot deadlock the pipe;
stderr tails are included in failure diagnostics. When REA is absent, the native analyzer still
produces SHA-256 hashes, format detection, deep PE analysis (imported
functions incl. ordinals, per-section entropy, ASLR/NX/CFG mitigations,
Authenticode presence, overlay size), Shannon entropy (packed-binary
heuristic), capability indicators (network/execution/injection/
persistence/anti-analysis strings), a summary block, and a 0–100 risk
score — the tool is fully functional offline either way. Mode B also
diffs the whole sandbox tree, so files dropped into the redirected
user profile are reported in `sandbox_delta`, not just `install\`.

## Development

```bat
cargo test --release      :: unit + integration + CLI tests, no network
cargo build --release
```

CI (`.github/workflows/ci.yml`) runs the tests on Windows **and** Linux, then
smoke-tests the binary end to end: `doctor`, a synthetic-PE scan in all three
formats, the `--fail-on` gate, a rendered window, snapshot/diff round trip and
the purge guard. Compiler and test diagnostics are mirrored as check-run
annotations and kept as artifacts, so a failure can be read without the job
log. Builds are published as artifacts (`rea-offline-<os>`) on every green
run.

## Build (air-gapped)

```bat
build-windows.bat          :: cargo build --release — no network needed
```

Requires only a Rust toolchain; `Cargo.toml` declares no dependencies.
CI (`.github/workflows/ci.yml`) runs `cargo test --release` on Windows
and Linux.

## Layout

| Path | Module |
|---|---|
| `src/universal_sandbox.rs` | Job Object sandbox engine |
| `src/snapshot.rs` | Zero-driver snapshot & delta reconciliation |
| `src/registry_sandbox.rs` | Offline registry hive mount/unmount |
| `src/rea_bridge.rs` | REA bridge + native PE/static analyzer (imphash, MD5) |
| `src/rules.rs` | Rule engine, findings, score & verdict |
| `src/report.rs` | Archived-report validation and lossless reopening |
| `src/render.rs`, `src/mdtable.rs` | Text / Markdown rendering |
| `src/gui/` | WizTree-shaped window: tree, treemap, loopback server |
| `src/cleanup.rs` | Cleanup & zero-residue purge controller |
| `src/imphash_ordinals.rs` | Frozen pefile ordinal tables (generated, checked in) |
| `src/sha256.rs`, `src/json.rs` | Std-only SHA-256 / JSON (offline build) |
| `docs/ARCHITECTURE.md` | Design, security model, honest limitations |

## Security note

A Job Object is containment, not a hypervisor: it bounds process lifetime,
memory and wall-clock, and redirects the child's per-user environment into
the sandbox — but it cannot stop an elevated installer from writing
elsewhere (no user-mode design on Windows Home can). Run untrusted
installers from a standard account and treat the delta + REA report as
the inspection record. See `docs/ARCHITECTURE.md`.

## Contributors

Created by Sean Shaffer

## License

MIT — see [LICENSE](LICENSE).

## Changelog

### 0.9.0
- **A run that did not finish is not complete evidence**: an installer killed
  at the timeout, or one that exited without reporting success, produced a
  delta of a *partial* install that still read as `coverage: complete` — and
  passed `--fail-on-incomplete`. How the run ended is now part of coverage,
  under the area `installer execution` (stages `timeout` and `exit`).
- **Partial evidence is still reported**: a half-installed tree is analyzed and
  rendered as before. Coverage labels the run; it never discards or inflates
  what was found, and a killed installer adds no risk points.
- **Windows Installer reboot codes count as success**: `1641` and `3010` are
  documented successes (installed, reboot requested), so a reboot-requiring
  MSI is no longer reported as a run that never finished.
- **Human formats say so**: text and Markdown label an exit code that is not
  success next to the number (`3 (did not report success)`), instead of
  printing a bare `3` for the reader to interpret.
- **Tamper resistance**: an archive whose `execution` block says the installer
  was killed while its `coverage` claims `complete` is rejected (exit `1`)
  rather than rendered or gated, and a malformed `execution` block is refused.
- **Tests**: a stalling installer end to end (library, CLI exit code `3`, and
  CI), an exit-code-3 installer, writer/validator agreement on which exit
  codes count as success, and archive-level tampering on both records at once.

### 0.8.0
- **Snapshot coverage is recorded, not skipped**: an unreadable directory used
  to vanish from the manifest with no trace, so a sandbox run could under-report
  drops and still look complete. Every traversal, entry, metadata and hashing
  failure is now an issue with a stable stage name; `complete` says whether
  absence from the manifest means absence from disk.
- **Unreadable files are no longer "unchanged"**: two empty hashes with equal
  size compared equal, so an installer rewriting a locked file disappeared
  from the delta. Those files are now reported as `unverified`. A size or kind
  change is still a modification, since that needs no hash.
- **One coverage block per report**: scan and sandbox envelopes aggregate
  snapshot and analysis limits into `coverage`, naming the phase that went
  blind. Surfaced in text, Markdown and the window next to the decision.
- **`--fail-on-incomplete`** (exit `3`): refuse a verdict built on partial
  evidence, independently of the risk gate. Archives with no coverage record
  are refused rather than assumed complete.
- **Tamper resistance**: `coverage.complete` is validated against its own
  issues and the per-report `scan_issues`, so an archive cannot be flipped to
  "complete" while still listing what it never saw.
- **Tests**: real unreadable trees and files (POSIX), portable diff semantics,
  gate exit codes, archive tampering, and an end-to-end sandbox run whose
  payload hides in a directory the snapshot cannot read.

### 0.7.0
- **pefile-compatible imphash**: imports are hashed in file order (ordinals no
  longer sorted to the end), ordinals are library-qualified and resolved
  through pefile's frozen imphash tables, and only `.ocx`/`.sys`/`.dll` are
  stripped. **Digests change for files with ordinal imports** — re-baseline any
  stored values; named-only imports are unaffected unless they used `.drv` or
  `.cpl` libraries.
- **Reference-verified**: ten fixtures covering ordinal tables, extension
  handling, dotted API-set names and import order were hashed by upstream
  pefile itself and are asserted in the test suite.
- **Offline provenance**: `src/imphash_ordinals.rs` is generated by
  `scripts/regen-imphash-ordinals.py` from a local pefile checkout; the build
  still needs no network, Python or crates.
- **`doctor` self-test**: `imphash_selftest` proves the running build matches
  the published convention, including the frozen ordinal table.
- **`imphash_source()`**: exposes the exact string that gets hashed, so a
  digest can be explained instead of trusted.

### 0.6.0
- **Sandbox verdict completeness**: files added/modified outside the install
  directory are now analyzed (`drops_report`), and the top-level
  `verdict`/`risk_score` cover the installer, the install tree and the drops
  (worst part wins). `verdict_sources` shows the breakdown; `--fail-on` gates
  on it. Previously an installer that dropped its payload into the redirected
  profile could produce a `low` verdict with an empty install tree.
- **Honest installer failures**: a failed installer analysis is recorded as
  `installer_error` instead of vanishing into a null report.
- **Format rules**: `FMT001` no longer fires on every ELF file — it now means
  "MZ present but the PE headers do not parse" (medium). New `FMT002` flags
  extension/format masquerades, and never fires on unclassified content.
- **One verdict everywhere**: text/Markdown lead with the overall decision and
  per-part scores, and the window merges `install/`, `_installer/` and drop
  paths into a single tree with the combined score on the chip.
- **Archive validation**: sandbox envelopes are checked against their
  `verdict_sources`, so a rewritten "calm" verdict is rejected.
- **POSIX sandbox fix**: a relative installer path is resolved before spawn
  (it was looked up on `PATH` and failed even though the file existed).
- **Tests**: end-to-end profile-drop verdict, gate and GUI coverage on both
  platforms, merged-view path handling, and format-rule regressions.

### 0.5.1
- **Strict JSON input**: the std-only parser now rejects malformed numbers,
  unescaped control characters, lone surrogates, duplicate object keys and
  excessive nesting instead of silently repairing untrusted reports/REA output.
- **External REA capture**: stdout/stderr are drained through bounded temporary
  files while the child runs, fixing pipe-buffer deadlocks on large reports and
  preserving stderr diagnostics; capture files are cleaned up on every exit path.
- **Tests**: JSON conformance/hostile-input cases, large-stream capture, timeout
  cleanup, and an end-to-end external REA merge with >200 KB of JSON.

### 0.5.0
- **Archived reports** (`report`): validate and render saved scan/sandbox JSON,
  apply `--fail-on` without rescanning, and reopen the same evidence in the GUI.
- **Strict CLI parsing**: reject unknown/misplaced options, missing values,
  duplicate flags, excess positional arguments, and invalid zero port/memory limits.
- **Coverage warnings**: unreadable content, external REA failures, and oversized
  files are recorded in `scan_issues` and surfaced in every human format.
- **Tests/CI**: archive round-trip and gate checks, hostile argument cases,
  permission-denied coverage, external-engine failure, and symlink boundary checks.

### 0.4.0
- **GUI** (`gui`): WizTree-shaped window — sortable size/risk grid, risk-coloured
  treemap, details pane with hashes and findings; loopback-only, no JavaScript;
  `--from-report` reopens archived reports.
- **Rule engine** (`src/rules.rs`): 18 explainable rules, stable ids, severities,
  and a 0–100 score where every point is attributable. `verdict` on every report.
- **Hashes**: MD5 and **imphash** alongside SHA-256; `doctor` self-tests both.
- **Human output**: `--format text|markdown`, `src/render.rs`, escaped Markdown tables.
- **CLI contract**: `--fail-on <level>` (exit 2), `--output` keeps stdout clean,
  `--format=value` form, `sample` fixtures, `gui --output` static pages.
- **Tests**: 60+ unit/integration/CLI cases including an end-to-end hostile-binary
  pipeline and a synthetic PE builder (`src/testutil.rs`).
- **CI**: Windows + Linux on every push, annotated diagnostics, published binaries.


### 0.2.0
- Deep PE parser: imported functions/ordinals, per-section entropy, mitigations, Authenticode presence, overlay detection; risk score factors in missing NX/ASLR, W+X sections, overlays.
- Mode B whole-sandbox delta (`sandbox_delta`) for profile-redirected drops.
- `schema_version: 2` on reports, report `summary` block, `--version` flag.

### 0.3.0
- Installer stdout/stderr captured to sandbox log files; tails + byte counts in the report's `execution` block.
- Mode B also analyzes the installer binary itself (`installer_report`).
- Job Object active-process ceiling (`--max-processes`, default 32).
- New `doctor` preflight command (platform, sandbox create/purge rehearsal, REA discovery).
