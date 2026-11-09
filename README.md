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
   directory (`drops_report`) — including its own temp folder (`tmp\`,
   where its `TEMP` points) and its working directory (`work\`); only the
   sandbox's own files (the hive and the two capture logs) are excluded.
   The verdict is the worst of those three
   parts, so a payload dropped into `AppData` cannot hide behind an empty
   install directory.
7. Unmounts the hive, recursively purges the sandbox, and verifies
   zero residue — on every exit path.

Utilities: `report <report.json>` (render/gate an archived inspection without
rescanning), `snapshot <dir>`, `diff <before.json> <after.json>`, and
`purge <rea_sandbox_dir>` (refuses non-sandbox paths without `--force`).

`snapshot` / `diff` are the workflow for a machine where the sandbox cannot
run: snapshot, install for real, then diff. That delta is only as trustworthy
as the two manifests behind it, so both commands carry the same `coverage`
record a report does — a diff inherits the blind spots of **both** snapshots
(two manifests that each failed to list the same directory agree completely,
and that agreement is not evidence) — and both accept `--fail-on-incomplete`:

```bat
rea-offline.exe snapshot "C:\Program Files" --output before.json --fail-on-incomplete
rea-offline.exe diff before.json after.json --fail-on-incomplete
```

A delta is only meaningful if the two manifests describe the same thing, so
`diff` refuses anything that is not a snapshot manifest (a report archive
handed to it by mistake exits `1` rather than reporting every file as
deleted), and the document names both sides — `before_root`, `after_root`
and their capture times. The entries inside a manifest are held to the same
standard: an entry that is not an object, has no path, duplicates an earlier
path, or carries a size or hash of the wrong shape is refused at load
(exit `1`) rather than silently dropped, overwritten or defaulted — a
manifest that loses entries on the way in would diff with complete-looking
coverage of evidence it never actually held. (A missing `sha256` stays
lenient by design: it is an empty digest, which diffs as `unverified`,
never as `unchanged`.) Two different directories compared by accident, or
an `after` that predates the `before` (swapped arguments invert `added` and
`deleted`), are recorded as coverage issues rather than quietly assumed
away: they gate, they do not refuse, because a manifest stores root-relative
paths precisely so it stays comparable after the tree is moved.

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
inflate the risk score. Files are analyzed without following symlinks — and a
link a scan does not follow is named in `scan_issues` (stage `symlink`), as is
anything that is not a regular file or directory (stage `special`), so a tree
whose links were never looked behind does not read as completely scanned.

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

### Coverage: what the sandbox could not contain

A Job Object is containment, not a hypervisor, and nothing in a file tree can
tell you what escaped it. Each sandbox run records that in `containment`:

```json
"containment": {
  "elevated": false,
  "registry": {"mounted": false, "status": "unavailable", "message": "..."},
  "limits": ["writes outside the sandbox tree are not visible: ..."]
}
```

* `elevated` — the run was **elevated** (administrator) or **root**: the
  installer could write outside the sandbox tree, and anything written there
  is missing from the delta and from every hash in the report. This is the
  documented advice ("run untrusted installers from a standard account") made
  checkable: an elevated run is incomplete coverage, and `doctor` tells you
  before you start which session you are in.
* `registry.status` — `mounted` (redirected writes landed in the sandbox
  file), `unavailable` (a registry exists but the hive would not mount, so
  installer registry writes were neither redirected nor visible), or
  `not-applicable` (POSIX: there is no registry to redirect).
* `limits` — what this **method** can never see, so an archived report can be
  read without the manual: registry writes (no driver to redirect them),
  writes outside the sandbox tree, the absence of any process, network or
  syscall monitoring, and files created and deleted between the two
  snapshots — a delta only sees what exists at the capture moments, so a
  drop that cleans up after itself leaves no trace. These are true of every
  run, so they are *not* coverage issues — a warning that is always on is a
  warning nobody reads.

An archive that claims `coverage: complete` while its `containment` block says
the run was elevated, or that the hive never mounted, is rejected rather than
rendered.

### Coverage: a failure the report admits

The coverage block is a **summary of the envelope**, so anything the report
records as not happening is a coverage issue and not merely a footnote:

| the report says | coverage issue |
|---|---|
| `installer_error` (the installer could not be read or analyzed) | area `installer analysis`, stage `analysis` — one of the three evidence sets is missing, which is not the same as clean |
| `purge_error` (the sandbox could not be cleaned up) | area `cleanup`, stage `purge` — the machine still holds the installer's files |
| `purge.verified_zero_residue: false` (deleted, but residue unconfirmed) | area `cleanup`, stage `verify` |

A dropper that deletes itself after running is the ordinary case for the first
row: the artifact the report most needs is gone. Its part of the verdict stays
`null` rather than a silent zero, and the run is incomplete — so
`--fail-on-incomplete` (exit `3`) catches it instead of a calm verdict sailing
through a pipeline.

`--fail-on-incomplete` makes partial evidence a build failure (exit `3`),
independently of how calm the verdict is. It works on every command that
produces evidence — `scan`, `sandbox`, `report`, and the `snapshot` / `diff`
pair. A file neither snapshot could hash counts as something the inspection
did not see: an empty hash on both sides is not evidence that nothing
changed.

```bat
rea-offline.exe sandbox setup.exe --fail-on high --fail-on-incomplete
rea-offline.exe report report.json --fail-on-incomplete --quiet
rea-offline.exe diff before.json after.json --fail-on-incomplete
```

The gate reads the `issues` list, not the `complete` flag: a coverage record
that claims to be complete while listing what it never saw is refused
(exit `1`) instead of believed.

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
| `src/containment.rs` | What a run could not contain (privileges, registry) |
| `src/coverage.rs` | Coverage vocabulary: what a report means by incomplete |
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

### 0.17.0

- **Double-clicking the .exe now opens the window.** The program is a console tool: run with no command it printed the help text and exited — and a console opened by a double-click closes the moment the program exits, so the release read as "the file does nothing". A launch with no console of the user's (the double-click signature) now opens the GUI picker instead: a page asking what to inspect — a file, folder or installer, or a report saved earlier — which then shows that inspection's window, with a link back to pick something else. `gui` with no path opens the same picker from a terminal. In a terminal, running with no command still prints help, and every command behaves exactly as before.

### 0.16.0

- **A file that changes while it is being read no longer looks stable.** Snapshots took a file's size before streaming its contents for the hash; a file rewritten mid-read paired one version's hash with another's size, and later diffs trusted the pair. Capture now re-checks size and modification time after hashing: on any movement the file stays in the manifest but unverified, with a `changed` coverage issue naming it.
- **Archives too old to have a coverage record now say so.** Text, Markdown, and the GUI window only warned when a coverage block existed; an archive with no block at all (schema-2 era) and no scan issues rendered exactly like a complete inspection. All three surfaces now state that coverage was **not recorded** and what the inspection could not see is unknown. (The risk gate already refused such archives; the displays now match it.)

### 0.15.0
- **The sandbox no longer throws away the installer's temp folder**: the
  whole-sandbox delta filtered out everything under `tmp\` and `work\` as
  "sandbox bookkeeping". They are the installer's folders — `TEMP`/`TMP`
  point at `tmp\`, and the installer runs with `work\` as its working
  directory — so a payload staged in its temp folder, or dropped next to
  its working directory, never reached the delta, was never analyzed as a
  drop, and was not recorded as excluded anywhere. Only the sandbox's own
  files are filtered now (the install tree, reported separately; the
  registry hive file; and the two `work\installer.*.log` capture logs), and
  temp/working-directory drops are analyzed into `drops_report` and count
  toward the verdict like any other drop.
- **A scan names the links it does not follow**: directory analysis never
  follows symlinks (a link could pull a file outside the tree into the
  report), but it skipped them in silence — the link appeared nowhere, and
  `summary.complete` still claimed a complete scan. Each skipped symlink
  is now a `scan_issues` entry (stage `symlink`), as is anything that is
  not a regular file or directory (stage `special`), so the coverage
  record and every human format disclose what was not analyzed.
- **Tests**: a temp-staged payload and a working-directory drop analyzed
  as drops end to end; the profile-drop delta test now expects the temp
  file it used to assert was filtered; the symlink boundary test now
  expects both links named instead of an empty issue list; a CLI scan
  naming a link as a coverage issue; and CI smoke checks for a
  temp-staged drop and a scanned link.

### 0.14.0
- **A manifest refuses entries it cannot read**: `diff` refused a document
  that was not a snapshot manifest, but inside a real manifest an entry with
  no path was silently skipped, a duplicate path silently overwrote the
  first entry, and a missing or mistyped size was defaulted to zero — the
  loaded manifest held fewer files than the one on disk, and the delta
  still claimed complete coverage. Entries are now validated on load: a
  non-object entry, a missing or empty path, a duplicate path, a size that
  is absent, negative, fractional or not a number, and a non-string
  `sha256`/`kind` are all refused with exit `1`, naming the entry. A missing
  `sha256` remains an empty digest by design — it diffs as `unverified`,
  not `unchanged`.
- **A drop that cleans up after itself is now a stated limit**: a file
  created and deleted between the before and after snapshots leaves no
  trace in either, and unlike every other standing blind spot this one was
  stated nowhere. It is now in `containment.limits` on every sandbox
  report, alongside registry writes, writes outside the tree and the
  absence of runtime telemetry.
- **Tests**: malformed-entry refusal for each failure shape (library),
  an absent hash loading as unverified, CLI exit `1` on duplicated and
  pathless entries, the transient-drop limit asserted on the containment
  block, and CI smoke checks for both. The permission-based fixtures also
  now skip cleanly under a privileged (root) test runner instead of
  failing: root ignores mode bits, so the fixture cannot be built there.

### 0.13.0
- **A delta refuses what it cannot compare**: `diff` accepted any two JSON
  documents. A report archive — or an empty file — loaded as "a snapshot of
  nothing", and comparing it to a real tree reported every file as added or
  deleted while the coverage block claimed the comparison was complete. Both
  inputs must now be snapshot manifests, with a `root` and an `entries` list.
- **A delta names both sides**: the document records `before_root`,
  `after_root`, `before_created_unix` and `after_created_unix`, so what was
  compared to what can be checked by hand.
- **Comparability is coverage, not a crash**: two different directories, or
  an `after` that predates the `before`, are recorded as coverage issues
  (stages `root` and `order`) and fail `--fail-on-incomplete` — they are not
  refused outright, because a manifest stores root-relative paths so it stays
  comparable after the tree is moved to another machine.
- **Tests**: manifests that are not manifests are refused in either position;
  a cross-tree diff reports both roots and gates; unit coverage for swapped
  arguments, undated manifests and same-second captures; CLI exit codes `1`
  and `3`; and CI checks for the refusal and the cross-tree delta.

### 0.12.0
- **A diff inherits the blindness of both snapshots**: `diff before.json
  after.json` dropped both manifests' traversal issues, so a directory neither
  snapshot could list looked *unchanged*. The delta now carries a `coverage`
  block aggregating both (`before snapshot` / `after snapshot`) plus every file
  whose contents could not be compared — the same rule the sandbox already
  applied to its own two deltas, so the manual workflow is neither more nor
  less permissive than the run it stands in for.
- **`snapshot` and `diff` are gateable**: both take `--fail-on-incomplete`
  (exit `3`), so the manual workflow — snapshot, install for real, diff — can
  refuse partial evidence the same way a sandbox run does. Both documents now
  carry the standard `coverage` block alongside their existing fields.
- **The gate reads evidence, not a flag**: `--fail-on-incomplete` derives
  incompleteness from the `issues` list, so a coverage record claiming
  `complete` while listing blind spots is refused (exit `1`) rather than
  believed. Reports are validated when loaded; snapshots and diffs are not, so
  the gate no longer trusts a boolean it can check.
- **Tests**: a snapshot/diff round trip that carries coverage; an unreadable
  directory making both incomplete and naming each phase; an unreadable *file*
  that the diff refuses to call unchanged, pinning that the manual workflow is
  no more permissive than the sandbox; CLI exit codes for both commands; and
  CI checks including a real locked-directory diff.

### 0.11.0
- **A failure the report admits is now a coverage failure**: a run whose
  installer could not be analyzed, or whose sandbox could not be cleaned up,
  reported `coverage: complete` — the installer is one of the three evidence
  sets, so "we could not read it" was not the same as "it was clean", yet the
  record claimed otherwise and `--fail-on-incomplete` passed.
- **The coverage block is a derived summary of the envelope.** New
  `src/coverage.rs` owns the vocabulary; the block is finished against the
  finished envelope, using the same function (`coverage::recorded_failures`)
  the archive validator uses, so the two cannot drift.
- **What counts**: `installer_error` (area `installer analysis`), `purge_error`
  and `purge.verified_zero_residue: false` (area `cleanup`). Recording is
  idempotent, so the block is a summary rather than an append-only log.
- **Tamper resistance**: an archive claiming `coverage: complete` while it
  records any of those failures is rejected (exit `1`) rather than rendered.
- **Tests**: an installer that deletes itself after dropping its payload
  (library, CLI exit `3`, and CI), coverage/validator agreement on each
  recorded failure, block arithmetic after recording, and archive tampering.

### 0.10.0
- **What the sandbox could not contain is now on the record**: an elevated or
  root run — or one where the registry hive would not mount — still reported
  `coverage: complete`, even though the installer could have written outside
  the sandbox tree where no snapshot looks. New `containment` block covers
  both, and they fold into coverage when they mean evidence is missing.
- **`elevated`**: the documented "run from a standard account" advice is now
  checkable. An elevated run is incomplete coverage (area `containment`,
  stage `elevated`), and `doctor` reports which session you are in before you
  trust a run. An elevation the platform will not disclose is recorded as
  `elevation-unknown` rather than assumed away.
- **`registry.status`**: `mounted` / `unavailable` / `not-applicable`. POSIX
  runs now report `not-applicable` instead of claiming a mounted hive, and a
  failed mount carries the reason into the report.
- **`containment.limits`**: the method's standing blind spots (registry
  writes, writes outside the sandbox tree, no runtime telemetry) travel with
  every report so an archived verdict can be read without the manual. They are
  deliberately *not* coverage issues — always-on warnings are ignored ones.
- **Tamper resistance**: an archive claiming `coverage: complete` for a run its
  own `containment` block admits was not contained is rejected (exit `1`).
- **Tests**: privilege/registry classification on every platform, an
  end-to-end run asserting the block against the real environment, archive
  tampering against both records, `doctor`'s new field, and CI checks.

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
