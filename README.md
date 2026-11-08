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
5. Re-snapshots, computes the exact added/modified/deleted delta.
6. Runs REA over the install tree (external REA if configured, otherwise
   the built-in native analyzer) and emits a structured JSON report.
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
external assets and no write endpoints. See [`docs/GUI.md`](docs/GUI.md).

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
  when the file hash differs.
* **`rules.findings`** — every point of the score is attributable to a named
  rule with the evidence that triggered it. The rulebook is
  [`src/rules.rs`](src/rules.rs) and is small enough to read in one sitting:
  no signatures, no ML, no feeds.

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
