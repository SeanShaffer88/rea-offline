# Architecture

Implements the *Universal Offline Windows Client & REA Analysis Engine*
blueprint. Pure Rust, **zero external dependencies** — a clean checkout
builds on an air-gapped machine with nothing but a Rust toolchain.

```
User / CLI
 ├─ Mode A: scan ───────────────────────────────► REA Bridge ──► JSON report
 └─ Mode B: sandbox
      1. prepare %TEMP%\rea_sandbox_<id>\  (install\ work\ tmp\)
      2. registry hive mount (sandbox_reg.dat, best-effort, warned)
      3. baseline SHA-256 snapshot of install\
      4. installer in Job Object (suspended → assign → resume),
         stdout/stderr captured to work\installer.*.log (tails in report)
      5. post-install snapshot → delta (added / modified / deleted),
         plus a whole-sandbox delta catching drops into the redirected
         profile (tmp/ work/ and the hive file are filtered out)
      6. REA analysis of install\  (external REA if found, else native)
      7. unmount hive → purge sandbox → verify zero residue
```

## Modules

| File | Blueprint module | Notes |
|---|---|---|
| `src/universal_sandbox.rs` | 1. Universal Sandbox Engine | Win32 Job Objects via direct FFI (`CreateJobObjectW`, `SetInformationJobObject`, `AssignProcessToJobObject`, `CreateProcessW` suspended). `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, process-memory ceiling, timeout → `TerminateJobObject`. Win7 SP1 → Win11, all editions incl. Home. POSIX fallback for dev/tests. |
| `src/snapshot.rs` | 2. Zero-Driver Snapshot & Delta | Recursive walk + streaming SHA-256 (`src/sha256.rs`, FIPS 180-4, no crates). Symlinked dirs never followed. |
| `src/registry_sandbox.rs` | 3. Registry Virtualization | `RegLoadKeyW`/`RegUnLoadKeyW` of `sandbox_reg.dat` under `HKEY_USERS\REA_SANDBOX_<id>`; Drop-unmount. |
| `src/rea_bridge.rs` | 4. REA Engine Bridge | Invokes local REA CLI/Node (`--rea`, `REA_PATH`, or PATH probe) with `--format json`; merges with built-in native analyzer: deep PE parsing (imported functions incl. ordinals, per-section entropy, DllCharacteristics mitigations ASLR/NX/CFG, Authenticode presence, entry point, timestamp, overlay size), Shannon entropy, capability-indicator strings, risk score, and a report `summary` block. Reports carry `schema_version: 3`; coverage fields are additive. |
| `src/cleanup.rs` | 5. Cleanup & Purge | Unmount → retrying recursive delete → existence verification. Refuses non-`rea_sandbox_*` paths without `--force`. |
| `src/report.rs` | Archived evidence | Validate scan/sandbox envelopes before rendering or gating; no target access or REA execution. |
| `src/json.rs`, `src/sha256.rs` | support | Std-only JSON + SHA-256 so the offline build needs no registry access. |

## Security model & honest limits

A Job Object is *containment*, not a hypervisor: it bounds lifetime
(whole tree dies with the job), memory, and (with the timeout) wall
clock, and the child gets a throwaway directory plus a redirected
per-user environment. It does **not** stop a determined installer from
writing elsewhere on disk or to the real registry if it runs elevated —
no user-mode-only design on Windows Home can. Run untrusted installers
from a standard (non-admin) account, and treat the delta + REA report
as the inspection record. Registry hive mounting additionally needs
`SeRestorePrivilege` (typically admin) and a valid hive file; when
unavailable the run continues with environment redirection and the
report carries a `registry_warning` field rather than failing silently.

## Offline REA

Set `REA_PATH` or pass `--rea C:\path\to\rea` (executable or Node `.js`
entry). If REA is absent, the native analyzer still produces hashes,
formats, PE metadata, indicators and a 0–100 risk score.

## Coverage is not risk

Native directory analysis records operational limitations in
`report.scan_issues`: unreadable directories/files, external REA failures, and
files above the 32 MiB content-analysis limit (full-file hashes are still
computed). `summary.complete` is false when any issue exists. These fields are
additive within schema 3 and are shown by text, Markdown, and the GUI. They do
not add risk points: an access-denied error is not evidence of malice. Symlinks
are never followed by static directory analysis.

`report <archive.json>` validates saved evidence and renders/gates it without
revisiting the target. Schema 2 remains readable; a gate requires a valid
verdict, and conflicting envelope/body verdicts are rejected.
