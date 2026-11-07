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

Utilities: `snapshot <dir>`, `diff <before.json> <after.json>`,
`purge <rea_sandbox_dir>` (refuses non-sandbox paths without `--force`).

## REA integration

REA ([morluto/rea](https://github.com/morluto/rea)) is invoked locally when
found via `--rea <path>`, the `REA_PATH` environment variable, or a PATH
probe (executable or Node `.js` entry). Its JSON is merged into the report
under `rea_external`. When REA is absent, the native analyzer still
produces SHA-256 hashes, format detection, deep PE analysis (imported
functions incl. ordinals, per-section entropy, ASLR/NX/CFG mitigations,
Authenticode presence, overlay size), Shannon entropy (packed-binary
heuristic), capability indicators (network/execution/injection/
persistence/anti-analysis strings), a summary block, and a 0–100 risk
score — the tool is fully functional offline either way. Mode B also
diffs the whole sandbox tree, so files dropped into the redirected
user profile are reported in `sandbox_delta`, not just `install\`.

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
| `src/rea_bridge.rs` | REA bridge + native PE/static analyzer |
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

### 0.2.0
- Deep PE parser: imported functions/ordinals, per-section entropy, mitigations, Authenticode presence, overlay detection; risk score factors in missing NX/ASLR, W+X sections, overlays.
- Mode B whole-sandbox delta (`sandbox_delta`) for profile-redirected drops.
- `schema_version: 2` on reports, report `summary` block, `--version` flag.

### 0.3.0
- Installer stdout/stderr captured to sandbox log files; tails + byte counts in the report's `execution` block.
- Mode B also analyzes the installer binary itself (`installer_report`).
- Job Object active-process ceiling (`--max-processes`, default 32).
- New `doctor` preflight command (platform, sandbox create/purge rehearsal, REA discovery).
