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
    pub output: Option<PathBuf>,
    pub rea_path: Option<PathBuf>,
}

/// Mode A — Local Program Inspection.
pub fn mode_scan(opts: ScanOptions) -> Result<Value> {
    let bridge = ReaBridge::new(ReaConfig { rea_path: opts.rea_path, timeout: None });
    let report = bridge.analyze(&opts.target)?;
    let json = Value::obj(vec![
        ("mode", Value::str("local-scan")),
        ("generated_unix", Value::num(unix_secs())),
        ("report", report.to_json()),
    ]);
    emit(&json, &opts.output)?;
    Ok(json)
}

pub struct SandboxOptions {
    pub installer: PathBuf,
    pub installer_args: Vec<String>,
    pub output: Option<PathBuf>,
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
    emit(&report, &opts.output)?;
    Ok(report)
}

fn run_sandbox_inner(opts: &SandboxOptions, sandbox: &Sandbox, install_dir: &Path) -> Result<Value> {
    // Baseline snapshot of the (empty) install target.
    let before = Snapshot::capture(install_dir)?;
    // 3. Execution under containment.
    let outcome = sandbox.run_installer(&opts.installer, &opts.installer_args)?;
    // 4. Post-install snapshot & delta.
    let after = Snapshot::capture(install_dir)?;
    let delta = before.diff(&after);
    // 5. REA inspection of exactly what the installer changed.
    let bridge = ReaBridge::new(ReaConfig { rea_path: opts.rea_path.clone(), timeout: None });
    let rea_report = bridge.analyze(install_dir)?;
    Ok(Value::obj(vec![
        ("mode", Value::str("sandbox-installer")),
        ("generated_unix", Value::num(unix_secs())),
        ("installer", Value::str(opts.installer.display().to_string())),
        ("execution", Value::obj(vec![
            ("command", Value::str(outcome.command.clone())),
            ("exit_code", outcome.exit_code.map(|c| Value::num(c as u64)).unwrap_or(Value::Null)),
            ("timed_out", Value::Bool(outcome.timed_out)),
            ("duration_ms", Value::num(outcome.duration_ms)),
        ])),
        ("delta", delta.to_json()),
        ("report", rea_report.to_json()),
    ]))
}

pub fn mode_snapshot(dir: &Path, output: &Option<PathBuf>) -> Result<Value> {
    let snap = Snapshot::capture(dir)?;
    if let Some(out) = output { snap.save(out)?; }
    Ok(snap.to_json())
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

fn emit(json: &Value, output: &Option<PathBuf>) -> Result<()> {
    let text = json.to_string_pretty();
    match output {
        Some(path) => {
            std::fs::write(path, format!("{text}\n"))?;
            eprintln!("[rea-offline] report written to {}", path.display());
        }
        None => println!("{text}"),
    }
    Ok(())
}
