use rea_offline::cleanup::CleanupController;
use rea_offline::rea_bridge::{ReaBridge, ReaConfig};
use rea_offline::snapshot::Snapshot;
use std::path::PathBuf;

fn tmp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rea_offline_it_{tag}_{}", rea_offline::util::new_id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn snapshot_save_load_diff_roundtrip() {
    let dir = tmp_dir("snap");
    std::fs::write(dir.join("a.txt"), b"hello").unwrap();
    let snap_path = dir.join("snap.json");
    Snapshot::capture(&dir).unwrap().save(&snap_path).unwrap();
    let loaded = Snapshot::load(&snap_path).unwrap();
    assert!(loaded.entries.contains_key("a.txt"));
    std::fs::write(dir.join("b.bin"), b"\x7fELF fake").unwrap();
    let after = Snapshot::capture(&dir).unwrap();
    let delta = loaded.diff(&after);
    assert!(delta.added.iter().any(|e| e.path == "b.bin"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn native_analyzer_flags_indicators_and_hashes() {
    let dir = tmp_dir("rea");
    let file = dir.join("sample.txt");
    std::fs::write(&file, b"beacon https://example.invalid and CreateRemoteThread").unwrap();
    let bridge = ReaBridge::new(ReaConfig::default());
    let report = bridge.analyze(&file).unwrap();
    assert_eq!(report.files.len(), 1);
    assert_eq!(report.files[0].sha256.len(), 64);
    assert!(report.files[0].indicators.iter().any(|i| i.category == "injection"));
    assert!(report.risk_score() > 0);
    let json = report.to_json();
    let text = json.to_string_pretty();
    assert!(rea_offline::json::parse(&text).is_ok(), "report must be valid JSON");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn purge_removes_sandbox_tree_and_verifies() {
    let dir = std::env::temp_dir().join(format!("rea_sandbox_{}", rea_offline::util::new_id()));
    std::fs::create_dir_all(dir.join("install")).unwrap();
    std::fs::write(dir.join("install/app.exe"), b"MZ").unwrap();
    let report = CleanupController::purge_dir(&dir, false).unwrap();
    assert!(report.removed && report.verified_zero_residue);
    assert!(!dir.exists());
}

#[cfg(unix)]
#[test]
fn sandbox_delta_catches_drops_outside_install_dir() {
    use rea_offline::app::{mode_sandbox, SandboxOptions};
    use rea_offline::universal_sandbox::SandboxConfig;
    let dir = tmp_dir("profiledrop");
    let script = dir.join("fake_installer.sh");
    // Installers commonly write into the (redirected) user profile, not
    // the install dir — the whole-sandbox delta must surface that.
    std::fs::write(&script, "#!/bin/sh\nprintf 'profile payload' > \"$REASANDBOX/profile_drop.txt\"\nprintf 'scratch' > \"$REASANDBOX/tmp/scratch.txt\"\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let root = std::env::temp_dir().join(format!("rea_sandbox_{}", rea_offline::util::new_id()));
    let mut config = SandboxConfig::default();
    config.root = Some(root.clone());
    config.keep = true;
    let report = mode_sandbox(SandboxOptions {
        installer: script,
        installer_args: vec![],
        rea_path: None,
        sandbox: config,
    }).unwrap();
    let sandbox_delta = report.get("sandbox_delta").expect("sandbox_delta in report");
    let added = sandbox_delta.get("added").expect("added list");
    let text = format!("{added:?}");
    assert!(text.contains("profile_drop.txt"), "profile drop must be reported: {text}");
    assert!(!text.contains("scratch.txt"), "tmp/ bookkeeping must be filtered out: {text}");
    CleanupController::purge_dir(&root, false).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

#[cfg(unix)]
#[test]
fn sandbox_captures_installer_output_and_exit_code() {
    use rea_offline::app::{mode_sandbox, SandboxOptions};
    use rea_offline::universal_sandbox::SandboxConfig;
    let dir = tmp_dir("outcap");
    let script = dir.join("noisy_installer.sh");
    std::fs::write(&script, "#!/bin/sh\necho 'installing widgets...'\necho 'warning: widget quota low' >&2\nexit 3\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let root = std::env::temp_dir().join(format!("rea_sandbox_{}", rea_offline::util::new_id()));
    let mut config = SandboxConfig::default();
    config.root = Some(root.clone());
    let report = mode_sandbox(SandboxOptions {
        installer: script,
        installer_args: vec![],
        rea_path: None,
        sandbox: config,
    }).unwrap();
    let execution = report.get("execution").expect("execution block");
    let text = format!("{execution:?}");
    assert!(text.contains("installing widgets"), "stdout tail captured: {text}");
    assert!(text.contains("widget quota low"), "stderr tail captured: {text}");
    // The installer file itself is analyzed as evidence too.
    let installer_report = report.get("installer_report").expect("installer report");
    assert!(installer_report.get("file_count").is_some());
    assert!(!root.exists(), "sandbox purged after run");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[cfg(unix)]
#[test]
fn sandbox_runs_harmless_program_and_captures_delta() {
    use rea_offline::app::{mode_sandbox, SandboxOptions};
    use rea_offline::universal_sandbox::SandboxConfig;
    // A tiny shell script acts as a stand-in "installer" on POSIX dev boxes.
    let dir = tmp_dir("installer");
    let script = dir.join("fake_installer.sh");
    std::fs::write(&script, "#!/bin/sh\nmkdir -p \"$REASANDBOX_INSTALL\"\nprintf 'MZ dropped' > \"$REASANDBOX_INSTALL/dropped.exe\"\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let root = std::env::temp_dir().join(format!("rea_sandbox_{}", rea_offline::util::new_id()));
    let mut config = SandboxConfig::default();
    config.root = Some(root.clone());
    config.keep = true; // inspect first, then let purge be exercised below
    let report = mode_sandbox(SandboxOptions {
        installer: script,
        installer_args: vec![],
        rea_path: None,
        sandbox: config,
    }).unwrap();
    let text = report.to_string_pretty();
    assert!(text.contains("dropped.exe"), "delta should name the dropped file:\n{text}");
    CleanupController::purge_dir(&root, false).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn external_rea_failure_is_reported_without_losing_native_evidence() {
    let dir = tmp_dir("rea-failure");
    let target = dir.join("sample.txt");
    let broken_rea = dir.join("broken-rea");
    std::fs::write(&target, b"CreateRemoteThread https://example.invalid").unwrap();
    // Exists but is not executable: discovery selects it, spawning fails on
    // both Unix and Windows. Native analysis must still produce evidence.
    std::fs::write(&broken_rea, b"not an executable").unwrap();
    let bridge = ReaBridge::new(ReaConfig { rea_path: Some(broken_rea), timeout: None });
    let report = bridge.analyze(&target).unwrap();
    assert_eq!(report.files.len(), 1);
    assert!(report.files[0].indicators.iter().any(|i| i.category == "injection"));
    assert!(report.scan_issues.iter().any(|i| i.stage == "rea-external"), "{:?}", report.scan_issues);
    let json = report.to_json();
    assert_eq!(json.get("summary").and_then(|s| s.get("complete")), Some(&rea_offline::json::Value::Bool(false)));
    let envelope = rea_offline::json::Value::obj(vec![
        ("schema_version", rea_offline::json::Value::num(rea_offline::SCHEMA_VERSION)),
        ("mode", rea_offline::json::Value::str("local-scan")),
        ("verdict", rea_offline::json::Value::str(report.verdict())),
        ("report", json),
    ]);
    assert!(rea_offline::report::validate(&envelope).is_ok());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[cfg(unix)]
#[test]
fn directory_analysis_does_not_follow_symlinks_outside_the_target() {
    let dir = tmp_dir("symlink");
    let target = dir.join("tree");
    let outside = dir.join("outside");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(target.join("inside.txt"), b"inside").unwrap();
    std::fs::write(outside.join("secret.txt"), b"outside secret").unwrap();
    std::os::unix::fs::symlink(&outside, target.join("linked-dir")).unwrap();
    std::os::unix::fs::symlink(outside.join("secret.txt"), target.join("linked-file.txt")).unwrap();
    let report = ReaBridge::new(ReaConfig::default()).analyze(&target).unwrap();
    assert_eq!(report.files.len(), 1);
    assert_eq!(report.files[0].path, "inside.txt");
    assert!(report.scan_issues.is_empty());
    std::fs::remove_dir_all(&dir).unwrap();
}
