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
        output: None,
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
        output: None,
        rea_path: None,
        sandbox: config,
    }).unwrap();
    let text = report.to_string_pretty();
    assert!(text.contains("dropped.exe"), "delta should name the dropped file:\n{text}");
    CleanupController::purge_dir(&root, false).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}
