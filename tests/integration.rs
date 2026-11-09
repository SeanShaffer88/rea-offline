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

/// The manual workflow is snapshot → install → diff. A delta is only as
/// trustworthy as the two manifests behind it, so the diff has to carry both
/// sets of issues instead of silently agreeing wherever neither could look.
#[test]
fn a_diff_inherits_the_blindness_of_both_snapshots() {
    let dir = tmp_dir("diff-coverage");
    std::fs::write(dir.join("a.txt"), b"one").unwrap();
    std::fs::write(dir.join("b.txt"), b"two").unwrap();

    let before_path = dir.join("before.json");
    let after_path = dir.join("after.json");
    Snapshot::capture(&dir).unwrap().save(&before_path).unwrap();
    std::fs::write(dir.join("c.txt"), b"three").unwrap();
    Snapshot::capture(&dir).unwrap().save(&after_path).unwrap();

    // A fully readable tree: the manifest's own fields and the coverage
    // record the gate reads agree with each other.
    let snapshot = rea_offline::app::mode_snapshot(&dir).unwrap();
    assert_eq!(
        snapshot.get("coverage").and_then(|c| c.get("complete")),
        Some(&rea_offline::json::Value::Bool(true)),
        "a fully readable tree is complete: {snapshot:?}"
    );
    assert_eq!(snapshot.get("complete"), Some(&rea_offline::json::Value::Bool(true)),
        "the manifest's pre-existing fields are unchanged: {snapshot:?}");
    // The saved manifest keeps the shape `diff` reads back: issues, not a
    // coverage block, since the diff recomputes it from both sides.
    let saved = rea_offline::json::parse(&std::fs::read_to_string(&before_path).unwrap()).unwrap();
    assert_eq!(saved.get("complete"), Some(&rea_offline::json::Value::Bool(true)), "{saved:?}");

    let diff = rea_offline::app::mode_diff(&before_path, &after_path).unwrap();
    let coverage = diff.get("coverage").expect("a diff carries its coverage record");
    assert_eq!(coverage.get("complete"), Some(&rea_offline::json::Value::Bool(true)),
        "{coverage:?}");
    // The change is still there: coverage describes the evidence, not the delta.
    let added = format!("{:?}", diff.get("added"));
    assert!(added.contains("c.txt"), "{added}");

    std::fs::remove_dir_all(&dir).unwrap();
}

#[cfg(unix)]
#[test]
fn an_unreadable_directory_makes_the_snapshot_and_the_diff_incomplete() {
    use rea_offline::json::Value;
    use std::os::unix::fs::PermissionsExt;

    let dir = tmp_dir("diff-blind");
    let tree = dir.join("tree");
    let locked = tree.join("locked");
    std::fs::create_dir_all(&locked).unwrap();
    std::fs::write(locked.join("payload.exe"), b"MZ").unwrap();
    std::fs::write(tree.join("visible.txt"), b"hi").unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::read_dir(&locked).is_ok() {
        // Running with privilege that ignores mode bits: nothing to prove.
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        return;
    }

    let before_path = dir.join("before.json");
    let after_path = dir.join("after.json");
    Snapshot::capture(&tree).unwrap().save(&before_path).unwrap();
    std::fs::write(tree.join("dropped.exe"), b"MZ dropped").unwrap();
    Snapshot::capture(&tree).unwrap().save(&after_path).unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();

    // Both manifests were captured while the directory was locked, and both
    // say so — before the diff is asked to compare them.
    for (label, path) in [("before", &before_path), ("after", &after_path)] {
        let saved = rea_offline::json::parse(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(
            saved.get("complete"),
            Some(&Value::Bool(false)),
            "{label} snapshot must not claim to be complete: {saved:?}"
        );
    }
    // ...so the diff between them is not evidence that nothing changed there.
    let diff = rea_offline::app::mode_diff(&before_path, &after_path).unwrap();
    let coverage = diff.get("coverage").expect("coverage record");
    assert_eq!(coverage.get("complete"), Some(&Value::Bool(false)),
        "two blind snapshots agreeing is not evidence: {coverage:?}");
    let issues = match coverage.get("issues") {
        Some(Value::Array(items)) => items.clone(),
        other => panic!("issues array expected, got {other:?}"),
    };
    assert!(issues.len() >= 2, "both snapshots' blind spots are carried: {issues:?}");
    assert!(
        issues.iter().any(|i| i.get("area").and_then(Value::as_str) == Some("before snapshot"))
            && issues.iter().any(|i| i.get("area").and_then(Value::as_str) == Some("after snapshot")),
        "each phase is named: {issues:?}"
    );
    assert!(issues.iter().all(|i| i.get("path").and_then(Value::as_str)
        .map(|p| p.contains("locked")).unwrap_or(false)), "the locked directory is named: {issues:?}");

    std::fs::remove_dir_all(&dir).unwrap();
}

/// The subtler blindness: a file both manifests listed but neither could
/// read looks *unchanged*, because two empty hashes are not evidence of
/// equality either. The diff must be no more permissive than the sandbox run
/// it substitutes for, which already counts uncomparable files against its
/// own coverage — that is what `unverified_count` is there to carry.
#[cfg(unix)]
#[test]
fn a_file_neither_snapshot_could_read_counts_against_the_diff() {
    use rea_offline::json::Value;
    use std::os::unix::fs::PermissionsExt;

    let dir = tmp_dir("diff-unverified");
    let tree = dir.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    let secret = tree.join("secret.bin");
    std::fs::write(&secret, b"0123456789abcdef").unwrap();
    std::fs::write(tree.join("visible.txt"), b"hi").unwrap();
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::File::open(&secret).is_ok() {
        // Privileged process: nothing here is unreadable, so nothing to prove.
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        return;
    }

    let before_path = dir.join("before.json");
    let after_path = dir.join("after.json");
    Snapshot::capture(&tree).unwrap().save(&before_path).unwrap();
    Snapshot::capture(&tree).unwrap().save(&after_path).unwrap();
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();

    // The manifest listed the file and admits it never hashed it...
    let saved = rea_offline::json::parse(&std::fs::read_to_string(&before_path).unwrap()).unwrap();
    assert_eq!(saved.get("complete"), Some(&Value::Bool(false)), "{saved:?}");
    // ...and the diff does not call it unchanged.
    let diff = rea_offline::app::mode_diff(&before_path, &after_path).unwrap();
    let unverified = format!("{:?}", diff.get("unverified"));
    assert!(unverified.contains("secret.bin"), "{unverified}");

    let coverage = diff.get("coverage").expect("coverage record");
    assert_eq!(coverage.get("complete"), Some(&Value::Bool(false)), "{coverage:?}");
    let count = coverage.get("unverified_count");
    match count {
        Some(Value::Number(n)) if *n >= 1.0 => {}
        other => panic!("unverified_count counts what could not be compared: {other:?}"),
    }

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
    // Exit 3 is not a crash of the tool — it is the installer reporting that
    // it did not finish, so the run is not complete evidence of an install.
    let coverage = report.get("coverage").expect("coverage block");
    assert_eq!(coverage.get("complete"), Some(&rea_offline::json::Value::Bool(false)),
        "an installer that failed must not look like a completed run: {coverage:?}");
    let issues = match coverage.get("issues") {
        Some(rea_offline::json::Value::Array(items)) => items.clone(),
        other => panic!("issues array expected, got {other:?}"),
    };
    assert!(issues.iter().any(|issue| {
        issue.get("area").and_then(|v| v.as_str()) == Some("installer execution")
            && issue.get("stage").and_then(|v| v.as_str()) == Some("exit")
    }), "the failed run must be named: {issues:?}");
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

#[cfg(unix)]
#[test]
fn external_rea_large_json_is_merged_without_pipe_deadlock() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tmp_dir("rea-large");
    let target = dir.join("sample.txt");
    std::fs::write(&target, b"CreateRemoteThread").unwrap();
    // A fake REA that emits well over a pipe buffer of JSON on stdout and
    // diagnostics on stderr. The bridge must drain both while the child runs.
    let rea = dir.join("large-rea.sh");
    std::fs::write(
        &rea,
        "#!/bin/sh\nprintf '{\"note\":\"'\nhead -c 200000 /dev/zero | tr '\\0' x\nprintf '\"}'\nprintf 'diagnostic noise\\n' >&2\n",
    )
    .unwrap();
    std::fs::set_permissions(&rea, std::fs::Permissions::from_mode(0o755)).unwrap();
    let bridge = ReaBridge::new(ReaConfig {
        rea_path: Some(rea),
        timeout: Some(std::time::Duration::from_secs(30)),
    });
    let report = bridge.analyze(&target).unwrap();
    assert!(report.scan_issues.is_empty(), "{:?}", report.scan_issues);
    assert!(report.external_json.is_some());
    assert_eq!(report.files.len(), 1);
    assert!(report.files[0].indicators.iter().any(|i| i.category == "injection"));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A PE that trips the injection/packing/hardening rules — the payload an
/// installer drops behind the user's back, not the installer itself.
fn hostile_payload() -> Vec<u8> {
    use rea_offline::testutil::{Import, PeBuilder};
    let mut bytes = PeBuilder::new()
        .signed(false)
        .dll_characteristics(0x0100) // NX only: no ASLR, no CFG
        .sections(vec![
            (".text".to_string(), 0x200, 0x200, 0x6000_0020),
            ("UPX1".to_string(), 0x1000, 0x200, 0xE000_0020), // exec + write
        ])
        .imports(
            "KERNEL32.dll",
            vec![
                Import::Named("VirtualAllocEx"),
                Import::Named("WriteProcessMemory"),
                Import::Named("CreateRemoteThread"),
                Import::Named("IsDebuggerPresent"),
            ],
        )
        .overlay(8192)
        .build();
    bytes.extend_from_slice(b"http://example.invalid/gate.php\x00powershell -enc AAAA\x00");
    bytes
}

#[cfg(unix)]
#[test]
fn a_payload_dropped_outside_the_install_tree_decides_the_verdict() {
    use rea_offline::app::{mode_sandbox, SandboxOptions};
    use rea_offline::universal_sandbox::SandboxConfig;
    use std::os::unix::fs::PermissionsExt;

    let dir = tmp_dir("drop-verdict");
    let payload = dir.join("payload.bin");
    std::fs::write(&payload, hostile_payload()).unwrap();
    // Nothing is written into install\ — the whole payload lands in the
    // redirected profile, which the install-tree analysis never sees.
    let script = dir.join("dropper.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nmkdir -p \"$REASANDBOX/AppData/Roaming\"\ncp '{}' \"$REASANDBOX/AppData/Roaming/payload.exe\"\n",
            payload.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

    let report = mode_sandbox(SandboxOptions {
        installer: script,
        installer_args: vec![],
        rea_path: None,
        sandbox: SandboxConfig::default(),
    })
    .unwrap();

    let number = |v: Option<&rea_offline::json::Value>| match v {
        Some(rea_offline::json::Value::Number(n)) => *n as u64,
        other => panic!("expected a number, got {other:?}"),
    };
    let text_of = |v: Option<&rea_offline::json::Value>| v.and_then(|x| x.as_str()).unwrap_or("").to_string();

    // The install tree really is empty: the old verdict would have been low.
    let install = report.get("report").expect("install-tree body");
    assert_eq!(number(install.get("file_count")), 0);
    assert_eq!(text_of(install.get("verdict")), "low");

    // The drop was analyzed, with a sandbox-relative path.
    let drops = report.get("drops_report").expect("drops_report");
    assert_eq!(number(drops.get("file_count")), 1);
    let files = match drops.get("files") {
        Some(rea_offline::json::Value::Array(items)) => items,
        other => panic!("files array expected, got {other:?}"),
    };
    assert_eq!(text_of(files[0].get("path")), "AppData/Roaming/payload.exe");
    assert_eq!(text_of(files[0].get("format")), "PE");
    assert_eq!(files[0].get("sha256").and_then(|v| v.as_str()).map(str::len), Some(64));

    // The envelope carries the worst part, and says where it came from.
    let score = number(report.get("risk_score"));
    assert!(score >= 70, "dropped implant must score critical, got {score}");
    assert_eq!(text_of(report.get("verdict")), "critical");
    let sources = report.get("verdict_sources").expect("verdict_sources");
    assert_eq!(text_of(sources.get("drops").and_then(|s| s.get("verdict"))), "critical");
    assert_eq!(text_of(sources.get("install_tree").and_then(|s| s.get("verdict"))), "low");
    assert_eq!(number(sources.get("drops").and_then(|s| s.get("risk_score"))), score);

    // The archive is self-consistent, and every human format keeps the decision.
    rea_offline::report::validate(&report).expect("sandbox envelope must validate");
    let text = rea_offline::render::summary_text(&report);
    assert!(text.contains("overall verdict"), "{text}");
    assert!(text.contains("CRITICAL"), "{text}");
    assert!(text.contains("Dropped-file findings"), "{text}");
    assert!(text.contains("PE140"), "{text}");
    let md = rea_offline::render::to_markdown(&report);
    assert!(md.contains("## Dropped-file analysis"), "{md}");
    assert!(md.contains("AppData/Roaming/payload.exe"), "{md}");

    // The window shows the same evidence and the same number.
    let page = rea_offline::gui::Page::new(report.clone(), "sandbox");
    assert_eq!(page.score(), score);
    assert_eq!(page.verdict(), "critical");
    let details = rea_offline::gui::tree::details_text(&page.tree, "AppData/Roaming/payload.exe");
    assert!(details.contains("PE140"), "{details}");
    let html = rea_offline::gui::page_html(&page, "");
    assert!(html.contains("chip verdict-critical"), "verdict chip");
    assert!(html.contains("payload.exe"), "the drop must be visible in the grid");

    std::fs::remove_dir_all(&dir).unwrap();
}

/// The report has to say what the sandbox could not hold, because nothing in
/// a file tree can: an elevated installer writes where the snapshot never
/// looks, and an unmounted hive leaves registry persistence unrecorded.
#[cfg(unix)]
#[test]
fn a_run_records_what_the_sandbox_could_not_contain() {
    use rea_offline::app::{mode_sandbox, SandboxOptions};
    use rea_offline::json::Value;
    use rea_offline::universal_sandbox::SandboxConfig;
    use std::os::unix::fs::PermissionsExt;

    let dir = tmp_dir("containment");
    let script = dir.join("installer.sh");
    std::fs::write(&script, "#!/bin/sh\nprintf 'MZ' > \"$REASANDBOX_INSTALL/app.exe\"\n").unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let elevated = rea_offline::containment::elevation();

    let report = mode_sandbox(SandboxOptions {
        installer: script,
        installer_args: vec![],
        rea_path: None,
        sandbox: SandboxConfig::default(),
    })
    .unwrap();

    let containment = report.get("containment").expect("containment block");
    assert_eq!(containment.get("elevated").and_then(Value::as_bool), elevated,
        "the block states this run's privileges: {containment:?}");
    // POSIX has no registry to redirect, and must not claim one was captured.
    assert_eq!(
        containment.get("registry").and_then(|r| r.get("status")).and_then(Value::as_str),
        Some("not-applicable")
    );
    let limits = match containment.get("limits") {
        Some(Value::Array(items)) => items.clone(),
        other => panic!("limits array expected, got {other:?}"),
    };
    assert!(!limits.is_empty(), "the method's standing limits travel with the report");

    // An unprivileged run stays quiet; a privileged one says so, and the
    // coverage record agrees with it either way.
    let coverage = report.get("coverage").expect("coverage block");
    let issues = match coverage.get("issues") {
        Some(Value::Array(items)) => items.clone(),
        other => panic!("issues array expected, got {other:?}"),
    };
    let contained_issues: Vec<_> = issues
        .iter()
        .filter(|i| i.get("area").and_then(Value::as_str) == Some("containment"))
        .collect();
    if elevated == Some(true) {
        assert!(!contained_issues.is_empty(),
            "a privileged run must say what it could not contain: {issues:?}");
        assert_eq!(coverage.get("complete"), Some(&Value::Bool(false)), "{coverage:?}");
    } else {
        assert!(contained_issues.is_empty(), "an unprivileged run is not a coverage gap: {issues:?}");
        assert_eq!(coverage.get("complete"), Some(&Value::Bool(true)), "{coverage:?}");
    }

    // Every surface states the same facts, and the archive validates.
    let text = rea_offline::render::summary_text(&report);
    assert!(text.contains("ran elevated"), "{text}");
    assert!(text.contains("registry hive"), "{text}");
    let md = rea_offline::render::to_markdown(&report);
    assert!(md.contains("## Containment & cleanup"), "{md}");
    assert!(md.contains("not visible to this method"), "{md}");
    let html = rea_offline::gui::page_html(
        &rea_offline::gui::Page::new(report.clone(), "sandbox"), "");
    assert!(html.contains("ran elevated"), "the window must say so too");
    rea_offline::report::validate(&report).unwrap();

    std::fs::remove_dir_all(&dir).unwrap();
}

/// A dropper that deletes itself is the realistic version of this gap: the
/// one artifact the report most needs is gone, and "we could not read it" is
/// not the same as "it was clean".
#[cfg(unix)]
#[test]
fn an_installer_that_erases_itself_leaves_a_hole_in_the_record() {
    use rea_offline::app::{mode_sandbox, SandboxOptions};
    use rea_offline::json::Value;
    use rea_offline::universal_sandbox::SandboxConfig;
    use std::os::unix::fs::PermissionsExt;

    let dir = tmp_dir("self-delete");
    let script = dir.join("dropper.sh");
    std::fs::write(
        &script,
        "#!/bin/sh\nprintf 'MZ' > \"$REASANDBOX_INSTALL/app.exe\"\nrm -f \"$0\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

    let report = mode_sandbox(SandboxOptions {
        installer: script.clone(),
        installer_args: vec![],
        rea_path: None,
        sandbox: SandboxConfig::default(),
    })
    .unwrap();

    // The installer is really gone: the analysis had nothing to read.
    assert!(!script.exists(), "the fixture must actually self-delete");
    assert!(report.get("installer_error").and_then(Value::as_str).is_some(),
        "a failed installer analysis must be recorded: {}", report.to_string_pretty());
    assert_eq!(report.get("installer_report"), Some(&Value::Null));
    // ...and its part of the verdict is absent rather than counted as zero.
    let sources = report.get("verdict_sources").expect("verdict_sources");
    assert_eq!(sources.get("installer"), Some(&Value::Null));

    // What was still analyzable is still reported — the install tree is here.
    let text = report.to_string_pretty();
    assert!(text.contains("app.exe"), "the drop is still evidence:\n{text}");

    // The hole is in the coverage record, not just in a free-text field.
    let coverage = report.get("coverage").expect("coverage block");
    assert_eq!(coverage.get("complete"), Some(&Value::Bool(false)),
        "a missing evidence set must not look like a clean run: {}", coverage.to_string_pretty());
    let issues = match coverage.get("issues") {
        Some(Value::Array(items)) => items.clone(),
        other => panic!("issues array expected, got {other:?}"),
    };
    assert!(issues.iter().any(|i| {
        i.get("area").and_then(Value::as_str) == Some("installer analysis")
            && i.get("stage").and_then(Value::as_str) == Some("analysis")
    }), "the missing installer must be named: {issues:?}");

    let rendered = rea_offline::render::summary_text(&report);
    assert!(rendered.contains("coverage: INCOMPLETE"), "{rendered}");
    assert!(rendered.contains("installer analysis"), "{rendered}");
    assert!(rea_offline::render::to_markdown(&report).contains("## Installer analysis"));

    // Self-consistent, and not editable into a clean-looking report.
    rea_offline::report::validate(&report).unwrap();
    let mut tampered = report.clone();
    if let Value::Object(map) = &mut tampered {
        map.insert("coverage".into(), Value::obj(vec![
            ("complete", Value::Bool(true)),
            ("issue_count", Value::num(0)),
            ("unverified_count", Value::num(0)),
            ("issues", Value::Array(Vec::new())),
        ]));
    }
    let error = rea_offline::report::validate(&tampered).unwrap_err().to_string();
    assert!(error.contains("records a failure"), "{error}");

    std::fs::remove_dir_all(&dir).unwrap();
}

/// An installer killed at the timeout has only performed *part* of its
/// install. What it dropped is still evidence — but it is not evidence of a
/// complete run, and a clean-looking delta must not be read as one.
#[cfg(unix)]
#[test]
fn an_installer_killed_at_the_timeout_makes_the_run_incomplete() {
    use rea_offline::app::{mode_sandbox, SandboxOptions};
    use rea_offline::json::Value;
    use rea_offline::universal_sandbox::SandboxConfig;
    use std::os::unix::fs::PermissionsExt;

    let dir = tmp_dir("timeout");
    let script = dir.join("slow_installer.sh");
    // Writes a decoy payload and then stalls: what a hung or deliberately
    // slow installer looks like from inside the sandbox.
    std::fs::write(
        &script,
        "#!/bin/sh\nmkdir -p \"$REASANDBOX_INSTALL\"\nprintf 'MZ half' > \"$REASANDBOX_INSTALL/partial.exe\"\nsleep 30\n",
    ).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

    let report = mode_sandbox(SandboxOptions {
        installer: script,
        installer_args: vec![],
        rea_path: None,
        sandbox: SandboxConfig { timeout: std::time::Duration::from_secs(1), ..Default::default() },
    }).unwrap();

    // The half-installed tree is still reported: partial evidence is not
    // discarded, it is labelled.
    let text = report.to_string_pretty();
    assert!(text.contains("partial.exe"), "the partial install is still evidence:\n{text}");
    assert_eq!(report.get("execution").and_then(|e| e.get("timed_out")), Some(&Value::Bool(true)));

    // ...but the run is not complete, and the record says which phase said so.
    let coverage = report.get("coverage").expect("coverage block");
    assert_eq!(coverage.get("complete"), Some(&Value::Bool(false)),
        "a killed installer must not look like a clean run: {}", coverage.to_string_pretty());
    let issues = match coverage.get("issues") {
        Some(Value::Array(items)) => items.clone(),
        other => panic!("issues array expected, got {other:?}"),
    };
    assert!(issues.iter().any(|i| {
        i.get("area").and_then(Value::as_str) == Some("installer execution")
            && i.get("stage").and_then(Value::as_str) == Some("timeout")
    }), "the killed run must be named: {issues:?}");

    let rendered = rea_offline::render::summary_text(&report);
    assert!(rendered.contains("coverage: INCOMPLETE"), "{rendered}");
    assert!(rendered.contains("installer execution"), "{rendered}");
    let md = rea_offline::render::to_markdown(&report);
    assert!(md.contains("## Coverage warnings"), "{md}");
    let html = rea_offline::gui::page_html(
        &rea_offline::gui::Page::new(report.clone(), "sandbox"), "");
    assert!(html.contains("coverage-incomplete"), "the window must flag it too");

    // The archive is self-consistent, and cannot be edited into a
    // clean-looking one: erasing the coverage issues does not help, because
    // the execution block still records that the installer was killed.
    rea_offline::report::validate(&report).unwrap();
    let mut tampered = report.clone();
    if let Value::Object(map) = &mut tampered {
        map.insert("coverage".into(), Value::obj(vec![
            ("complete", Value::Bool(true)),
            ("issue_count", Value::num(0)),
            ("unverified_count", Value::num(0)),
            ("issues", Value::Array(Vec::new())),
        ]));
    }
    let error = rea_offline::report::validate(&tampered).unwrap_err().to_string();
    assert!(error.contains("did not finish"), "{error}");

    std::fs::remove_dir_all(&dir).unwrap();
}

/// A drop the snapshot was not allowed to read must not produce a calm,
/// complete-looking report. This is the same class of bug as the v0.6.0
/// verdict gap: the tool claiming confidence it has not earned.
#[cfg(unix)]
#[test]
fn an_unreadable_drop_makes_the_run_incomplete_not_clean() {
    use rea_offline::app::{mode_sandbox, SandboxOptions};
    use rea_offline::json::Value;
    use rea_offline::universal_sandbox::SandboxConfig;
    use std::os::unix::fs::PermissionsExt;

    let dir = tmp_dir("blind-drop");
    let root = dir.join("sandbox");
    let payload = dir.join("payload.bin");
    std::fs::write(&payload, hostile_payload()).unwrap();
    // The installer hides its payload in a directory it then locks. The
    // payload never enters the install tree and cannot be read afterwards.
    let script = dir.join("dropper.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nmkdir -p \"$REASANDBOX/AppData/hidden\"\ncp '{}' \"$REASANDBOX/AppData/hidden/payload.exe\"\nchmod 000 \"$REASANDBOX/AppData/hidden\"\n",
            payload.display()
        ),
    ).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

    let report = mode_sandbox(SandboxOptions {
        installer: script,
        installer_args: vec![],
        rea_path: None,
        sandbox: SandboxConfig { root: Some(root.clone()), keep: true, ..Default::default() },
    }).unwrap();

    // Restore access so the tree can be cleaned up even if assertions fail.
    let hidden = root.join("AppData/hidden");
    let privileged = hidden.exists() && std::fs::read_dir(&hidden).is_ok();
    if hidden.exists() {
        let _ = std::fs::set_permissions(&hidden, std::fs::Permissions::from_mode(0o700));
    }
    let cleanup = || { let _ = std::fs::remove_dir_all(&dir); };
    if privileged {
        cleanup();
        return; // running with privilege that ignores mode bits
    }

    let coverage = report.get("coverage").expect("coverage block");
    assert_eq!(coverage.get("complete"), Some(&Value::Bool(false)),
        "a drop that could not be read must not look like a clean run: {}", coverage.to_string_pretty());
    let issues = match coverage.get("issues") {
        Some(Value::Array(items)) => items.clone(),
        other => panic!("issues array expected, got {other:?}"),
    };
    assert!(issues.iter().any(|i| {
        i.get("stage").and_then(Value::as_str) == Some("traverse")
            && i.get("path").and_then(Value::as_str).unwrap_or("").contains("AppData/hidden")
    }), "the locked directory must be named: {issues:?}");
    assert!(issues.iter().any(|i| i.get("area").and_then(Value::as_str) == Some("sandbox snapshot (after)")),
        "coverage says which phase went blind: {issues:?}");

    // The verdict stays honest about what was analyzed (nothing readable),
    // and the coverage record is what stops this being read as "clean".
    let text = rea_offline::render::summary_text(&report);
    assert!(text.contains("coverage: INCOMPLETE"), "{text}");
    assert!(text.contains("AppData/hidden"), "{text}");
    let md = rea_offline::render::to_markdown(&report);
    assert!(md.contains("## Coverage warnings"), "{md}");
    assert!(md.contains("sandbox snapshot (after)"), "{md}");
    let page = rea_offline::gui::Page::new(report.clone(), "sandbox");
    let html = rea_offline::gui::page_html(&page, "");
    assert!(html.contains("coverage-incomplete"), "the window must flag it too");

    // The archive is internally consistent, and cannot be edited into a
    // clean-looking one by flipping a single boolean.
    rea_offline::report::validate(&report).unwrap();
    let mut tampered = report.clone();
    if let Value::Object(map) = &mut tampered {
        map.insert("coverage".into(), Value::obj(vec![
            ("complete", Value::Bool(true)),
            ("issue_count", Value::num(issues.len() as u64)),
            ("issues", Value::Array(issues)),
        ]));
    }
    let error = rea_offline::report::validate(&tampered).unwrap_err().to_string();
    assert!(error.contains("claims to be complete"), "{error}");

    cleanup();
}
