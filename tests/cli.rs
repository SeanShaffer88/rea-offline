//! CLI-level tests: run the built binary the way an operator does.
//!
//! These are the tests that would have caught an argument renamed in the
//! library but not in the CLI, a format flag that prints nothing, or a
//! `--fail-on` gate that never fires.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> PathBuf {
    // Cargo sets CARGO_BIN_EXE_<name> for integration tests.
    PathBuf::from(env!("CARGO_BIN_EXE_rea-offline"))
}

fn workdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rea_offline_cli_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run(dir: &Path, args: &[&str]) -> Run {
    let output = Command::new(bin())
        .args(args)
        .current_dir(dir)
        .output()
        .expect("failed to run rea-offline");
    Run {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

#[test]
fn help_and_version_do_not_need_arguments() {
    let dir = workdir("help");
    let help = run(&dir, &["--help"]);
    assert_eq!(help.code, 0);
    assert!(help.stdout.contains("USAGE:"));
    assert!(help.stdout.contains("--fail-on"));

    let version = run(&dir, &["--version"]);
    assert_eq!(version.code, 0);
    assert!(version.stdout.contains(env!("CARGO_PKG_VERSION")));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn scan_sample_reports_hashes_and_verdict() {
    let dir = workdir("scan");
    let sample = dir.join("sample.exe");
    assert_eq!(run(&dir, &["sample", sample.to_str().unwrap()]).code, 0);

    let scan = run(&dir, &["scan", "sample.exe"]);
    assert_eq!(scan.code, 0, "stderr: {}", scan.stderr);
    let json = rea_offline::json::parse(&scan.stdout).expect("stdout must be JSON");
    assert_eq!(json.get("mode").and_then(|m| m.as_str()), Some("local-scan"));
    assert_eq!(
        json.get("schema_version").and_then(|v| match v {
            rea_offline::json::Value::Number(n) => Some(*n as u64),
            _ => None,
        }),
        Some(rea_offline::SCHEMA_VERSION)
    );
    let report = json.get("report").expect("report block");
    let files = report.get("files").expect("files");
    let text = format!("{files:?}");
    assert!(text.contains("sha256"), "hashes present");
    assert!(text.contains("imphash"), "imphash present for a PE sample");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn formats_render_the_same_decision() {
    let dir = workdir("formats");
    let sample = dir.join("sample.exe");
    run(&dir, &["sample", sample.to_str().unwrap()]);

    let json = run(&dir, &["scan", "sample.exe", "--format", "json"]);
    let text = run(&dir, &["scan", "sample.exe", "--format", "text"]);
    let md = run(&dir, &["scan", "sample.exe", "--format", "markdown"]);
    assert_eq!(text.code, 0, "{}", text.stderr);
    assert!(text.stdout.contains("risk score"), "{}", text.stdout);
    assert!(md.stdout.starts_with("# rea-offline inspection report"), "{}", md.stdout);

    // Every format must agree on the verdict.
    let parsed = rea_offline::json::parse(&json.stdout).unwrap();
    let verdict = parsed.get("verdict").and_then(|v| v.as_str()).unwrap().to_uppercase();
    assert!(text.stdout.contains(&verdict), "text output lost the verdict");
    assert!(md.stdout.to_lowercase().contains(&verdict.to_lowercase()));

    assert!(run(&dir, &["scan", "sample.exe", "--format", "yaml"]).code != 0);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn output_flag_writes_file_and_keeps_stdout_clean() {
    let dir = workdir("output");
    let sample = dir.join("sample.exe");
    run(&dir, &["sample", sample.to_str().unwrap()]);
    let out = dir.join("report.json");
    let result = run(
        &dir,
        &["scan", "sample.exe", "--output", "report.json", "--format", "markdown"],
    );
    assert_eq!(result.code, 0, "{}", result.stderr);
    assert!(result.stdout.is_empty(), "stdout should be empty: {}", result.stdout);
    let written = std::fs::read_to_string(&out).unwrap();
    assert!(written.starts_with("# rea-offline inspection report"));

    let quiet = run(&dir, &["scan", "sample.exe", "--output", "r2.json", "--quiet"]);
    assert!(quiet.stderr.is_empty(), "--quiet must silence the notice: {}", quiet.stderr);
    assert!(dir.join("r2.json").exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn fail_on_gates_the_exit_code() {
    let dir = workdir("gate");
    let sample = dir.join("sample.exe");
    run(&dir, &["sample", sample.to_str().unwrap()]);

    // The demo sample has network capability strings but no injection set,
    // so its verdict is at most "medium".
    let strict = run(&dir, &["scan", "sample.exe", "--fail-on", "critical", "--quiet"]);
    assert_eq!(strict.code, 0, "critic threshold must not fire: {}", strict.stderr);
    let loose = run(&dir, &["scan", "sample.exe", "--fail-on", "low", "--quiet"]);
    assert_eq!(loose.code, 2, "low threshold must fire: {}", loose.stderr);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn sample_kinds_and_errors() {
    let dir = workdir("sample");
    assert_eq!(run(&dir, &["sample", "s.ps1", "--kind", "script"]).code, 0);
    let script = run(&dir, &["scan", "s.ps1", "--format", "text"]);
    assert_eq!(script.code, 0);
    // The text report spells severity in words rather than printing rule
    // titles verbatim, so assert on the decision, not on one phrasing.
    assert!(script.stdout.contains("risk score"), "{}", script.stdout);
    assert!(script.stdout.contains("STR001") || script.stdout.contains("Capability"),
            "capability findings must reach the text report: {}", script.stdout);
    assert_ne!(run(&dir, &["sample", "x.exe", "--kind", "elf"]).code, 0);

    let missing = run(&dir, &["scan", "definitely-not-here.exe"]);
    assert_ne!(missing.code, 0);
    assert!(missing.stderr.contains("not found"), "{}", missing.stderr);

    let unknown = run(&dir, &["frobnicate"]);
    assert_ne!(unknown.code, 0);
    assert!(unknown.stderr.contains("unknown command"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn gui_renders_a_window_and_can_reopen_a_report() {
    let dir = workdir("gui");
    let sample = dir.join("sample.exe");
    run(&dir, &["sample", sample.to_str().unwrap()]);

    // Static page (no server, no browser needed).
    let page = run(&dir, &["gui", ".", "--output", "window.html", "--no-open"]);
    assert_eq!(page.code, 0, "{}", page.stderr);
    let html = std::fs::read_to_string(dir.join("window.html")).unwrap();
    assert!(html.starts_with("<!doctype html>"));
    assert!(html.contains("<svg"), "treemap present");
    assert!(html.contains("sample.exe"), "grid lists the analyzed file");
    assert!(html.contains("risk score"), "footer carries the summary");
    assert!(html.contains("chip verdict-"), "verdict chip present");
    assert!(!html.contains("<script"), "no JavaScript by design");

    // Reopening an archived report must produce the same window.
    let scan = run(&dir, &["scan", ".", "--output", "archived.json", "--quiet"]);
    assert_eq!(scan.code, 0, "{}", scan.stderr);
    let reopened = run(
        &dir,
        &["gui", "archived.json", "--from-report", "--output", "reopened.html", "--no-open"],
    );
    assert_eq!(reopened.code, 0, "{}", reopened.stderr);
    let again = std::fs::read_to_string(dir.join("reopened.html")).unwrap();
    assert!(again.contains("sample.exe"));
    assert!(again.contains("<svg"));

    // A filter in the URL survives into the rendered page.
    let page = rea_offline::gui::page_from_report_file(&dir.join("archived.json")).unwrap();
    let filtered = rea_offline::gui::page_html(&page, "filter=sample&hide_clean=1");
    assert!(filtered.contains("filter=sample"), "state round-trips into links");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn doctor_reports_a_working_build() {
    let dir = workdir("doctor");
    let doctor = run(&dir, &["doctor"]);
    assert_eq!(doctor.code, 0, "{}", doctor.stderr);
    let json = rea_offline::json::parse(&doctor.stdout).unwrap();
    assert_eq!(json.get("mode").and_then(|v| v.as_str()), Some("doctor"));
    let hashes = json.get("hashes").expect("hash self-test block");
    assert_eq!(
        hashes.get("sha256_selftest"),
        Some(&rea_offline::json::Value::Bool(true))
    );
    assert_eq!(
        hashes.get("md5_selftest"),
        Some(&rea_offline::json::Value::Bool(true))
    );
    // An air-gapped operator can prove this build's imphash still agrees with
    // pefile/VirusTotal without sending a sample anywhere.
    assert_eq!(
        hashes.get("imphash_selftest"),
        Some(&rea_offline::json::Value::Bool(true))
    );
    assert_eq!(
        json.get("sandbox_rehearsal_ok"),
        Some(&rea_offline::json::Value::Bool(true))
    );

    let md = run(&dir, &["doctor", "--format", "markdown"]);
    assert!(md.stdout.starts_with("# rea-offline doctor"), "{}", md.stdout);
    assert!(md.stdout.contains("| imphash self-test (pefile) | yes |"), "{}", md.stdout);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn snapshot_and_diff_round_trip() {
    let dir = workdir("snap");
    let target = dir.join("tree");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join("a.txt"), b"one").unwrap();
    assert_eq!(
        run(&dir, &["snapshot", "tree", "--output", "before.json", "--quiet"]).code,
        0
    );
    std::fs::write(target.join("b.txt"), b"two").unwrap();
    assert_eq!(
        run(&dir, &["snapshot", "tree", "--output", "after.json", "--quiet"]).code,
        0
    );
    let diff = run(&dir, &["diff", "before.json", "after.json"]);
    assert_eq!(diff.code, 0, "{}", diff.stderr);
    let json = rea_offline::json::parse(&diff.stdout).unwrap();
    let added = format!("{:?}", json.get("added"));
    assert!(added.contains("b.txt"), "{added}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn purge_refuses_arbitrary_directories() {
    let dir = workdir("purge");
    let victim = dir.join("important");
    std::fs::create_dir_all(&victim).unwrap();
    let refused = run(&dir, &["purge", "important"]);
    assert_ne!(refused.code, 0);
    assert!(refused.stderr.contains("refused"), "{}", refused.stderr);
    assert!(victim.exists(), "guard must not delete anything");

    let sandbox = dir.join(format!("rea_sandbox_{}", std::process::id()));
    std::fs::create_dir_all(sandbox.join("install")).unwrap();
    let purged = run(&dir, &["purge", sandbox.to_str().unwrap()]);
    assert_eq!(purged.code, 0, "{}", purged.stderr);
    let json = rea_offline::json::parse(&purged.stdout).unwrap();
    assert_eq!(json.get("verified_zero_residue"), Some(&rea_offline::json::Value::Bool(true)));
    assert!(!sandbox.exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn report_command_reopens_archives_without_rescanning_and_gates_them() {
    let dir = workdir("report");
    let sample = dir.join("sample.exe");
    assert_eq!(run(&dir, &["sample", sample.to_str().unwrap()]).code, 0);
    let archived = dir.join("archived.json");
    assert_eq!(run(&dir, &["scan", "sample.exe", "--output", "archived.json", "--quiet"]).code, 0);
    let before = std::fs::read_to_string(&archived).unwrap();
    let original = rea_offline::json::parse(&before).unwrap();
    std::fs::remove_file(&sample).unwrap();

    let json = run(&dir, &["report", "archived.json"]);
    assert_eq!(json.code, 0, "{}", json.stderr);
    assert_eq!(rea_offline::json::parse(&json.stdout).unwrap(), original);
    let text = run(&dir, &["report", "archived.json", "--format", "text"]);
    assert_eq!(text.code, 0, "{}", text.stderr);
    assert!(text.stdout.contains("risk score"), "{}", text.stdout);
    let md = run(&dir, &["report", "archived.json", "--format", "markdown", "--output", "report.md", "--quiet"]);
    assert_eq!(md.code, 0, "{}", md.stderr);
    assert!(std::fs::read_to_string(dir.join("report.md")).unwrap().starts_with("# rea-offline inspection report"));
    assert_eq!(run(&dir, &["report", "archived.json", "--fail-on", "low", "--quiet"]).code, 2);
    assert_eq!(run(&dir, &["report", "archived.json", "--fail-on", "critical", "--quiet"]).code, 0);
    assert_eq!(std::fs::read_to_string(&archived).unwrap(), before, "archive must not be rewritten");

    let invalid = dir.join("invalid.json");
    std::fs::write(&invalid, r#"{"verdict":"low"}"#).unwrap();
    let rejected = run(&dir, &["report", "invalid.json", "--fail-on", "low"]);
    assert_eq!(rejected.code, 1, "invalid evidence must not pass a gate: {}", rejected.stderr);
    assert!(rejected.stderr.contains("invalid report"), "{}", rejected.stderr);
    let gui = run(&dir, &["gui", "invalid.json", "--from-report", "--output", "bad.html", "--no-open"]);
    assert_ne!(gui.code, 0);
    assert!(!dir.join("bad.html").exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn cli_rejects_mistyped_and_misplaced_options_before_doing_work() {
    let dir = workdir("args");
    let sample = dir.join("sample.exe");
    assert_eq!(run(&dir, &["sample", sample.to_str().unwrap()]).code, 0);
    for args in [
        vec!["scan", "sample.exe", "--outpt", "report.json"],
        vec!["scan", "sample.exe", "--output"],
        vec!["scan", "sample.exe", "--output", "--quiet"],
        vec!["scan", "sample.exe", "--quiet=false"],
        vec!["scan", "sample.exe", "--port", "9000"],
        vec!["scan", "sample.exe", "--output", "a.json", "--output", "b.json"],
        vec!["scan", "sample.exe", "extra.exe"],
        vec!["doctor", "extra"],
        vec!["diff", "only-one.json"],
        vec!["report", "missing.json", "--rea", "rea.exe"],
        vec!["sandbox", "sample.exe", "--memory-mb", "0"],
        vec!["gui", "sample.exe", "--port", "0", "--no-open"],
    ] {
        let result = run(&dir, &args);
        assert_eq!(result.code, 1, "accepted {args:?}: {}", result.stdout);
        assert!(result.stderr.contains("invalid input"), "{}", result.stderr);
    }
    assert!(!dir.join("report.json").exists());
    assert!(!dir.join("a.json").exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[cfg(unix)]
#[test]
fn unreadable_files_are_visible_as_coverage_issues_in_every_format() {
    use std::os::unix::fs::PermissionsExt;
    let dir = workdir("coverage");
    let target = dir.join("tree");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join("readable.txt"), b"visible").unwrap();
    let locked = target.join("locked.bin");
    std::fs::write(&locked, b"hidden").unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();

    let result = run(&dir, &["scan", "tree"]);
    assert_eq!(result.code, 0, "{}", result.stderr);
    let json = rea_offline::json::parse(&result.stdout).unwrap();
    let report = json.get("report").unwrap();
    let issues = format!("{:?}", report.get("scan_issues"));
    assert!(issues.contains("locked.bin"), "{issues}");
    assert_eq!(report.get("file_count"), Some(&rea_offline::json::Value::num(1)));
    assert_eq!(report.get("summary").and_then(|s| s.get("complete")), Some(&rea_offline::json::Value::Bool(false)));
    let text = run(&dir, &["scan", "tree", "--format", "text"]);
    assert!(text.stdout.contains("coverage: INCOMPLETE"), "{}", text.stdout);
    assert!(text.stdout.contains("locked.bin"), "{}", text.stdout);
    let md = run(&dir, &["scan", "tree", "--format", "markdown"]);
    assert!(md.stdout.contains("## Coverage warnings"), "{}", md.stdout);
    assert!(md.stdout.contains("locked.bin"), "{}", md.stdout);
    let gui = run(&dir, &["gui", "tree", "--output", "window.html", "--no-open"]);
    assert_eq!(gui.code, 0, "{}", gui.stderr);
    let html = std::fs::read_to_string(dir.join("window.html")).unwrap();
    assert!(html.contains("coverage: INCOMPLETE"), "GUI must disclose incomplete coverage");
    assert!(html.contains("chip coverage-incomplete"), "coverage chip stays visible regardless of selection");

    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// An archived sandbox run whose install tree is clean but whose profile
/// drop is critical. Written by hand so the gate/GUI/render path is covered
/// on Windows too, where the POSIX dropper fixture cannot run.
const SANDBOX_ARCHIVE: &str = r#"{
  "schema_version": 3,
  "mode": "sandbox-installer",
  "generated_unix": 1700000000,
  "verdict": "critical",
  "risk_score": 94,
  "verdict_sources": {
    "installer": {"risk_score": 6, "verdict": "low"},
    "install_tree": {"risk_score": 0, "verdict": "low"},
    "drops": {"risk_score": 94, "verdict": "critical"}
  },
  "installer": "setup.exe",
  "execution": {"command": "setup.exe", "exit_code": 0, "timed_out": false, "duration_ms": 10},
  "installer_report": {
    "file_count": 1, "risk_score": 6, "verdict": "low", "target": "setup.exe",
    "files": [{"path": "setup.exe", "size": 100, "format": "PE", "sha256": "aa", "md5": "bb"}],
    "rules": {"findings": []}, "scan_issues": []
  },
  "delta": {"added": [], "modified": [], "deleted": []},
  "sandbox_delta": {
    "added": [{"path": "AppData/Roaming/payload.exe", "size": 200, "sha256": "cc"}],
    "modified": [], "deleted": []
  },
  "drops_report": {
    "file_count": 1, "risk_score": 94, "verdict": "critical", "target": "/tmp/rea_sandbox_x",
    "files": [{"path": "AppData/Roaming/payload.exe", "size": 200, "format": "PE", "sha256": "cc", "md5": "dd"}],
    "rules": {"findings": [
      {"rule": "PE140", "title": "Injection API set present", "severity": "high",
       "file": "AppData/Roaming/payload.exe",
       "evidence": "VirtualAllocEx + WriteProcessMemory + CreateRemoteThread"}
    ]},
    "scan_issues": []
  },
  "report": {
    "file_count": 0, "risk_score": 0, "verdict": "low", "target": "/tmp/rea_sandbox_x/install",
    "files": [], "rules": {"findings": []}, "scan_issues": []
  }
}"#;

#[test]
fn archived_sandbox_gates_on_the_combined_verdict_not_the_install_tree() {
    let dir = workdir("sandbox-archive");
    let archive = dir.join("sandbox.json");
    std::fs::write(&archive, SANDBOX_ARCHIVE).unwrap();

    // The install-tree body says "low"; the gate must still fire.
    let gate = run(&dir, &["report", "sandbox.json", "--fail-on", "high", "--quiet"]);
    assert_eq!(gate.code, 2, "combined verdict must gate: {}", gate.stderr);
    let calm = run(&dir, &["report", "sandbox.json", "--fail-on", "critical", "--quiet"]);
    assert_eq!(calm.code, 2, "{}", calm.stderr);

    let text = run(&dir, &["report", "sandbox.json", "--format", "text"]);
    assert_eq!(text.code, 0, "{}", text.stderr);
    assert!(text.stdout.contains("overall verdict"), "{}", text.stdout);
    assert!(text.stdout.contains("CRITICAL"), "{}", text.stdout);
    assert!(text.stdout.contains("Dropped-file findings"), "{}", text.stdout);
    assert!(text.stdout.contains("install tree: 0/100 low"), "{}", text.stdout);

    let md = run(&dir, &["report", "sandbox.json", "--format", "markdown"]);
    assert_eq!(md.code, 0, "{}", md.stderr);
    assert!(md.stdout.contains("| overall verdict | **CRITICAL** |"), "{}", md.stdout);
    assert!(md.stdout.contains("## Dropped-file analysis"), "{}", md.stdout);
    assert!(md.stdout.contains("AppData/Roaming/payload.exe"), "{}", md.stdout);

    // The window merges the three sets and shows the combined score.
    let gui = run(&dir, &["gui", "sandbox.json", "--from-report", "--output", "sandbox.html", "--no-open"]);
    assert_eq!(gui.code, 0, "{}", gui.stderr);
    let html = std::fs::read_to_string(dir.join("sandbox.html")).unwrap();
    assert!(html.contains("chip verdict-critical"), "combined verdict chip");
    assert!(html.contains("94/100"), "combined score, not the install tree's 0");
    assert!(html.contains("payload.exe"), "the drop is in the grid");
    assert!(html.contains("_installer"), "the installer is in the grid too");
    assert!(!html.contains("<script"), "still no JavaScript");

    // An archive rewritten to look calm while its own sources say otherwise
    // is rejected instead of passing a gate.
    let tampered = SANDBOX_ARCHIVE
        .replace("\"verdict\": \"critical\",\n  \"risk_score\": 94", "\"verdict\": \"low\",\n  \"risk_score\": 6");
    assert_ne!(tampered, SANDBOX_ARCHIVE, "fixture must actually be rewritten");
    std::fs::write(dir.join("tampered.json"), tampered).unwrap();
    let rejected = run(&dir, &["report", "tampered.json", "--fail-on", "high", "--quiet"]);
    assert_eq!(rejected.code, 1, "tampered archive must fail closed: {}", rejected.stdout);
    assert!(rejected.stderr.contains("worst analyzed part"), "{}", rejected.stderr);

    std::fs::remove_dir_all(&dir).unwrap();
}

#[cfg(unix)]
#[test]
fn sandbox_gate_fires_on_a_profile_drop() {
    use std::os::unix::fs::PermissionsExt;
    let dir = workdir("sandbox-gate");
    let payload = dir.join("payload.bin");
    let bytes = rea_offline::testutil::PeBuilder::new()
        .dll_characteristics(0x0100)
        .sections(vec![
            (".text".to_string(), 0x200, 0x200, 0x6000_0020),
            ("UPX1".to_string(), 0x1000, 0x200, 0xE000_0020),
        ])
        .imports(
            "KERNEL32.dll",
            vec![
                rea_offline::testutil::Import::Named("VirtualAllocEx"),
                rea_offline::testutil::Import::Named("WriteProcessMemory"),
                rea_offline::testutil::Import::Named("CreateRemoteThread"),
            ],
        )
        .overlay(8192)
        .build();
    std::fs::write(&payload, bytes).unwrap();
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

    let gated = run(&dir, &["sandbox", "dropper.sh", "--fail-on", "high", "--quiet", "--output", "run.json"]);
    assert_eq!(gated.code, 2, "a critical profile drop must fail the gate: {}", gated.stderr);
    let json = rea_offline::json::parse(&std::fs::read_to_string(dir.join("run.json")).unwrap()).unwrap();
    assert_eq!(json.get("verdict").and_then(|v| v.as_str()), Some("critical"));
    assert_eq!(
        json.get("report").and_then(|r| r.get("verdict")).and_then(|v| v.as_str()),
        Some("low"),
        "the install tree stayed empty — the drop is what decided this"
    );
    // The recorded run gates the same way when reopened later.
    let archived = run(&dir, &["report", "run.json", "--fail-on", "high", "--quiet"]);
    assert_eq!(archived.code, 2, "{}", archived.stderr);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// End-to-end through the CLI: an installer that stalls must reach the exit
/// code, not just the JSON. A pipeline cannot read a coverage block; it can
/// read `3`.
#[cfg(unix)]
#[test]
fn a_timed_out_sandbox_run_exits_three() {
    use std::os::unix::fs::PermissionsExt;
    let dir = workdir("sandbox-timeout");
    let script = dir.join("stall.sh");
    std::fs::write(
        &script,
        "#!/bin/sh\nmkdir -p \"$REASANDBOX_INSTALL\"\nprintf 'MZ half' > \"$REASANDBOX_INSTALL/partial.exe\"\nsleep 30\n",
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

    let gated = run(
        &dir,
        &["sandbox", "stall.sh", "--timeout", "1", "--fail-on-incomplete", "--quiet", "--output", "run.json"],
    );
    assert_eq!(gated.code, 3, "a killed run is not complete evidence: {}", gated.stderr);

    // The report is still written, and it says why the run is not complete.
    let json = rea_offline::json::parse(&std::fs::read_to_string(dir.join("run.json")).unwrap()).unwrap();
    assert_eq!(
        json.get("execution").and_then(|e| e.get("timed_out")),
        Some(&rea_offline::json::Value::Bool(true))
    );
    assert_eq!(
        json.get("coverage").and_then(|c| c.get("complete")),
        Some(&rea_offline::json::Value::Bool(false))
    );

    // Without the flag the verdict is unchanged: coverage never adds risk.
    let plain = run(&dir, &["sandbox", "stall.sh", "--timeout", "1", "--quiet", "--output", "plain.json"]);
    assert_eq!(plain.code, 0, "{}", plain.stderr);

    // The recorded run gates the same way when reopened later.
    let archived = run(&dir, &["report", "run.json", "--fail-on-incomplete", "--quiet"]);
    assert_eq!(archived.code, 3, "{}", archived.stderr);

    std::fs::remove_dir_all(&dir).unwrap();
}

/// An archive cannot claim complete coverage for a run its own `execution`
/// block says was killed. Portable: it exercises the validator, not a
/// process, so it runs on Windows too.
#[test]
fn an_archive_cannot_claim_complete_coverage_for_a_run_that_was_killed() {
    let dir = workdir("execution-tamper");
    let path = dir.join("killed.json");
    // Only the two records disagree: the run says it was killed at the
    // timeout, the coverage record says everything was seen. Everything
    // else is left exactly as a real (critical) run would have written it.
    let killed = SANDBOX_ARCHIVE.replace(
        "\"execution\": {\"command\": \"setup.exe\", \"exit_code\": 0, \"timed_out\": false, \"duration_ms\": 10}",
        "\"coverage\": {\"complete\": true, \"issue_count\": 0, \"unverified_count\": 0, \"issues\": []},\n  \
         \"execution\": {\"command\": \"setup.exe\", \"exit_code\": null, \"timed_out\": true, \"duration_ms\": 300000}",
    );
    assert_ne!(killed, SANDBOX_ARCHIVE, "fixture must actually be rewritten");
    std::fs::write(&path, killed).unwrap();

    let rejected = run(&dir, &["report", "killed.json", "--fail-on-incomplete"]);
    assert_eq!(rejected.code, 1, "a contradictory archive must fail closed: {}", rejected.stdout);
    assert!(rejected.stderr.contains("did not finish"), "{}", rejected.stderr);
    // It is refused rather than rendered, in every format.
    let rendered = run(&dir, &["report", "killed.json", "--format", "text"]);
    assert_eq!(rendered.code, 1, "{}", rendered.stdout);

    std::fs::remove_dir_all(&dir).unwrap();
}

/// An archive cannot claim complete coverage for a run it admits was never
/// contained. Portable: it exercises the validator, not a process.
#[test]
fn a_run_that_was_not_contained_cannot_claim_complete_coverage() {
    let dir = workdir("containment-tamper");
    // An elevated run, recorded honestly: coverage must agree that evidence
    // may have escaped the sandbox.
    let honest = r#"{"schema_version":3,"mode":"sandbox-installer","verdict":"low","risk_score":0,
        "coverage":{"complete":false,"issue_count":1,"unverified_count":0,"issues":[
            {"area":"containment","path":"/tmp/rea_sandbox_x","stage":"elevated",
             "message":"ran as root"}]},
        "containment":{"elevated":true,"registry":{"mounted":false,"status":"unavailable",
            "message":"RegLoadKeyW failed"},"limits":[]},
        "execution":{"command":"setup.exe","exit_code":0,"timed_out":false},
        "report":{"file_count":0,"risk_score":0,"verdict":"low","files":[],"scan_issues":[]}}"#;
    std::fs::write(dir.join("honest.json"), honest).unwrap();
    let gated = run(&dir, &["report", "honest.json", "--fail-on-incomplete", "--quiet"]);
    assert_eq!(gated.code, 3, "an uncontained run is incomplete evidence: {}", gated.stderr);

    // The same run with the coverage record quietly flipped: refused, not
    // rendered, and certainly not gated as clean.
    let tampered = honest.replace(
        r#""coverage":{"complete":false,"issue_count":1,"unverified_count":0,"issues":[
            {"area":"containment","path":"/tmp/rea_sandbox_x","stage":"elevated",
             "message":"ran as root"}]}"#,
        r#""coverage":{"complete":true,"issue_count":0,"unverified_count":0,"issues":[]}"#,
    );
    assert_ne!(tampered, honest, "fixture must actually be rewritten");
    std::fs::write(dir.join("tampered.json"), tampered).unwrap();
    let rejected = run(&dir, &["report", "tampered.json", "--fail-on-incomplete"]);
    assert_eq!(rejected.code, 1, "a contradictory archive must fail closed: {}", rejected.stdout);
    assert!(rejected.stderr.contains("not contained"), "{}", rejected.stderr);

    std::fs::remove_dir_all(&dir).unwrap();
}

/// `doctor` has to say whether this session is the standard-account one the
/// manual asks for: an elevated run can write past the sandbox.
#[test]
fn doctor_reports_whether_the_session_is_elevated() {
    let dir = workdir("doctor-elevation");
    let doctor = run(&dir, &["doctor"]);
    assert_eq!(doctor.code, 0, "{}", doctor.stderr);
    let json = rea_offline::json::parse(&doctor.stdout).expect("doctor JSON");
    assert!(
        matches!(json.get("elevated"), Some(rea_offline::json::Value::Bool(_))
            | Some(rea_offline::json::Value::Null)),
        "doctor must state the session's privilege level: {json:?}"
    );
    let md = run(&dir, &["doctor", "--format", "markdown"]);
    assert!(md.stdout.contains("running elevated"), "{}", md.stdout);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A minimal archive whose coverage record is the only interesting part.
fn coverage_archive(complete: bool) -> String {
    let issues = if complete {
        "[]".to_string()
    } else {
        r#"[{"area":"sandbox snapshot (after)","path":"AppData/hidden",
             "stage":"traverse","message":"Permission denied (os error 13)"}]"#.to_string()
    };
    format!(
        r#"{{"schema_version":3,"mode":"local-scan","generated_unix":1,"verdict":"low",
            "coverage":{{"complete":{},"issue_count":{},"unverified_count":0,"issues":{}}},
            "report":{{"file_count":0,"risk_score":0,"verdict":"low","files":[],"scan_issues":[]}}}}"#,
        complete,
        if complete { 0 } else { 1 },
        issues
    )
}

#[test]
fn fail_on_incomplete_refuses_a_calm_but_blind_archive() {
    let dir = workdir("coverage-gate");
    let clean = dir.join("clean.json");
    let blind = dir.join("blind.json");
    std::fs::write(&clean, coverage_archive(true)).unwrap();
    std::fs::write(&blind, coverage_archive(false)).unwrap();

    // Same verdict, same score — only the coverage record differs.
    let ok = run(&dir, &["report", "clean.json", "--fail-on-incomplete", "--quiet"]);
    assert_eq!(ok.code, 0, "{}", ok.stderr);
    let blocked = run(&dir, &["report", "blind.json", "--fail-on-incomplete"]);
    assert_eq!(blocked.code, 3, "{}", blocked.stderr);
    assert!(blocked.stderr.contains("coverage is incomplete"), "{}", blocked.stderr);

    // Without the flag the verdict gate is unchanged, and the warning is
    // still rendered so a human is not misled either.
    let plain = run(&dir, &["report", "blind.json", "--fail-on", "high", "--quiet"]);
    assert_eq!(plain.code, 0, "{}", plain.stderr);
    let text = run(&dir, &["report", "blind.json", "--format", "text"]);
    assert!(text.stdout.contains("coverage: INCOMPLETE"), "{}", text.stdout);
    assert!(text.stdout.contains("AppData/hidden"), "{}", text.stdout);
    let md = run(&dir, &["report", "blind.json", "--format", "markdown"]);
    assert!(md.stdout.contains("## Coverage warnings"), "{}", md.stdout);
    assert!(md.stdout.contains("sandbox snapshot (after)"), "{}", md.stdout);

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn an_archive_cannot_be_edited_into_looking_complete() {
    let dir = workdir("coverage-tamper");
    let path = dir.join("tampered.json");
    // Flip only the boolean, leaving the issues it contradicts in place.
    let tampered = coverage_archive(false).replace("\"complete\":false", "\"complete\":true");
    std::fs::write(&path, tampered).unwrap();
    let run = run(&dir, &["report", "tampered.json", "--fail-on-incomplete"]);
    assert_eq!(run.code, 1, "a tampered archive must be rejected, not gated: {}", run.stdout);
    assert!(run.stderr.contains("claims to be complete"), "{}", run.stderr);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn coverage_gate_says_so_when_an_archive_never_recorded_coverage() {
    let dir = workdir("coverage-legacy");
    let path = dir.join("legacy.json");
    std::fs::write(
        &path,
        r#"{"schema_version":2,"mode":"local-scan","report":{"file_count":0,"files":[]}}"#,
    ).unwrap();
    let gated = run(&dir, &["report", "legacy.json", "--fail-on-incomplete"]);
    assert_eq!(gated.code, 1, "{}", gated.stdout);
    assert!(gated.stderr.contains("does not"), "{}", gated.stderr);
    // It still renders: refusing to gate is not refusing to read.
    assert_eq!(run(&dir, &["report", "legacy.json", "--format", "text"]).code, 0);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn snapshot_and_scan_publish_their_coverage_record() {
    let dir = workdir("coverage-record");
    let tree = dir.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("a.txt"), b"hello").unwrap();

    let snap = run(&dir, &["snapshot", "tree"]);
    assert_eq!(snap.code, 0, "{}", snap.stderr);
    let json = rea_offline::json::parse(&snap.stdout).unwrap();
    assert_eq!(json.get("complete"), Some(&rea_offline::json::Value::Bool(true)));
    assert_eq!(json.get("issue_count"), Some(&rea_offline::json::Value::num(0)));

    let scan = run(&dir, &["scan", "tree", "--fail-on-incomplete", "--quiet"]);
    assert_eq!(scan.code, 0, "{}", scan.stderr);
    let report = dir.join("scan.json");
    run(&dir, &["scan", "tree", "--output", report.to_str().unwrap(), "--quiet"]);
    let json = rea_offline::json::parse(&std::fs::read_to_string(&report).unwrap()).unwrap();
    assert_eq!(
        json.get("coverage").and_then(|c| c.get("complete")),
        Some(&rea_offline::json::Value::Bool(true))
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// End-to-end through the CLI: a real unreadable directory must reach the
/// exit code, not just the JSON.
#[cfg(unix)]
#[test]
fn scanning_an_unreadable_tree_exits_three() {
    use std::os::unix::fs::PermissionsExt;
    let dir = workdir("coverage-unreadable");
    let tree = dir.join("tree");
    let locked = tree.join("locked");
    std::fs::create_dir_all(&locked).unwrap();
    std::fs::write(locked.join("hidden.exe"), b"MZ").unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::read_dir(&locked).is_ok() {
        // Privileged process: mode bits do not apply.
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        return;
    }
    let gated = run(&dir, &["scan", "tree", "--fail-on-incomplete"]);
    let snapshot = run(&dir, &["snapshot", "tree"]);
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();

    assert_eq!(gated.code, 3, "{}", gated.stderr);
    let json = rea_offline::json::parse(&snapshot.stdout).unwrap();
    assert_eq!(json.get("complete"), Some(&rea_offline::json::Value::Bool(false)));
    let issues = match json.get("issues") {
        Some(rea_offline::json::Value::Array(items)) => items.clone(),
        other => panic!("issues expected, got {other:?}"),
    };
    assert!(issues.iter().any(|i| {
        i.get("path").and_then(|v| v.as_str()) == Some("locked")
            && i.get("stage").and_then(|v| v.as_str()) == Some("traverse")
    }), "{issues:?}");
}
