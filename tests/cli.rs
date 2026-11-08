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
    assert_eq!(
        json.get("sandbox_rehearsal_ok"),
        Some(&rea_offline::json::Value::Bool(true))
    );

    let md = run(&dir, &["doctor", "--format", "markdown"]);
    assert!(md.stdout.starts_with("# rea-offline doctor"), "{}", md.stdout);
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
