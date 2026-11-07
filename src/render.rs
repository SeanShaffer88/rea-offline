//! Human-readable rendering.
//!
//! JSON is the machine contract; this module is what a person reads at the
//! end of an offline inspection. Given a report [`Value`] it produces either
//! a terminal summary or a self-contained Markdown document, and it works on
//! *any* report this tool emits (`local-scan`, `sandbox-installer`), because
//! it reads the JSON shape rather than Rust structs — so a report archived
//! months ago still renders.
//!
//! Colour is never load-bearing: severity is spelled out in words, so the
//! output survives pipes, log files and monochrome terminals.

use crate::json::Value;
use crate::mdtable::Table;

/// Width of the aligned `label value` blocks in terminal mode.
const LABEL_WIDTH: usize = 26;
/// Rows rendered per table before truncating (full data stays in the JSON).
const MAX_ROWS: usize = 200;

fn s(v: Option<&Value>) -> String {
    v.and_then(Value::as_str).unwrap_or("").to_string()
}

fn n(v: Option<&Value>) -> u64 {
    match v {
        Some(Value::Number(x)) if *x >= 0.0 => *x as u64,
        _ => 0,
    }
}

fn flag(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Bool(true)))
}

fn array(v: Option<&Value>) -> &[Value] {
    match v {
        Some(Value::Array(items)) => items,
        _ => &[],
    }
}

fn nullish(v: Option<&Value>) -> bool {
    matches!(v, None | Some(Value::Null))
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 { format!("{bytes} B") } else { format!("{value:.1} {}", UNITS[unit]) }
}

/// The static-analysis block: `report` for scans, `installer_report` also
/// exists for sandbox runs (the installer binary itself is evidence).
fn primary_report(root: &Value) -> Option<&Value> {
    root.get("report")
        .filter(|r| r.get("file_count").is_some())
        .or_else(|| root.get("installer_report").filter(|r| r.get("file_count").is_some()))
}

fn pad(label: &str) -> String {
    if label.len() >= LABEL_WIDTH {
        format!("{label}: ")
    } else {
        format!("{label:<LABEL_WIDTH$}: ")
    }
}

fn severity_rank(sev: &str) -> u8 {
    match sev {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}

fn sorted_findings(rules: &Value) -> Vec<&Value> {
    let mut items: Vec<&Value> = array(rules.get("findings")).iter().collect();
    items.sort_by(|a, b| {
        severity_rank(&s(a.get("severity")))
            .cmp(&severity_rank(&s(b.get("severity"))))
            .then(s(a.get("file")).cmp(&s(b.get("file"))))
            .then(s(a.get("rule")).cmp(&s(b.get("rule"))))
    });
    items
}

fn delta_line(label: &str, delta: &Value) -> String {
    format!(
        "{}{} added · {} modified · {} deleted",
        pad(label),
        array(delta.get("added")).len(),
        array(delta.get("modified")).len(),
        array(delta.get("deleted")).len()
    )
}

/// Terminal summary — plain text, no ANSI escapes.
pub fn summary_text(root: &Value) -> String {
    let mut out = String::new();
    let mode = s(root.get("mode"));
    let mode = if mode.is_empty() { "report".to_string() } else { mode };
    out.push_str(&format!("rea-offline report ({mode})\n"));
    out.push_str(&"=".repeat(30));
    out.push('\n');

    if let Some(r) = primary_report(root) {
        let summary = r.get("summary");
        out.push_str(&format!("{}{}\n", pad("target"), s(r.get("target"))));
        out.push_str(&format!("{}{}\n", pad("engine"), s(r.get("engine"))));
        out.push_str(&format!(
            "{}{} files ({})\n",
            pad("analyzed"),
            n(r.get("file_count")),
            human_bytes(n(summary.and_then(|x| x.get("total_bytes"))))
        ));
        let score = n(r.get("risk_score"));
        out.push_str(&format!("{}{}/100\n", pad("risk score"), score));
        out.push_str(&format!("{}{}\n", pad("verdict"), s(r.get("verdict")).to_uppercase()));

        let rules = r.get("rules");
        if let Some(by) = rules.and_then(|x| x.get("by_severity")) {
            let parts: Vec<String> = ["critical", "high", "medium", "low", "info"]
                .iter()
                .map(|k| format!("{} {}", n(by.get(*k)), k))
                .collect();
            out.push_str(&format!("{}{}\n", pad("findings"), parts.join(" · ")));
        }
        let wx = n(summary.and_then(|x| x.get("writable_executable_sections")));
        let unsigned = n(summary.and_then(|x| x.get("unsigned_pe_files")));
        let pe = n(summary.and_then(|x| x.get("pe_files")));
        out.push_str(&format!(
            "{}{} sections W+X · {}/{} PE files unsigned\n",
            pad("hardening"),
            wx,
            unsigned,
            pe
        ));

        let top: Vec<String> = rules
            .map(|rules| {
                sorted_findings(rules)
                    .into_iter()
                    .filter(|f| s(f.get("severity")) != "info")
                    .take(8)
                    .map(|f| {
                        format!(
                            "{:<8} {}  {}  ({})",
                            s(f.get("severity")).to_uppercase(),
                            s(f.get("rule")),
                            s(f.get("title")),
                            s(f.get("file")),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        if !top.is_empty() {
            out.push_str("\nTop findings\n");
            for line in &top {
                out.push_str(&format!("  {line}\n"));
            }
        }
    }

    if let Some(exec) = root.get("execution") {
        out.push_str("\nExecution\n");
        out.push_str(&format!("{}{}\n", pad("command"), s(exec.get("command"))));
        let code = if nullish(exec.get("exit_code")) {
            if flag(exec.get("timed_out")) { "killed (timeout)".to_string() } else { "n/a".to_string() }
        } else {
            n(exec.get("exit_code")).to_string()
        };
        out.push_str(&format!("{}{}\n", pad("exit code"), code));
        out.push_str(&format!("{}{} ms\n", pad("duration"), n(exec.get("duration_ms"))));
        let tail = s(exec.get("stdout_tail"));
        if !tail.trim().is_empty() {
            out.push_str(&format!("{}last stdout lines\n", pad("")));
            let lines: Vec<&str> = tail.lines().rev().take(6).collect();
            for line in lines.into_iter().rev() {
                out.push_str(&format!("  {line}\n"));
            }
        }
        let err_tail = s(exec.get("stderr_tail"));
        if !err_tail.trim().is_empty() {
            out.push_str(&format!("{}last stderr lines\n", pad("")));
            let lines: Vec<&str> = err_tail.lines().rev().take(4).collect();
            for line in lines.into_iter().rev() {
                out.push_str(&format!("  {line}\n"));
            }
        }
    }

    if let Some(delta) = root.get("delta") {
        out.push_str("\nInstall-tree changes\n");
        out.push_str(&delta_line("delta", delta));
        out.push('\n');
        for item in array(delta.get("added")).iter().take(12) {
            out.push_str(&format!(
                "  + {} ({})\n",
                s(item.get("path")),
                human_bytes(n(item.get("size")))
            ));
        }
        for item in array(delta.get("modified")).iter().take(6) {
            out.push_str(&format!("  ~ {}\n", s(item.get("path"))));
        }
        for item in array(delta.get("deleted")).iter().take(6) {
            out.push_str(&format!("  - {}\n", s(item.get("path"))));
        }
    }

    if let Some(delta) = root.get("sandbox_delta") {
        let added = array(delta.get("added"));
        if !added.is_empty() {
            out.push_str(&format!(
                "\n{} {} file(s) written outside the install directory\n",
                pad("sandbox drops"),
                added.len()
            ));
            for item in added.iter().take(12) {
                out.push_str(&format!("  + {}\n", s(item.get("path"))));
            }
        }
    }

    if let Some(purge) = root.get("purge").filter(|p| p.get("path").is_some()) {
        out.push_str(&format!("\n{}{}\n", pad("purged"), s(purge.get("path"))));
        out.push_str(&format!(
            "{}{}\n",
            pad("zero residue"),
            if flag(purge.get("verified_zero_residue")) { "verified" } else { "NOT verified" }
        ));
    } else if flag(root.get("sandbox_kept")) {
        out.push_str(&format!("\n{}{}\n", pad("sandbox kept"), s(root.get("sandbox_path"))));
    }
    if let Some(err) = root.get("purge_error") {
        out.push_str(&format!("{}{}\n", pad("purge error"), s(Some(err))));
    }
    if let Some(warn) = root.get("registry_warning") {
        out.push_str(&format!("{}{}\n", pad("registry warning"), s(Some(warn))));
    }
    out
}

/// Markdown report suitable for pasting into a ticket or wiki.
pub fn summary_markdown(root: &Value) -> String {
    let mut out = String::new();
    let mode = s(root.get("mode"));
    out.push_str("# rea-offline inspection report\n\n");
    out.push_str(&format!("**Mode:** `{}`  \n", if mode.is_empty() { "report" } else { mode.as_str() }));
    if let Some(ts) = root.get("generated_unix") {
        out.push_str(&format!("**Generated (unix):** `{}`  \n", n(Some(ts))));
    }
    if let Some(installer) = root.get("installer") {
        out.push_str(&format!("**Installer:** `{}`  \n", s(Some(installer))));
    }
    out.push('\n');

    if let Some(r) = primary_report(root) {
        let score = n(r.get("risk_score"));
        let verdict = s(r.get("verdict")).to_uppercase();
        out.push_str("## Verdict\n\n| field | value |\n|---|---|\n");
        out.push_str(&format!("| risk score | **{score}/100** |\n"));
        out.push_str(&format!("| verdict | **{verdict}** |\n"));
        out.push_str(&format!("| target | `{}` |\n", s(r.get("target"))));
        out.push_str(&format!("| engine | `{}` |\n", s(r.get("engine"))));
        out.push_str(&format!("| files analyzed | {} |\n", n(r.get("file_count"))));
        let total = human_bytes(n(r.get("summary").and_then(|x| x.get("total_bytes"))));
        out.push_str(&format!("| total size | {total} |\n\n"));

        if let Some(rules) = r.get("rules") {
            let findings = sorted_findings(rules);
            if !findings.is_empty() {
                out.push_str("## Findings\n\n");
                let mut table = Table::new(["severity", "rule", "file", "evidence"]);
                for f in findings.iter().take(MAX_ROWS) {
                    table.row([
                        s(f.get("severity")),
                        format!("`{}` — {}", s(f.get("rule")), s(f.get("title"))),
                        format!("`{}`", s(f.get("file"))),
                        s(f.get("evidence")),
                    ]);
                }
                out.push_str(&table.render());
                if findings.len() > MAX_ROWS {
                    out.push_str(&format!(
                        "\n_{} further findings omitted; see the JSON report._\n",
                        findings.len() - MAX_ROWS
                    ));
                }
                out.push('\n');
            }
        }

        // Hashes are the part operators copy into other tools.
        let files = array(r.get("files"));
        if !files.is_empty() {
            out.push_str("## Files\n\n");
            let mut table = Table::new(["path", "size", "format", "sha256", "md5", "imphash"]);
            for f in files.iter().take(MAX_ROWS) {
                table.row([
                    s(f.get("path")),
                    human_bytes(n(f.get("size"))),
                    s(f.get("format")),
                    s(f.get("sha256")),
                    s(f.get("md5")),
                    s(f.get("imphash")),
                ]);
            }
            out.push_str(&table.render());
            if files.len() > MAX_ROWS {
                out.push_str(&format!("\n_{} further files omitted._\n", files.len() - MAX_ROWS));
            }
            out.push('\n');
        }
    }

    if let Some(exec) = root.get("execution") {
        out.push_str("## Execution\n\n");
        out.push_str(&format!("- command: `{}`\n", s(exec.get("command"))));
        let code = if nullish(exec.get("exit_code")) {
            if flag(exec.get("timed_out")) { "killed (timeout)".to_string() } else { "n/a".to_string() }
        } else {
            n(exec.get("exit_code")).to_string()
        };
        out.push_str(&format!("- exit code: {code}\n"));
        out.push_str(&format!("- duration: {} ms\n", n(exec.get("duration_ms"))));
        out.push_str(&format!(
            "- stdout captured: {}\n",
            human_bytes(n(exec.get("stdout_bytes")))
        ));
        let text_out = s(exec.get("stdout_tail"));
        let text_err = s(exec.get("stderr_tail"));
        if !text_out.trim().is_empty() || !text_err.trim().is_empty() {
            out.push_str("\n```text\n");
            for block in [&text_out, &text_err] {
                if block.trim().is_empty() {
                    continue;
                }
                out.push_str(block);
                if !block.ends_with('\n') {
                    out.push('\n');
                }
            }
            out.push_str("```\n");
        }
        out.push('\n');
    }

    for (title, key) in [
        ("Install-tree changes", "delta"),
        ("Changes outside the install directory", "sandbox_delta"),
    ] {
        let Some(delta) = root.get(key) else { continue };
        if key == "sandbox_delta"
            && delta.get("added").is_none()
            && delta.get("modified").is_none()
            && delta.get("deleted").is_none()
        {
            continue;
        }
        out.push_str(&format!("## {title}\n\n"));
        out.push_str(&format!(
            "{} added · {} modified · {} deleted\n\n",
            array(delta.get("added")).len(),
            array(delta.get("modified")).len(),
            array(delta.get("deleted")).len()
        ));
        if !array(delta.get("added")).is_empty()
            || !array(delta.get("modified")).is_empty()
            || !array(delta.get("deleted")).is_empty()
        {
            let mut table = Table::new(["change", "path", "size", "sha256"]);
            for (mark, list) in [("added", "added"), ("modified", "modified"), ("deleted", "deleted")] {
                for item in array(delta.get(list)).iter().take(MAX_ROWS) {
                    table.row([
                        mark.to_string(),
                        s(item.get("path")),
                        human_bytes(n(item.get("size"))),
                        s(item.get("sha256")),
                    ]);
                }
            }
            out.push_str(&table.render());
            out.push('\n');
        }
    }

    out.push_str("## Containment & cleanup\n\n");
    let mut anything = false;
    if flag(root.get("sandbox_kept")) {
        out.push_str(&format!("- sandbox **kept** at `{}`\n", s(root.get("sandbox_path"))));
        anything = true;
    }
    if let Some(purge) = root.get("purge").filter(|p| p.get("path").is_some()) {
        out.push_str(&format!("- purged `{}`\n", s(purge.get("path"))));
        out.push_str(&format!(
            "- zero residue: **{}**\n",
            if flag(purge.get("verified_zero_residue")) { "verified" } else { "NOT verified" }
        ));
        anything = true;
    }
    if let Some(warn) = root.get("registry_warning") {
        out.push_str(&format!("- registry warning: {}\n", s(Some(warn))));
        anything = true;
    }
    if !anything {
        out.push_str("- static inspection only (no execution)\n");
    }
    out.push_str(
        "\n> Static indicators are evidence, not a verdict. A Job Object is containment,\n> not a hypervisor — see `docs/ARCHITECTURE.md`.\n",
    );
    out
}

/// Markdown for `doctor`.
pub fn doctor_markdown(root: &Value) -> String {
    let ok = |b: bool| if b { "yes" } else { "no" };
    let mut table = Table::new(["check", "value"]);
    table.row(["version", &s(root.get("version"))]);
    table.row(["platform", &format!("{} / {}", s(root.get("os")), s(root.get("arch")))]);
    table.row(["Win32 Job Objects", ok(flag(root.get("windows_job_objects")))]);
    table.row(["registry hive mount", &s(root.get("registry_hive_mount"))]);
    table.row(["temp dir", &s(root.get("temp_dir"))]);
    table.row(["sandbox rehearsal", ok(flag(root.get("sandbox_rehearsal_ok")))]);
    if let Some(err) = root.get("sandbox_rehearsal_error").filter(|v| !matches!(v, Value::Null)) {
        table.row(["rehearsal error", &s(Some(err))]);
    }
    if let Some(rea) = root.get("rea") {
        table.row(["REA found", ok(flag(rea.get("found")))]);
        table.row(["REA path", &s(rea.get("path"))]);
    }
    format!("# rea-offline doctor\n\n{}", table.render())
}

/// Render any report as Markdown; `doctor` output has its own shape.
pub fn to_markdown(root: &Value) -> String {
    if s(root.get("mode")) == "doctor" {
        doctor_markdown(root)
    } else {
        summary_markdown(root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report() -> Value {
        Value::obj(vec![
            ("mode", Value::str("sandbox-installer")),
            ("generated_unix", Value::num(1_700_000_000)),
            ("installer", Value::str("setup.exe")),
            ("report", Value::obj(vec![
                ("target", Value::str("C:/tmp/install")),
                ("engine", Value::str("rea-offline-native")),
                ("file_count", Value::num(2)),
                ("risk_score", Value::num(52)),
                ("verdict", Value::str("high")),
                ("summary", Value::obj(vec![
                    ("total_bytes", Value::num(2048)),
                    ("pe_files", Value::num(2)),
                    ("writable_executable_sections", Value::num(1)),
                    ("unsigned_pe_files", Value::num(1)),
                ])),
                ("rules", Value::obj(vec![
                    ("score", Value::num(52)),
                    ("verdict", Value::str("high")),
                    ("by_severity", Value::obj(vec![
                        ("critical", Value::num(0)), ("high", Value::num(1)),
                        ("medium", Value::num(1)), ("low", Value::num(0)), ("info", Value::num(1)),
                    ])),
                    ("findings", Value::Array(vec![
                        Value::obj(vec![("rule", Value::str("PE100")), ("title", Value::str("W+X")),
                            ("severity", Value::str("high")), ("file", Value::str("a.exe")),
                            ("evidence", Value::str("code|write"))]),
                        Value::obj(vec![("rule", Value::str("PE110")), ("title", Value::str("entropy")),
                            ("severity", Value::str("medium")), ("file", Value::str("a.exe")),
                            ("evidence", Value::str("7.6"))]),
                    ])),
                ])),
                ("files", Value::Array(vec![Value::obj(vec![
                    ("path", Value::str("a.exe")), ("size", Value::num(1024)),
                    ("format", Value::str("PE")), ("sha256", Value::str("ab")),
                    ("md5", Value::str("cd")), ("imphash", Value::str("ef")),
                ])])),
            ])),
            ("execution", Value::obj(vec![
                ("command", Value::str("setup.exe /S")),
                ("exit_code", Value::num(0)),
                ("timed_out", Value::Bool(false)),
                ("duration_ms", Value::num(1500)),
                ("stdout_bytes", Value::num(11)),
                ("stdout_tail", Value::str("installing\n")),
                ("stderr_tail", Value::str("")),
            ])),
            ("delta", Value::obj(vec![
                ("added", Value::Array(vec![Value::obj(vec![
                    ("path", Value::str("a.exe")), ("size", Value::num(1024)),
                    ("sha256", Value::str("ab")),
                ])])),
                ("modified", Value::Array(vec![])),
                ("deleted", Value::Array(vec![])),
            ])),
            ("purge", Value::obj(vec![
                ("path", Value::str("/tmp/rea_sandbox_x")),
                ("removed", Value::Bool(true)),
                ("verified_zero_residue", Value::Bool(true)),
            ])),
        ])
    }

    #[test]
    fn text_summary_mentions_the_decisions() {
        let text = summary_text(&sample_report());
        assert!(text.contains("52/100"), "{text}");
        assert!(text.contains("HIGH"), "{text}");
        assert!(text.contains("PE100"), "{text}");
        assert!(text.contains("installing"), "{text}");
        assert!(text.contains("zero residue"), "{text}");
        assert!(text.contains("1 added"), "{text}");
        assert!(!text.contains('\u{1b}'), "no ANSI escapes in plain output");
    }

    #[test]
    fn markdown_escapes_pipes_and_stays_rectangular() {
        let md = to_markdown(&sample_report());
        assert!(md.starts_with("# rea-offline"));
        assert!(md.contains("code\\|write"), "pipe inside a cell must be escaped:\n{md}");
        assert!(md.contains("## Execution"));
        assert!(md.contains("zero residue: **verified**"));
        // Every table row must carry the same number of columns as its header.
        let mut columns: Option<usize> = None;
        for line in md.lines() {
            if line.starts_with('|') && line.trim_end().ends_with('|') {
                let count = line.matches('|').count();
                match columns {
                    None => columns = Some(count),
                    Some(expected) => {
                        if line.contains("---") {
                            assert_eq!(count, expected, "separator width drifted: {line}");
                        }
                    }
                }
            } else {
                columns = None;
            }
        }
    }

    #[test]
    fn renders_reports_with_missing_sections() {
        // A half-populated or older report must not panic.
        let minimal = Value::obj(vec![("mode", Value::str("local-scan"))]);
        assert!(summary_text(&minimal).contains("local-scan"));
        assert!(to_markdown(&minimal).starts_with("# rea-offline"));
        assert!(to_markdown(&Value::Null).starts_with("# rea-offline"));
        let doctor = Value::obj(vec![
            ("mode", Value::str("doctor")),
            ("version", Value::str("0.4.0")),
            ("os", Value::str("linux")),
            ("arch", Value::str("x86_64")),
            ("windows_job_objects", Value::Bool(false)),
            ("registry_hive_mount", Value::str("not applicable")),
            ("temp_dir", Value::str("/tmp")),
            ("sandbox_rehearsal_ok", Value::Bool(true)),
        ]);
        let md = to_markdown(&doctor);
        assert!(md.starts_with("# rea-offline doctor"));
        assert!(md.contains("| Win32 Job Objects | no |"));
    }

    #[test]
    fn timed_out_execution_is_labelled() {
        let mut root = sample_report();
        if let Value::Object(map) = &mut root {
            map.insert("execution".into(), Value::obj(vec![
                ("command", Value::str("setup.exe")),
                ("exit_code", Value::Null),
                ("timed_out", Value::Bool(true)),
                ("duration_ms", Value::num(300_000)),
            ]));
        }
        let text = summary_text(&root);
        assert!(text.contains("killed (timeout)"), "{text}");
        assert!(to_markdown(&root).contains("killed (timeout)"));
    }

    #[test]
    fn byte_formatting() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1023), "1023 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(5 * 1024 * 1024), "5.0 MiB");
    }
}
