//! Graphical interface — a WizTree-shaped window for analysis, not disk use.
//!
//! `rea-offline gui` serves a single self-contained page on `127.0.0.1` and
//! opens it in the default browser. Why not a native Win32 window? Because
//! this tool must build on an air-gapped machine with **zero crates** — no
//! GUI toolkit is available without vendoring one — and a browser is a
//! windowing system every Windows edition already ships. See `docs/GUI.md`
//! for the full rationale and the Windows-native escape hatch we rejected.
//!
//! Shape of the UI, borrowed from WizTree and re-aimed at evidence:
//!
//! ```text
//! +------------------------------------------------------------------+
//! | [Scan folder…] [Pick folder]   Filter: ______  Hide clean [x]     |
//! +---------------------------+--------------------------------------+
//! | Name          Size  Risk  |                                      |
//! | > install/    4.2 MiB  ⚠  |            treemap                   |
//! |   > a.exe     1.1 MiB  ⛔ |      (tiles tinted by risk)          |
//! +---------------------------+--------------------------------------+
//! | details of the selected file: hashes, findings, verdict            |
//! +------------------------------------------------------------------+
//! ```
//!
//! The data model lives in [`tree`] and is unit-tested on every platform;
//! this file only turns that model into HTML/SVG and moves bytes over a
//! loopback socket.

pub mod tree;

use crate::json::Value;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::time::Duration;
use tree::{SortColumn, TreemapScope, View};

/// Everything the page needs, computed once per request.
pub struct Page {
    pub report: Value,
    pub root_name: String,
    pub tree: tree::DirNode,
}

impl Page {
    pub fn new(report: Value, root_name: &str) -> Page {
        // A sandbox run analyzes three sets: the install tree, the installer
        // itself and the files dropped outside the install dir. Showing only
        // one of them would hide the payload that decided the verdict, so
        // the tree merges them under labelled folders.
        let merged = sandbox_view_body(&report);
        let body = match &merged {
            Some(body) => body,
            None => report
                .get("report")
                .filter(|r| r.get("files").is_some())
                .or_else(|| {
                    report
                        .get("installer_report")
                        .filter(|r| r.get("files").is_some())
                })
                .unwrap_or(&report),
        };
        let mut node = tree::from_report(body);
        if node.name.is_empty() {
            node.name = root_name.to_string();
        }
        Page {
            report,
            root_name: root_name.to_string(),
            tree: node,
        }
    }

    pub fn verdict(&self) -> String {
        self.report
            .get("verdict")
            .and_then(Value::as_str)
            .or_else(|| {
                self.report
                    .get("report")
                    .and_then(|r| r.get("verdict"))
                    .and_then(Value::as_str)
            })
            .unwrap_or("low")
            .to_string()
    }

    pub fn score(&self) -> u64 {
        // The envelope carries the combined sandbox score; the body only
        // knows about the install tree. Chip and verdict must agree.
        if let Some(Value::Number(x)) = self.report.get("risk_score") {
            if *x >= 0.0 {
                return *x as u64;
            }
        }
        let source = self.report.get("report").unwrap_or(&self.report);
        match source.get("risk_score") {
            Some(Value::Number(x)) if *x >= 0.0 => *x as u64,
            _ => 0,
        }
    }

    pub fn summary_text(&self) -> String {
        crate::render::summary_text(&self.report)
    }
}

/// Path of a file inside the merged sandbox tree. Absolute installer paths
/// are made relative (and lose their drive letter) so the grid never grows
/// a `C:` folder or an empty root segment.
fn sandbox_view_path(prefix: &str, path: &str) -> String {
    let normalized = path.replace('\\', "/");
    let relative = normalized.trim_start_matches('/');
    let relative = match relative.as_bytes() {
        [drive, b':', ..] if drive.is_ascii_alphabetic() => relative[2..].trim_start_matches('/'),
        _ => relative,
    };
    if prefix.is_empty() {
        relative.to_string()
    } else {
        format!("{prefix}/{relative}")
    }
}

/// One analysis body describing every file a sandbox run inspected, with
/// `install/`, `_installer/` and profile-relative drop paths side by side.
/// Returns `None` when there is nothing to merge (plain scans, or a sandbox
/// run with no installer body and no drops).
fn sandbox_view_body(report: &Value) -> Option<Value> {
    if report.get("mode").and_then(Value::as_str) != Some("sandbox-installer") {
        return None;
    }
    let has_extra = ["installer_report", "drops_report"].iter().any(|key| {
        report
            .get(key)
            .map(|part| !array(part.get("files")).is_empty())
            .unwrap_or(false)
    });
    if !has_extra {
        return None;
    }
    let parts = [
        ("_installer", report.get("installer_report")),
        ("install", report.get("report")),
        ("", report.get("drops_report")),
    ];
    let mut files: Vec<Value> = Vec::new();
    let mut findings: Vec<Value> = Vec::new();
    let mut target = String::new();
    for (prefix, part) in parts {
        let Some(part) = part.filter(|p| !matches!(p, Value::Null)) else {
            continue;
        };
        if prefix.is_empty() {
            target = part
                .get("target")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
        }
        for file in array(part.get("files")) {
            let path = sandbox_view_path(
                prefix,
                file.get("path").and_then(Value::as_str).unwrap_or(""),
            );
            if path.is_empty() {
                continue;
            }
            if let Value::Object(mut map) = file.clone() {
                map.insert("path".into(), Value::str(path));
                files.push(Value::Object(map));
            }
        }
        // Findings are matched to files by path, so they must be rewritten
        // exactly the same way or every tint/detail lookup would miss.
        for finding in array(part.get("rules").and_then(|r| r.get("findings"))) {
            let file = sandbox_view_path(
                prefix,
                finding.get("file").and_then(Value::as_str).unwrap_or(""),
            );
            if let Value::Object(mut map) = finding.clone() {
                map.insert("file".into(), Value::str(file));
                findings.push(Value::Object(map));
            }
        }
    }
    Some(Value::obj(vec![
        ("target", Value::str(target)),
        ("files", Value::Array(files)),
        (
            "rules",
            Value::obj(vec![("findings", Value::Array(findings))]),
        ),
    ]))
}

/// Percent-encode for query strings / JSON-in-HTML attributes.
fn encode(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn parse_query(query: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (key, value) = match pair.split_once('=') {
            Some(parts) => parts,
            None => (pair, ""),
        };
        out.push((key.to_string(), percent_decode(value)));
    }
    out
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                if let Ok(value) = u8::from_str_radix(&text[i + 1..i + 3], 16) {
                    out.push(value);
                    i += 3;
                    continue;
                }
                out.push(bytes[i]);
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn view_from(query: &[(String, String)]) -> View {
    let mut view = View::default();
    // The report root starts open; `collapse=.` (ROOT_KEY) closes it.
    view.expanded.push(tree::ROOT_KEY.to_string());
    for (key, value) in query {
        match key.as_str() {
            "expand" => {
                if !view.expanded.contains(value) {
                    view.expanded.push(value.clone());
                }
            }
            "collapse" => view.expanded.retain(|p| p != value),
            "filter" => view.filter = value.clone(),
            "hide_clean" => view.hide_clean = value == "1",
            "min_risk" => view.min_risk = value.parse().unwrap_or(0),
            "sort" => {
                view.sort = match value.as_str() {
                    "name" => SortColumn::Name,
                    "risk" => SortColumn::Risk,
                    "files" => SortColumn::Files,
                    "format" => SortColumn::Format,
                    _ => SortColumn::Size,
                }
            }
            "dir" => view.descending = value != "asc",
            "scope" => {
                view.scope = if value == "files" {
                    TreemapScope::Files
                } else {
                    TreemapScope::TopLevel
                }
            }
            "select" => view.selected = Some(value.clone()),
            _ => {}
        }
    }
    view
}

/// The state every control carries forward (search, filters, sort, the open
/// tree, the selection). Expansion is appended by the caller because it
/// differs per link.
fn state_params(view: &View) -> Vec<String> {
    let mut params = Vec::new();
    if !view.filter.is_empty() {
        params.push(format!("filter={}", encode(&view.filter)));
    }
    if view.hide_clean {
        params.push("hide_clean=1".into());
    }
    if view.min_risk > 0 {
        params.push(format!("min_risk={}", view.min_risk));
    }
    if view.scope == TreemapScope::Files {
        params.push("scope=files".into());
    }
    if view.sort != SortColumn::Size {
        let key = match view.sort {
            SortColumn::Name => "name",
            SortColumn::Size => "size",
            SortColumn::Risk => "risk",
            SortColumn::Files => "files",
            SortColumn::Format => "format",
        };
        params.push(format!("sort={key}"));
    }
    if !view.descending {
        params.push("dir=asc".into());
    }
    if let Some(selected) = &view.selected {
        params.push(format!("select={}", encode(selected)));
    }
    // Note: expansion state is owned by the page visitor, not by the link
    // generator — see `export_expansion` below. Keeping it out of here is
    // what stops the links from growing on every click.
    // Expansion is appended by the caller from `open_paths` (the nodes that
    // are actually open on this page), never from the visitor's whole history
    // — otherwise every click would make the URL longer.
    params
}

fn array(value: Option<&Value>) -> &[Value] {
    match value {
        Some(Value::Array(items)) => items,
        _ => &[],
    }
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn hex(rgb: u32) -> String {
    format!("#{:06x}", rgb)
}

fn html_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// Full page for one request. `query` is the raw URL query string.
///
/// Every interactive control is a link (`/view?...`) so the page needs no
/// JavaScript to be useful, and no state survives a refresh that the URL does
/// not carry. That matters on a locked-down machine where the browser may
/// have scripting disabled by policy.
pub fn page_html(page: &Page, query: &str) -> String {
    let parsed = parse_query(query);
    let view = view_from(&parsed);
    // Only nodes that are open *and currently visible* count as state;
    // anything else is history and would just make every URL longer.
    let rows = tree::rows(&page.tree, &view);
    let visible_dirs: Vec<String> = rows
        .iter()
        .filter(|r| r.is_dir)
        .map(|r| r.path.clone())
        .collect();
    let mut open_paths: Vec<String> = view
        .expanded
        .iter()
        .filter(|p| p.as_str() == tree::ROOT_KEY || visible_dirs.iter().any(|v| v == *p))
        .cloned()
        .collect();
    // A search opens the way to its matches even if the visitor never
    // clicked those nodes (the tree does the same; this mirrors it so the
    // links stay consistent with what is on screen).
    if !view.filter.is_empty() {
        for row in rows.iter().filter(|r| r.is_dir) {
            let prefix = format!("{}/", row.path);
            if rows
                .iter()
                .any(|other| other.depth == row.depth + 1 && other.path.starts_with(&prefix))
            {
                open_paths.push(row.path.clone());
            }
        }
    }
    open_paths.sort();
    open_paths.dedup();
    // The SVG uses a 0..100 viewBox, so the layout runs in "percent" units
    // and the browser scales it to the pane: no JS, no resize handling.
    let banner = tree::treemap(&page.tree, 100.0, 100.0, &view, 1.2);
    let selected = view.selected.clone().unwrap_or_default();

    let mut body = String::new();
    body.push_str("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">");
    body.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
    body.push_str("<title>rea-offline — ");
    body.push_str(&html_escape(&page.root_name));
    body.push_str("</title><style>");
    body.push_str(STYLE);
    body.push_str("</style></head><body>");

    // Toolbar: the WizTree drive selector becomes "which target", and the
    // primary actions are scan/purge because this is an inspection tool.
    body.push_str("<header><div class=\"title\"><span class=\"logo\">rea-offline</span>");
    body.push_str(&format!(
        "<span class=\"path\">{}</span></div>",
        html_escape(&page.root_name)
    ));
    body.push_str("<div class=\"chips\">");
    body.push_str(&format!(
        "<span class=\"chip verdict-{}\">{} — {}/100</span>",
        html_escape(&page.verdict()),
        html_escape(&page.verdict().to_uppercase()),
        page.score()
    ));
    let issue_count: usize = match page.report.get("coverage").and_then(|c| c.get("issues")) {
        Some(issues) => array(Some(issues)).len(),
        None => ["report", "installer_report", "drops_report"]
            .iter()
            .map(|key| array(page.report.get(key).and_then(|r| r.get("scan_issues"))).len())
            .sum(),
    };
    if issue_count > 0 {
        body.push_str(&format!(
            "<span class=\"chip coverage-incomplete\">incomplete coverage — {issue_count} issue(s)</span>"
        ));
    }
    body.push_str(&format!(
        "<span class=\"chip\">{} files · {}</span>",
        page.tree.file_count,
        human_bytes(page.tree.size)
    ));
    body.push_str("</div></header>");

    body.push_str("<div class=\"toolbar\">");
    body.push_str(&format!(
        "<form method=\"get\" action=\"/\" class=\"filter\"><input name=\"filter\" value=\"{}\" placeholder=\"filter paths…\" aria-label=\"filter\">\
         <input type=\"hidden\" name=\"hide_clean\" value=\"{}\"><button>Apply</button></form>",
        html_escape(&view.filter),
        if view.hide_clean { "1" } else { "0" }
    ));
    let toggle = |label: &str, on: bool, href: String| {
        format!(
            "<a class=\"toggle{}\" href=\"{}\">{}</a>",
            if on { " on" } else { "" },
            href,
            label
        )
    };
    // Clicking a row only changes that row's open/closed state; everything
    // else (search, filters, sort, selection) is carried along.
    let with_expansion = |path: &str, expand: bool| -> String {
        let mut params = state_params(&view);
        // Carry the open nodes, but not this one: the clicked node's state is
        // what the next page changes.
        for open in &open_paths {
            if open != path {
                params.push(format!("expand={}", encode(open)));
            }
        }
        params.push(format!(
            "{}={}",
            if expand { "expand" } else { "collapse" },
            encode(path)
        ));
        format!("/view?{}", params.join("&"))
    };
    let expand_all = |params: &mut Vec<String>| {
        for path in &open_paths {
            params.push(format!("expand={}", encode(path)));
        }
    };
    let base = |extra: &str| -> String {
        let mut params = state_params(&view);
        if !extra.is_empty() {
            params.push(extra.to_string());
        }
        expand_all(&mut params);
        format!("/view?{}", params.join("&"))
    };
    body.push_str(&toggle(
        "hide clean",
        view.hide_clean,
        if view.hide_clean {
            base("")
        } else {
            base("hide_clean=1")
        },
    ));
    body.push_str(&toggle(
        "risk ≥ 12",
        view.min_risk >= 12,
        if view.min_risk >= 12 {
            base("")
        } else {
            base("min_risk=12")
        },
    ));
    body.push_str(&toggle(
        "all files in map",
        view.scope == TreemapScope::Files,
        if view.scope == TreemapScope::Files {
            base("")
        } else {
            base("scope=files")
        },
    ));
    body.push_str(
        "<span class=\"spacer\"></span><a class=\"toggle\" href=\"/json\">JSON</a>\
         <a class=\"toggle\" href=\"/markdown\">Markdown</a>\
         <a class=\"toggle\" href=\"/text\">Text</a>",
    );
    body.push_str("</div>");

    // Main split: grid on the left, treemap on the right (WizTree layout).
    body.push_str("<main><section class=\"grid\"><table><thead><tr>");
    let sort_link = |label: &str, column: SortColumn| -> String {
        let descending = if view.sort == column {
            !view.descending
        } else {
            true
        };
        let marker = if view.sort == column {
            if view.descending {
                " ▾"
            } else {
                " ▴"
            }
        } else {
            ""
        };
        let key = match column {
            SortColumn::Name => "name",
            SortColumn::Size => "size",
            SortColumn::Risk => "risk",
            SortColumn::Files => "files",
            SortColumn::Format => "format",
        };
        let mut params = state_params(&view);
        expand_all(&mut params);
        params.push(format!("sort={key}"));
        params.push(format!("dir={}", if descending { "desc" } else { "asc" }));
        format!(
            "<th><a href=\"/view?{}\">{label}{marker}</a></th>",
            params.join("&")
        )
    };
    body.push_str(&sort_link("Name", SortColumn::Name));
    body.push_str(&sort_link("Size", SortColumn::Size));
    body.push_str(&sort_link("Risk", SortColumn::Risk));
    body.push_str(&sort_link("Files", SortColumn::Files));
    body.push_str(&sort_link("Type", SortColumn::Format));
    body.push_str("</tr></thead><tbody>");

    for row in &rows {
        let is_open = view.expanded.iter().any(|e| e == &row.path);
        let indent = 10 + row.depth * 14;
        let expander = if row.is_dir {
            let href = with_expansion(&row.path, !is_open);
            format!(
                "<a class=\"expander\" href=\"{href}\">{}</a>",
                if is_open { "▾" } else { "▸" }
            )
        } else {
            "<span class=\"expander\"></span>".to_string()
        };
        let href = if row.is_dir {
            with_expansion(&row.path, !is_open)
        } else {
            base(&format!("select={}", encode(&row.path)))
        };
        let selected_class = if !selected.is_empty() && selected == row.path {
            " selected"
        } else {
            ""
        };
        body.push_str(&format!(
            "<tr class=\"tint-{}{}\" style=\"--indent:{indent}px\">\
             <td class=\"name\"><span class=\"pad\"></span>{expander}<a href=\"{href}\">{}</a></td>\
             <td class=\"num\">{}</td><td class=\"num\"><i class=\"dot\" style=\"background:{}\"></i>{}</td>\
             <td class=\"num\">{}</td><td>{}</td></tr>",
            row.tint.as_str(),
            selected_class,
            html_escape(&row.name),
            human_bytes(row.size),
            hex(row.tint.rgb()),
            if row.risk > 0 { row.risk.to_string() } else { "—".into() },
            if row.is_dir { row.file_count.to_string() } else { String::new() },
            html_escape(&row.format),
        ));
    }
    body.push_str("</tbody></table></section>");

    // Treemap (SVG, so it scales with the window and needs no canvas code).
    body.push_str("<section class=\"map\"><svg viewBox=\"0 0 100 100\" preserveAspectRatio=\"none\" role=\"img\" aria-label=\"risk treemap\">");
    for tile in &banner {
        let opacity = match tile.depth {
            0 => 0.92,
            1 => 0.78,
            _ => 0.62,
        };
        let href = if tile.is_dir {
            with_expansion(&tile.path, true)
        } else {
            base(&format!("select={}", encode(&tile.path)))
        };
        body.push_str(&format!(
            "<a href=\"{href}\"><rect x=\"{:.2}\" y=\"{:.2}\" width=\"{:.2}\" height=\"{:.2}\" \
             fill=\"{}\" fill-opacity=\"{opacity:.2}\" stroke=\"#0b0f14\" stroke-width=\"0.12\">\
             <title>{} — {} (risk {})</title></rect></a>",
            tile.x,
            tile.y,
            tile.w,
            tile.h,
            hex(tile.tint.rgb()),
            html_escape(&tile.path),
            human_bytes(tile.size),
            tile.risk
        ));
    }
    body.push_str("</svg></section></main>");

    // Details pane: the evidence for whatever is selected. `selected` is a
    // report path (what `details_text` looks up), so a selected *folder*
    // simply falls back to the summary rather than printing "no record".
    body.push_str("<footer><pre>");
    if selected.is_empty() || rows.iter().any(|r| r.is_dir && r.path == selected) {
        body.push_str(&html_escape(&compact_summary(page)));
    } else {
        body.push_str(&html_escape(&tree::details_text(&page.tree, &selected)));
    }
    body.push_str("</pre></footer>");
    body.push_str("</body></html>");
    body
}

fn compact_summary(page: &Page) -> String {
    let text = page.summary_text();
    // The footer gets the interesting half of the text report, not the whole.
    // Never let the compact view turn an incomplete scan into a clean-looking
    // summary: coverage warnings are appended even when the cutoff hit first.
    let mut lines: Vec<String> = text.lines().take(18).map(str::to_string).collect();
    if text.lines().count() > lines.len() {
        lines.push("…".into());
    }
    if let Some(issues) = page.report.get("coverage").and_then(|c| c.get("issues")) {
        let count = array(Some(issues)).len();
        if count > 0 {
            let heading = format!("coverage: INCOMPLETE ({count} issue(s))");
            if !lines.contains(&heading) {
                lines.push(heading);
            }
        }
    } else {
        for (label, key) in [
            ("", "report"),
            ("installer ", "installer_report"),
            ("dropped files ", "drops_report"),
        ] {
            let issues = array(page.report.get(key).and_then(|r| r.get("scan_issues")));
            if issues.is_empty() {
                continue;
            }
            let heading = format!("{label}coverage: INCOMPLETE ({} issue(s))", issues.len());
            if !lines.contains(&heading) {
                lines.push(heading);
            }
        }
    }
    // What the sandbox could not contain is what is missing from this tree:
    // an elevated installer writes where the snapshot never looks.
    if let Some(block) = page.report.get("containment") {
        for (label, value) in crate::render::containment_lines(block) {
            // Continuation lines (the method's standing limits) are already
            // in the text half when it fits; only the labelled facts are
            // worth re-stating, and never twice.
            if label.is_empty() {
                continue;
            }
            let already = lines.iter().any(|existing| existing.starts_with(&label));
            if !already {
                lines.push(format!("{label}: {value}"));
            }
        }
    }
    lines.join("\n")
}

const STYLE: &str = r#"
:root{--bg:#0b0f14;--panel:#121820;--line:#1f2937;--text:#e5edf5;--muted:#8b9bb0;
      --clean:#4a5568;--info:#718096;--low:#2f855a;--medium:#b7791f;--high:#c05621;--critical:#9b2c2c}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
     font:13px/1.45 "Segoe UI",system-ui,-apple-system,sans-serif;display:flex;flex-direction:column;height:100vh}
header{display:flex;align-items:center;gap:16px;padding:8px 14px;background:var(--panel);border-bottom:1px solid var(--line)}
.title{display:flex;align-items:baseline;gap:10px;min-width:0}
.logo{font-weight:700;letter-spacing:.02em}
.path{color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.chips{margin-left:auto;display:flex;gap:8px}
.chip{padding:2px 10px;border-radius:999px;border:1px solid var(--line);background:#0e141b;white-space:nowrap}
.coverage-incomplete{background:#33290f;border-color:var(--medium);color:#fbd38d}
.verdict-critical{background:#3a1414;border-color:var(--critical)}
.verdict-high{background:#33200f;border-color:var(--high)}
.verdict-medium{background:#33290f;border-color:var(--medium)}
.verdict-low{background:#12251a;border-color:var(--low)}
.toolbar{display:flex;align-items:center;gap:8px;padding:8px 14px;background:#0e141b;border-bottom:1px solid var(--line);flex-wrap:wrap}
.toolbar .filter{display:flex;gap:6px}
input{background:#0b0f14;border:1px solid var(--line);color:var(--text);padding:5px 8px;border-radius:6px;min-width:220px}
button{background:#1c2733;color:var(--text);border:1px solid var(--line);padding:5px 12px;border-radius:6px;cursor:pointer}
.toggle{padding:4px 10px;border:1px solid var(--line);border-radius:999px;color:var(--muted);text-decoration:none}
.toggle.on{color:var(--text);background:#1c2733;border-color:#3b4b60}
.spacer{flex:1}
main{display:grid;grid-template-columns:minmax(340px,42%) 1fr;gap:1px;background:var(--line);min-height:0;flex:1}
.grid{background:var(--bg);overflow:auto}
table{width:100%;border-collapse:collapse}
th{position:sticky;top:0;background:#0e141b;text-align:left;padding:7px 10px;font-weight:600;color:var(--muted);border-bottom:1px solid var(--line)}
th a{color:inherit;text-decoration:none}
td{padding:4px 10px;border-bottom:1px solid #11161d;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
td.num{text-align:right;font-variant-numeric:tabular-nums}
td.name a{color:var(--text);text-decoration:none}
td.name a:hover{text-decoration:underline}
.pad{display:inline-block;width:var(--indent)}
.expander{display:inline-block;width:14px;color:var(--muted);text-decoration:none}
tr.selected{background:#182534}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;vertical-align:middle}
tr.tint-critical td.name{color:#feb2b2}
tr.tint-high td.name{color:#fbd38d}
.map{background:#080b0f;overflow:hidden}
.map svg{width:100%;height:100%;display:block}
.map rect:hover{stroke:#e5edf5;stroke-width:.3;fill-opacity:1}
footer{background:var(--panel);border-top:1px solid var(--line);padding:8px 14px;max-height:32vh;overflow:auto}
footer pre{margin:0;font:12px/1.5 "Cascadia Mono",Consolas,monospace;color:#c6d3e2;white-space:pre-wrap}
@media (max-width:760px){main{grid-template-columns:1fr;grid-template-rows:1fr 1fr}}
"#;

// ---------------------------------------------------------------------------
// Loopback server
// ---------------------------------------------------------------------------

/// Serve `page` on `127.0.0.1:preferred` until the process is killed.
///
/// One request at a time, no keep-alive, no chunking: enough for a UI that a
/// single operator drives, and small enough to audit. Only loopback is bound,
/// so nothing is exposed to the network (this tool is for air-gapped hosts).
pub fn serve(page: Page, preferred_port: u16) -> crate::Result<u16> {
    let mut last_error = None;
    for offset in 0..40u16 {
        let port = preferred_port.saturating_add(offset);
        match TcpListener::bind(("127.0.0.1", port)) {
            Ok(listener) => {
                listener.set_nonblocking(false).ok();
                eprintln!("[rea-offline] GUI: http://127.0.0.1:{port}/  (Ctrl+C to stop)");
                for stream in listener.incoming() {
                    match stream {
                        Ok(stream) => {
                            if let Err(e) = handle(stream, &page) {
                                eprintln!("[rea-offline] gui request error: {e}");
                            }
                        }
                        Err(e) => {
                            eprintln!("[rea-offline] gui accept error: {e}");
                            std::thread::sleep(Duration::from_millis(50));
                        }
                    }
                }
                return Ok(port);
            }
            Err(e) => last_error = Some(e),
        }
    }
    Err(crate::Error::Io(last_error.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::AddrInUse, "no loopback port available")
    })))
}

fn handle(mut stream: TcpStream, page: &Page) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut buffer = [0u8; 8192];
    let read = stream.read(&mut buffer)?;
    let request = String::from_utf8_lossy(&buffer[..read]).to_string();
    let mut parts = request.lines().next().unwrap_or("").split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("/");
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path, query),
        None => (target, ""),
    };
    // Refuse anything but GET on loopback: no uploads, no state changes.
    if method != "GET" {
        return respond(
            &mut stream,
            "405 Method Not Allowed",
            "text/plain",
            b"GET only\n",
        );
    }
    match path {
        "/" | "/view" | "/index.html" => {
            let html = page_html(page, query);
            respond(
                &mut stream,
                "200 OK",
                "text/html; charset=utf-8",
                html.as_bytes(),
            )
        }
        "/json" => {
            let body = format!("{}\n", page.report.to_string_pretty());
            respond(&mut stream, "200 OK", "application/json", body.as_bytes())
        }
        "/text" => {
            let body = page.summary_text();
            respond(
                &mut stream,
                "200 OK",
                "text/plain; charset=utf-8",
                body.as_bytes(),
            )
        }
        "/markdown" => {
            let body = crate::render::to_markdown(&page.report);
            respond(
                &mut stream,
                "200 OK",
                "text/markdown; charset=utf-8",
                body.as_bytes(),
            )
        }
        "/healthz" => respond(&mut stream, "200 OK", "text/plain", b"ok\n"),
        _ => respond(&mut stream, "404 Not Found", "text/plain", b"not found\n"),
    }
}

fn respond(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\
         Referrer-Policy: no-referrer\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

/// Reopen an archived report (the JSON a previous run wrote) in the window.
/// This is what makes the GUI useful offline *after* the fact: an operator
/// can hand a report to a colleague and they get the same picture without
/// rescanning the machine.
pub fn page_from_report_file(path: &Path) -> crate::Result<Page> {
    let report = crate::report::load(path)?;
    let fallback = path.display().to_string();
    // A merged sandbox tree is rooted at the sandbox, so the header must name
    // the sandbox too — not the install subdirectory the tree no longer sits in.
    let sandbox_root = if report.get("mode").and_then(Value::as_str) == Some("sandbox-installer") {
        report
            .get("drops_report")
            .and_then(|r| r.get("target"))
            .and_then(Value::as_str)
    } else {
        None
    };
    let name = sandbox_root
        .or_else(|| {
            report
                .get("report")
                .and_then(|r| r.get("target"))
                .and_then(Value::as_str)
        })
        .unwrap_or(&fallback)
        .to_string();
    Ok(Page::new(report, &name))
}

/// Convenience for the CLI: scan `target`, then plot it.
pub fn page_for_path(target: &Path, rea_path: Option<std::path::PathBuf>) -> crate::Result<Page> {
    let report = crate::app::mode_scan(crate::app::ScanOptions {
        target: target.to_path_buf(),
        rea_path,
    })?;
    Ok(Page::new(report, &target.display().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Page {
        let report = crate::json::parse(
            r#"{"mode":"local-scan","verdict":"high","report":{
                 "target":"C:/demo","engine":"native","file_count":2,"risk_score":41,"verdict":"high",
                 "summary":{"total_bytes":300},
                 "rules":{"findings":[
                   {"rule":"PE100","title":"W+X","severity":"high","file":"bin/a.exe","evidence":"x"}]},
                 "files":[
                   {"path":"bin/a.exe","size":200,"format":"PE","sha256":"aa","md5":"bb","imphash":"cc"},
                   {"path":"docs/readme.txt","size":100,"format":"text","sha256":"dd","md5":"ee"}]}}"#,
        )
        .unwrap();
        Page::new(report, "C:/demo")
    }

    /// A sandbox report with an absolute Windows installer path, a file in
    /// the install tree and a profile drop that decided the verdict.
    fn sandbox_page() -> Page {
        let report = crate::json::parse(
            r#"{"mode":"sandbox-installer","verdict":"critical","risk_score":94,
                "verdict_sources":{"installer":{"risk_score":6,"verdict":"low"},
                                   "install_tree":{"risk_score":0,"verdict":"low"},
                                   "drops":{"risk_score":94,"verdict":"critical"}},
                "installer_report":{"target":"C:/Downloads/setup.exe","file_count":1,"risk_score":6,"verdict":"low",
                  "rules":{"findings":[{"rule":"PE001","title":"unsigned","severity":"low","file":"C:/Downloads/setup.exe","evidence":"x"}]},
                  "files":[{"path":"C:/Downloads/setup.exe","size":100,"format":"PE","sha256":"aa","md5":"bb"}]},
                "report":{"target":"C:/temp/rea_sandbox_1/install","file_count":1,"risk_score":0,"verdict":"low",
                  "rules":{"findings":[]},
                  "files":[{"path":"bin/app.exe","size":200,"format":"PE","sha256":"cc","md5":"dd"}]},
                "drops_report":{"target":"C:/temp/rea_sandbox_1","file_count":1,"risk_score":94,"verdict":"critical",
                  "rules":{"findings":[{"rule":"PE140","title":"injection","severity":"high","file":"AppData/Roaming/payload.exe","evidence":"y"}]},
                  "files":[{"path":"AppData/Roaming/payload.exe","size":300,"format":"PE","sha256":"ee","md5":"ff"}]}}"#,
        )
        .unwrap();
        Page::new(report, "sandbox")
    }

    #[test]
    fn sandbox_view_paths_never_grow_a_drive_letter_folder() {
        assert_eq!(
            sandbox_view_path("_installer", "C:\\Downloads\\setup.exe"),
            "_installer/Downloads/setup.exe"
        );
        assert_eq!(
            sandbox_view_path("_installer", "/tmp/x/setup.exe"),
            "_installer/tmp/x/setup.exe"
        );
        assert_eq!(
            sandbox_view_path("install", "bin/app.exe"),
            "install/bin/app.exe"
        );
        assert_eq!(
            sandbox_view_path("", "AppData/Roaming/payload.exe"),
            "AppData/Roaming/payload.exe"
        );
    }

    #[test]
    fn the_window_flags_incomplete_coverage_from_the_aggregated_block() {
        let report = crate::json::parse(
            r#"{"mode":"sandbox-installer","verdict":"low","risk_score":0,
                "coverage":{"complete":false,"issue_count":1,"unverified_count":0,"issues":[
                    {"area":"sandbox snapshot (after)","path":"AppData/hidden",
                     "stage":"traverse","message":"Permission denied"}]},
                "report":{"target":"C:/sandbox/install","file_count":0,"risk_score":0,
                          "verdict":"low","files":[],"scan_issues":[]}}"#,
        )
        .unwrap();
        let page = Page::new(report, "sandbox");
        let html = page_html(&page, "");
        assert!(
            html.contains("coverage-incomplete"),
            "the chip must warn: {html}"
        );
        assert!(html.contains("incomplete coverage — 1 issue(s)"), "{html}");
        // The compact summary is what a glance reads; it cannot look clean.
        assert!(compact_summary(&page).contains("coverage: INCOMPLETE (1 issue(s))"));
    }

    #[test]
    fn sandbox_window_merges_every_analyzed_set() {
        let page = sandbox_page();
        // The chip must agree with the envelope, not the calm install tree.
        assert_eq!(page.verdict(), "critical");
        assert_eq!(page.score(), 94);
        assert_eq!(page.tree.file_count, 3, "installer + install tree + drop");
        assert_eq!(page.tree.size, 600);

        // Each set keeps its own namespace, and findings still find their file.
        let drop = tree::details_text(&page.tree, "AppData/Roaming/payload.exe");
        assert!(drop.contains("PE140"), "{drop}");
        let installer = tree::details_text(&page.tree, "_installer/Downloads/setup.exe");
        assert!(installer.contains("PE001"), "{installer}");
        let installed = tree::details_text(&page.tree, "install/bin/app.exe");
        assert!(installed.contains("SHA-256: cc"), "{installed}");

        let html = page_html(&page, "");
        assert!(html.contains("chip verdict-critical"));
        assert!(html.contains("94/100"));
        assert!(html.contains("payload.exe"));
    }

    #[test]
    fn plain_scans_are_not_renamespaced() {
        let page = sample();
        assert_eq!(page.score(), 41);
        assert!(tree::details_text(&page.tree, "bin/a.exe").contains("PE100"));
    }

    #[test]
    fn page_carries_title_verdict_rows_and_tiles() {
        let page = sample();
        let html = page_html(&page, "");
        assert!(html.starts_with("<!doctype html>"));
        assert!(html.contains("HIGH — 41/100"), "{html}");
        assert!(html.contains("bin/a.exe"));
        assert!(html.contains("<svg"));
        assert!(html.contains("rect x="));
        assert!(html.contains("</html>"));
    }

    #[test]
    fn large_report_html_has_a_measured_size_and_render_baseline() {
        const FILE_COUNT: usize = 5_000;
        let files = (0..FILE_COUNT)
            .map(|index| {
                Value::obj(vec![
                    (
                        "path",
                        Value::str(format!("bin/group-{}/file-{index}.exe", index % 100)),
                    ),
                    ("size", Value::num(4096)),
                    ("format", Value::str("PE")),
                    ("sha256", Value::str("a".repeat(64))),
                    ("md5", Value::str("b".repeat(32))),
                ])
            })
            .collect();
        let report = Value::obj(vec![
            ("mode", Value::str("local-scan")),
            ("verdict", Value::str("low")),
            (
                "report",
                Value::obj(vec![
                    ("target", Value::str("large synthetic report")),
                    ("file_count", Value::num(FILE_COUNT as u64)),
                    ("risk_score", Value::num(0)),
                    ("verdict", Value::str("low")),
                    ("files", Value::Array(files)),
                ]),
            ),
        ]);
        let started = std::time::Instant::now();
        let page = Page::new(report, "large synthetic report");
        let html = page_html(&page, "scope=files");
        let elapsed = started.elapsed();

        assert_eq!(page.tree.file_count, FILE_COUNT as u64);
        assert!(html.contains("file-4999.exe"));
        assert!(
            html.len() < 8 * 1024 * 1024,
            "5,000-file report rendered to {} bytes",
            html.len()
        );
        eprintln!(
            "5,000-file GUI baseline: {} ms, {} HTML bytes",
            elapsed.as_millis(),
            html.len()
        );
    }

    #[test]
    fn query_state_is_honoured_and_round_trips() {
        let page = sample();
        let expanded = page_html(&page, "expand=bin&expand=docs&hide_clean=1");
        assert!(expanded.contains("bin/a.exe"));
        assert!(
            !expanded.contains("readme.txt"),
            "hide_clean must drop the clean file"
        );

        let filtered = page_html(&page, "filter=readme");
        let grid = {
            let body = filtered.split("<tbody>").nth(1).unwrap_or("");
            body.split("</tbody>").next().unwrap_or("").to_string()
        };
        assert!(grid.contains("readme.txt"), "{grid}");
        assert!(
            !grid.contains("a.exe"),
            "the grid honours the search: {grid}"
        );

        let selected = page_html(&page, "select=bin%2Fa.exe");
        assert!(
            selected.contains("SHA-256: aa"),
            "details pane shows hashes"
        );
        assert!(selected.contains("PE100"));
    }

    #[test]
    fn hostile_input_is_escaped() {
        let report = crate::json::parse(
            r#"{"verdict":"low","report":{"target":"x","file_count":1,"files":[
                 {"path":"<script>alert(1)</script>","size":1,"format":"text","sha256":"a","md5":"b"}]}}"#,
        )
        .unwrap();
        let page = Page::new(report, "x");
        let html = page_html(&page, "");
        assert!(
            !html.contains("<script>alert(1)</script>"),
            "injection must be escaped"
        );
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn percent_encoding_round_trips() {
        let text = "C:\\Program Files\\Some App & x=y#1";
        let encoded = encode(text);
        assert!(!encoded.contains(' '));
        assert!(!encoded.contains('&'));
        assert_eq!(percent_decode(&encoded), text);
        assert_eq!(percent_decode("a+b"), "a b");
    }

    #[test]
    fn routes_return_expected_content_types() {
        // Exercise the pure builders the routes use.
        let page = sample();
        assert!(page.summary_text().contains("risk score"));
        assert!(crate::render::to_markdown(&page.report).starts_with("# rea-offline"));
    }
}
