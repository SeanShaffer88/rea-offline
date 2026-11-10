//! Selected-file evidence from recorded facts only: no filesystem reads or tools.
use super::{array, html_escape};
use super::tree::Artifact;
use crate::json::Value;

const LIMIT: usize = 128;
fn text(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(s)) => html_escape(s),
        Some(Value::Number(n)) if n.is_finite() => n.to_string(),
        Some(Value::Bool(true)) => "set".into(),
        Some(Value::Bool(false)) => "not set".into(),
        _ => "not recorded".into(),
    }
}
fn fact(out: &mut String, label: &str, value: Option<&Value>) {
    out.push_str(&format!("<dt>{}</dt><dd>{}</dd>", html_escape(label), text(value)));
}
fn location(value: Option<&Value>) -> Option<u64> {
    match value {
        Some(Value::Number(n)) if n.is_finite() && *n >= 0.0 && *n < u64::MAX as f64 && n.fract() == 0.0 => Some(*n as u64),
        _ => None,
    }
}
fn range_text(range: &Value, file_size: u64) -> String {
    match (location(range.get("offset")), location(range.get("size"))) {
        (Some(offset), Some(size)) => match offset.checked_add(size).filter(|end| *end <= file_size) {
            Some(end) => format!("[0x{offset:X}, 0x{end:X}) — offset {offset}, {size} bytes; end exclusive"),
            None => "invalid recorded range (outside file bounds)".into(),
        },
        _ => "range not recorded or invalid".into(),
    }
}
fn file_ranges(out: &mut String, pe: &Value, file_size: u64) {
    out.push_str("<details open><summary>File layout and overlay ranges</summary><p>Ranges are half-open file offsets, not memory addresses or RVAs. Metadata does not establish payload execution or signature validity.</p>");
    match pe.get("certificate_range") {
        Some(Value::Null) => out.push_str("<p>Certificate range: none recorded.</p>"),
        Some(range) => out.push_str(&format!("<p>Certificate range: {}</p>", range_text(range, file_size))),
        None => out.push_str("<p>Certificate offsets not recorded in this report.</p>"),
    }
    match pe.get("overlay_ranges") {
        Some(Value::Array(ranges)) => {
            if ranges.is_empty() { out.push_str("<p>No overlay ranges recorded.</p>"); }
            out.push_str("<ul>");
            for range in ranges.iter().take(LIMIT) { out.push_str(&format!("<li>{}</li>", range_text(range, file_size))); }
            out.push_str("</ul>");
            omitted(out, ranges.len());
        }
        _ => out.push_str("<p>Overlay offsets not recorded in this report.</p>"),
    }
    out.push_str("</details>");
}
fn omitted(out: &mut String, count: usize) {
    if count > LIMIT {
        out.push_str(&format!("<p>{} additional entries omitted from this view; use JSON for the full recorded list.</p>", count - LIMIT));
    }
}
fn names(out: &mut String, title: &str, value: Option<&Value>) {
    out.push_str(&format!("<details><summary>{}</summary>", html_escape(title)));
    match value {
        Some(Value::Array(items)) => {
            if items.is_empty() { out.push_str("<p>No entries recorded. This is not proof of absence.</p>"); }
            else {
                out.push_str("<ul>");
                for item in items.iter().take(LIMIT) { out.push_str(&format!("<li><code>{}</code></li>", text(Some(item)))); }
                out.push_str("</ul>");
                omitted(out, items.len());
            }
        }
        _ => out.push_str("<p>Not recorded in this report.</p>"),
    }
    out.push_str("</details>");
}

pub(super) fn render(file: &Artifact) -> String {
    let mut out = String::from("<section class=\"evidence\"><h2>Recorded file evidence</h2><p>Static observations are not a safety verdict. These facts belong to the selected file, not every file in the report.</p>");
    out.push_str("<details open><summary>Why findings were raised</summary><p>Finding points are recorded contributions, not probabilities. The grid's severity-derived value may differ from the report's combined, capped risk score.</p>");
    if file.rule_details.is_empty() { out.push_str("<p>No rule evidence recorded for this file. Missing evidence is not proof of safety.</p>"); }
    for finding in file.rule_details.iter().take(LIMIT) {
        out.push_str(&format!("<article class=\"finding\"><strong>{} — {}</strong><dl>", text(finding.get("rule")), text(finding.get("title"))));
        for (label, key) in [("Severity", "severity"), ("Points", "score"), ("Category", "category"), ("File", "file"), ("Evidence", "evidence")] {
            fact(&mut out, label, finding.get(key));
        }
        out.push_str("</dl></article>");
    }
    omitted(&mut out, file.rule_details.len());
    out.push_str("</details>");
    match file.record.get("pe") {
        Some(pe @ Value::Object(_)) => {
            out.push_str("<details open><summary>PE headers and hardening</summary><dl>");
            for (label, key) in [("Machine", "machine"), ("64-bit", "is_64bit"), ("Subsystem", "subsystem"), ("COFF timestamp (raw)", "timestamp"), ("Entry point RVA (decimal)", "entry_point_rva"), ("Overlay bytes (certificate excluded)", "overlay_size")] {
                fact(&mut out, label, pe.get(key));
            }
            let certificate = match pe.get("signed") {
                Some(Value::Bool(true)) => "present — signature validity NOT verified",
                Some(Value::Bool(false)) => "not present according to this parser",
                _ => "not recorded — signature validity unknown",
            };
            out.push_str(&format!("<dt>Certificate table</dt><dd>{certificate}</dd></dl><p>Certificate-table presence is not publisher trust. Overlay bytes may be legitimate installer payloads.</p><dl>"));
            for (label, key) in [("ASLR (DYNAMIC_BASE)", "aslr_dynamic_base"), ("DEP (NX_COMPAT)", "nx_compat"), ("Control Flow Guard", "guard_cf"), ("NO_SEH", "no_seh"), ("High entropy VA", "high_entropy_va")] {
                fact(&mut out, label, pe.get("mitigations").and_then(|m| m.get(key)));
            }
            out.push_str("</dl><p>Header flags describe declared settings, not verified runtime protection.</p></details>");
            file_ranges(&mut out, pe, file.size);
            out.push_str("<details open><summary>PE sections</summary><p>Section geometry is declared by headers and may be malformed; offsets are not proof that all section bytes were inspected.</p>");
            match pe.get("section_details") {
                Some(Value::Array(sections)) if !sections.is_empty() => {
                    out.push_str("<table><thead><tr><th>Name</th><th>Raw offset</th><th>Raw bytes</th><th>RVA</th><th>Virtual bytes</th><th>Entropy</th><th>Executable</th><th>Writable</th></tr></thead><tbody>");
                    for section in sections.iter().take(LIMIT) {
                        out.push_str("<tr>");
                        for key in ["name", "raw_offset", "raw_size", "virtual_address", "virtual_size", "entropy", "executable", "writable"] {
                            let value = if key == "entropy" && matches!(section.get(key), None | Some(Value::Null)) {
                                "unknown — not fully inspected".into()
                            } else if key == "raw_offset" || key == "virtual_address" {
                                location(section.get(key)).map(|n| format!("0x{n:X} ({n})")).unwrap_or_else(|| "not recorded".into())
                            } else { text(section.get(key)) };
                            out.push_str(&format!("<td>{value}</td>"));
                        }
                        out.push_str("</tr>");
                    }
                    out.push_str("</tbody></table>");
                    omitted(&mut out, sections.len());
                }
                _ => out.push_str("<p>Section details not recorded. See JSON for any legacy section-name list.</p>"),
            }
            out.push_str("</details><p>Import lists can be partial because of parser limits or incomplete content coverage. A capability name does not establish that it was executed.</p>");
            names(&mut out, "Imported libraries", pe.get("imports"));
            names(&mut out, "Imported functions", pe.get("imported_functions"));
        }
        _ => out.push_str("<p>PE metadata not recorded or unavailable for this file. Non-PE files do not have PE headers.</p>"),
    }
    out.push_str("<details><summary>Recorded string indicators</summary>");
    let indicators = array(file.record.get("indicators"));
    if indicators.is_empty() { out.push_str("<p>No string indicators recorded. This does not prove their absence from uninspected content.</p>"); }
    else {
        out.push_str("<ul>");
        for indicator in indicators.iter().take(LIMIT) {
            out.push_str(&format!("<li>{} [{}]: <code>{}</code></li>", text(indicator.get("category")), text(indicator.get("severity")), text(indicator.get("matched"))));
        }
        out.push_str("</ul>");
        omitted(&mut out, indicators.len());
    }
    out.push_str("</details></section>");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    fn report() -> Value {
        crate::json::parse(r#"{"target":"sample.exe","files":[{
          "path":"sample.exe","size":123,"format":"PE",
          "pe":{"machine":"x86-64","is_64bit":true,"signed":true,"overlay_size":42,
             "mitigations":{"nx_compat":true,"aslr_dynamic_base":false},
             "section_details":[{"name":".text","raw_size":100,"virtual_size":200,"entropy":null,"executable":true,"writable":false}],
             "imports":["KERNEL32.dll"],"imported_functions":["KERNEL32.dll!CreateProcessW"]},
          "indicators":[{"category":"execution","severity":"medium","matched":"cmd.exe"}]}],
          "rules":{"findings":[{"file":"sample.exe","rule":"PE002","title":"No ASLR","severity":"medium","score":12,"category":"hardening","evidence":"DYNAMIC_BASE unset"}]}}
        "#).unwrap()
    }
    fn html(report: &Value) -> String {
        let tree = super::super::tree::from_report(report);
        render(super::super::tree::find_file(&tree, "sample.exe").unwrap())
    }
    #[test]
    fn file_ranges_render_hex_bounds_and_legacy_unknowns() {
        let pe = crate::json::parse(r#"{"certificate_range":{"offset":64,"size":16},"overlay_ranges":[{"offset":80,"size":32}]}"#).unwrap();
        let mut out = String::new();
        file_ranges(&mut out, &pe, 128);
        assert!(out.contains("[0x40, 0x50)"));
        assert!(out.contains("[0x50, 0x70)"));
        assert!(out.contains("end exclusive"));
        let mut old = String::new();
        file_ranges(&mut old, &Value::Null, 128);
        assert!(old.contains("Overlay offsets not recorded"));
        let invalid = crate::json::parse(r#"{"offset":120,"size":32}"#).unwrap();
        assert!(range_text(&invalid, 128).contains("invalid recorded range"));
    }

    #[test]
    fn structured_view_explains_findings_and_declared_pe_facts() {
        let out = html(&report());
        for expected in ["DYNAMIC_BASE unset", "<dt>Points</dt><dd>12</dd>", "KERNEL32.dll!CreateProcessW", "unknown — not fully inspected", "signature validity NOT verified", "Overlay bytes", "cmd.exe", "not verified runtime protection"] {
            assert!(out.contains(expected), "missing {expected}: {out}");
        }
    }
    #[test]
    fn absent_metadata_stays_unknown_in_legacy_and_non_pe_reports() {
        let old = crate::json::parse(r#"{"files":[{"path":"sample.exe","format":"text","size":1}]}"#).unwrap();
        let out = html(&old);
        assert!(out.contains("PE metadata not recorded or unavailable"));
        assert!(out.contains("No rule evidence recorded"));
        assert!(!out.contains("signature validity NOT verified"));
    }
    #[test]
    fn all_report_strings_are_escaped_not_executable_markup() {
        let data = report().to_string_pretty().replace("DYNAMIC_BASE unset", "<script>alert(1)</script>")
            .replace("KERNEL32.dll", "<img src=x onerror=alert(1)>").replace(".text", "<section>")
            .replace("cmd.exe", "<svg/onload=alert(1)>");
        let out = html(&crate::json::parse(&data).unwrap());
        assert!(!out.contains("<script>"));
        assert!(!out.contains("<img src=x"));
        assert!(!out.contains("<svg/onload"));
        assert!(out.contains("&lt;script&gt;"));
        assert!(out.contains("&lt;section&gt;"));
    }
    #[test]
    fn recorded_empty_lists_are_distinct_from_missing_lists() {
        let report = crate::json::parse(r#"{"files":[{"path":"sample.exe","pe":{"imports":[]}}]}"#).unwrap();
        let out = html(&report);
        assert!(out.contains("No entries recorded. This is not proof of absence."));
        assert!(out.contains("Not recorded in this report."));
        assert!(out.contains("signature validity unknown"));
    }
    #[test]
    fn long_import_lists_are_bounded_with_explicit_omission_counts() {
        let list = Value::Array((0..140).map(|i| Value::str(format!("f{i}"))).collect());
        let mut out = String::new();
        names(&mut out, "Functions", Some(&list));
        assert_eq!(out.matches("<li>").count(), LIMIT);
        assert!(out.contains("12 additional entries omitted"));
        assert!(!out.contains("<code>f139</code>"));
    }
    #[test]
    fn evidence_is_associated_with_the_exact_file_path() {
        let mut report = report();
        if let Value::Object(body) = &mut report {
            if let Some(Value::Array(files)) = body.get_mut("files") {
                files.push(Value::obj(vec![("path", Value::str("other.exe")), ("size", Value::num(2))]));
            }
        }
        let tree = super::super::tree::from_report(&report);
        let other = super::super::tree::find_file(&tree, "other.exe").unwrap();
        assert!(!render(other).contains("DYNAMIC_BASE unset"));
    }
}
