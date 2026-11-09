//! What a report means by "incomplete".
//!
//! A verdict is only as good as the evidence behind it, so a report has to
//! say what it did not see. This module owns that vocabulary, and it is the
//! one place the question is answered — the coverage block in an envelope is
//! a *derived* summary of that same envelope:
//!
//! * **snapshot and analysis limits** (`block`) — traversal, metadata,
//!   hashing and content limits, plus files whose contents could not be
//!   compared, each labelled with the area it came from;
//! * **how the run ended** (`universal_sandbox::run_issue`) — killed at the
//!   timeout, or an exit code that is not success;
//! * **what the sandbox could not contain** (`containment::issues`) — an
//!   elevated run, or a registry hive that would not mount;
//! * **failures the envelope records about itself** (`recorded_failures`) —
//!   an installer that could not be analyzed, or a sandbox that could not be
//!   cleaned up.
//!
//! The last one is why this is a module and not a helper: a report can state
//! in one field that it never analyzed the installer while claiming in
//! another that it saw everything. Each category has one function, and the
//! writer and the archive validator call the *same* function, so the two
//! cannot drift apart — which is the only way a coverage block can be worth
//! gating on.
//!
//! Coverage never contributes to the risk score. It is a statement about the
//! evidence, not about the sample: an access-denied error is not evidence of
//! malice.

use crate::json::Value;
use crate::rea_bridge::ScanIssue;

/// One thing the inspection could not see, or could not keep.
#[derive(Debug, Clone, PartialEq)]
pub struct Issue {
    /// The phase or surface that went blind: `sandbox snapshot (after)`,
    /// `installer execution`, `containment`, `cleanup`, …
    pub area: String,
    /// What it went blind on: a path, the sandbox root, the installer.
    pub path: String,
    /// Stable machine-readable reason: `traverse`, `hash`, `timeout`,
    /// `elevated`, `purge`, …
    pub stage: String,
    pub message: String,
}

impl Issue {
    pub fn new(area: &str, path: &str, stage: &str, message: &str) -> Self {
        Issue {
            area: area.to_string(),
            path: path.to_string(),
            stage: stage.to_string(),
            message: message.to_string(),
        }
    }

    fn to_json(&self) -> Value {
        Value::obj(vec![
            ("area", Value::str(self.area.clone())),
            ("path", Value::str(self.path.clone())),
            ("stage", Value::str(self.stage.clone())),
            ("message", Value::str(self.message.clone())),
        ])
    }
}

fn integer(value: Option<&Value>) -> u64 {
    match value {
        Some(Value::Number(n)) if n.is_finite() && *n >= 0.0 && n.fract() == 0.0 => *n as u64,
        _ => 0,
    }
}

/// The coverage block for the limits the *analysis* hit, each labelled with
/// the area it came from, plus every file whose contents could not be
/// compared. Passed the typed issues because at this point the report has
/// not been assembled yet; everything the envelope can say about itself is
/// added later by [`record`].
pub fn block(sources: Vec<(&str, Vec<ScanIssue>)>, deltas: Vec<(&str, &crate::snapshot::Delta)>) -> Value {
    let mut issues: Vec<Value> = Vec::new();
    let mut push = |area: &str, path: &str, stage: &str, message: &str| {
        issues.push(Issue::new(area, path, stage, message).to_json());
    };
    for (area, list) in &sources {
        for issue in list {
            push(area, &issue.path, &issue.stage, &issue.message);
        }
    }
    let mut unverified_count = 0u64;
    for (area, delta) in &deltas {
        for entry in &delta.unverified {
            unverified_count += 1;
            push(area, &entry.path, "compare",
                 "contents could not be compared: unreadable in one or both snapshots");
        }
    }
    assemble(issues, unverified_count)
}

/// Add issues to an envelope's coverage block, keeping its own arithmetic
/// true (`complete` ⇔ no issues, `issue_count` = number of issues) — the
/// archive validator checks exactly that, so a block that lies about itself
/// is rejected rather than rendered.
pub fn record(report: &mut Value, extra: Vec<Issue>) {
    if extra.is_empty() {
        return;
    }
    let Value::Object(map) = report else { return };
    let mut issues = match map.get("coverage").and_then(|c| c.get("issues")) {
        Some(Value::Array(items)) => items.clone(),
        _ => Vec::new(),
    };
    let unverified_count = integer(map.get("coverage").and_then(|c| c.get("unverified_count")));
    let mut added = 0;
    for issue in &extra {
        // Idempotent: the writer records the envelope's failures once per
        // phase, and a coverage block is a summary of the envelope — not an
        // append-only log of every time we looked at it.
        let duplicate = issues.iter().any(|existing| {
            existing.get("area").and_then(Value::as_str) == Some(issue.area.as_str())
                && existing.get("path").and_then(Value::as_str) == Some(issue.path.as_str())
                && existing.get("stage").and_then(Value::as_str) == Some(issue.stage.as_str())
        });
        if !duplicate {
            issues.push(issue.to_json());
            added += 1;
        }
    }
    if added == 0 {
        return;
    }
    map.insert("coverage".into(), assemble(issues, unverified_count));
}

fn assemble(issues: Vec<Value>, unverified_count: u64) -> Value {
    Value::obj(vec![
        ("complete", Value::Bool(issues.is_empty())),
        ("issue_count", Value::num(issues.len() as u64)),
        ("unverified_count", Value::num(unverified_count)),
        ("issues", Value::Array(issues)),
    ])
}

/// The failures an envelope records about *itself*: fields the report writes
/// when part of the inspection did not happen. Every one of them means the
/// report does not have the evidence it claims, so every one of them belongs
/// in the coverage block.
///
/// Shared with the validator, so an archive cannot keep a `installer_error`
/// next to a `coverage` block that says everything was seen.
pub fn recorded_failures(report: &Value) -> Vec<Issue> {
    let mut out = Vec::new();
    // The installer is one of the three things a sandbox run is supposed to
    // inspect. "We could not read it" is not the same as "it was clean".
    if let Some(error) = report.get("installer_error").and_then(Value::as_str) {
        out.push(Issue::new(
            "installer analysis",
            &installer_path(report),
            "analysis",
            &format!("the installer could not be analyzed, so one of the three evidence \
                      sets is missing from this report: {error}"),
        ));
    }
    // A sandbox we could not clean is a machine still holding the installer's
    // files — and it is also the record failing to keep its own promise.
    if let Some(error) = report.get("purge_error").and_then(Value::as_str) {
        out.push(Issue::new(
            "cleanup",
            &sandbox_path(report),
            "purge",
            &format!("the sandbox could not be cleaned up: {error}"),
        ));
    }
    if let Some(purge) = report.get("purge").filter(|v| matches!(v, Value::Object(_))) {
        if purge.get("verified_zero_residue") == Some(&Value::Bool(false)) {
            out.push(Issue::new(
                "cleanup",
                &sandbox_path(report),
                "verify",
                "the sandbox was deleted but zero residue could not be confirmed, \
                 so part of the run may still be on disk",
            ));
        }
    }
    out
}

fn installer_path(report: &Value) -> String {
    report
        .get("installer")
        .and_then(Value::as_str)
        .unwrap_or("installer")
        .to_string()
}

fn sandbox_path(report: &Value) -> String {
    report
        .get("purge")
        .and_then(|p| p.get("path"))
        .and_then(Value::as_str)
        .or_else(|| report.get("sandbox_path").and_then(Value::as_str))
        .unwrap_or("sandbox")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(extra: &str) -> Value {
        crate::json::parse(&format!(
            r#"{{"schema_version":3,"mode":"sandbox-installer","installer":"setup.exe"{extra}}}"#
        ))
        .unwrap()
    }

    #[test]
    fn a_report_with_no_recorded_failures_adds_nothing() {
        let report = envelope(r#","purge":{"path":"/tmp/rea_sandbox_x","removed":true,
            "verified_zero_residue":true}"#);
        assert!(recorded_failures(&report).is_empty());
        // A run that kept its sandbox on purpose did not fail to clean up.
        let kept = envelope(r#","sandbox_kept":true,"sandbox_path":"/tmp/rea_sandbox_x""#);
        assert!(recorded_failures(&kept).is_empty());
    }

    #[test]
    fn an_installer_that_could_not_be_analyzed_is_a_missing_evidence_set() {
        let report = envelope(r#","installer_error":"not found: setup.exe""#);
        let issues = recorded_failures(&report);
        assert_eq!(issues.len(), 1, "{issues:?}");
        assert_eq!(issues[0].area, "installer analysis");
        assert_eq!(issues[0].stage, "analysis");
        assert_eq!(issues[0].path, "setup.exe");
        assert!(issues[0].message.contains("could not be analyzed"), "{}", issues[0].message);
    }

    #[test]
    fn a_sandbox_that_could_not_be_cleaned_is_a_missing_promise() {
        let report = envelope(r#","purge_error":"access denied""#);
        let issues = recorded_failures(&report);
        assert_eq!(issues.len(), 1, "{issues:?}");
        assert_eq!(issues[0].area, "cleanup");
        assert_eq!(issues[0].stage, "purge");
        assert!(issues[0].message.contains("could not be cleaned up"), "{}", issues[0].message);

        // Deleted, but residue not confirmed: the run may still be on disk.
        let unverified = envelope(r#","purge":{"path":"/tmp/rea_sandbox_x","removed":true,
            "verified_zero_residue":false}"#);
        let issues = recorded_failures(&unverified);
        assert_eq!(issues.len(), 1, "{issues:?}");
        assert_eq!(issues[0].stage, "verify");
        assert_eq!(issues[0].path, "/tmp/rea_sandbox_x");
    }

    #[test]
    fn recording_keeps_the_blocks_own_arithmetic_true() {
        let mut report = envelope(r#","installer_error":"unreadable""#);
        assert!(report.get("coverage").is_none());
        let failures = recorded_failures(&report);
        record(&mut report, failures);
        let coverage = report.get("coverage").expect("coverage block");
        assert_eq!(coverage.get("complete"), Some(&Value::Bool(false)));
        assert_eq!(coverage.get("issue_count"), Some(&Value::num(1)));
        assert_eq!(array(&coverage), 1);

        // Recording the same failure again must not double-count: the block
        // is a summary of the envelope, not an append-only log, and the
        // writer records the envelope's failures once per phase.
        let again = recorded_failures(&report);
        record(&mut report, again);
        let coverage = report.get("coverage").expect("coverage block");
        assert_eq!(coverage.get("issue_count"), Some(&Value::num(1)), "no duplicates: {coverage:?}");
        assert_eq!(array(&coverage), 1);
        assert_eq!(coverage.get("complete"), Some(&Value::Bool(false)));

        // An unblemished envelope has nothing to record, and recording
        // nothing must not invent a block (or, worse, a claim about one).
        let mut clean = envelope("");
        let failures = recorded_failures(&clean);
        record(&mut clean, failures);
        assert!(clean.get("coverage").is_none(), "nothing recorded, nothing invented: {clean:?}");
        // An existing block is left exactly as it was.
        let mut complete = envelope("");
        if let Value::Object(map) = &mut complete {
            map.insert("coverage".to_string(), block(vec![], vec![]));
        }
        let failures = recorded_failures(&complete);
        record(&mut complete, failures);
        assert_eq!(
            complete.get("coverage").and_then(|c| c.get("complete")),
            Some(&Value::Bool(true))
        );
    }

    #[test]
    fn an_empty_block_stays_complete_and_counts_match() {
        let empty = block(vec![], vec![]);
        assert_eq!(empty.get("complete"), Some(&Value::Bool(true)));
        assert_eq!(empty.get("issue_count"), Some(&Value::num(0)));
        assert_eq!(empty.get("unverified_count"), Some(&Value::num(0)));
        assert_eq!(array(&empty), 0);
        let one = block(
            vec![("drops analysis", vec![ScanIssue::new("a.exe", "hash", "unreadable")])],
            vec![],
        );
        assert_eq!(one.get("complete"), Some(&Value::Bool(false)));
        assert_eq!(array(&one), 1);
    }

    fn array(coverage: &Value) -> usize {
        match coverage.get("issues") {
            Some(Value::Array(items)) => items.len(),
            _ => 0,
        }
    }
}
